import glob
import json
import logging
import subprocess
import time
from os import mkdir, remove
from os.path import exists, join, getsize
from urllib.parse import urlparse

import requests
import wget
from Crypto.Cipher import AES
from Crypto.Util import Counter
from pywidevine import Device, PSSH, Cdm
from pywidevine.exceptions import InvalidSession, InvalidLicenseMessage, InvalidContext, SignatureMismatch

from playplay_pb2 import PlayPlayLicenseRequest, PlayPlayLicenseResponse, AUDIO_TRACK, Interactivity
from id_type import IDType
from token_manager import TokenManager


class Spotify:
    MP4_FORMATS = [
        'MP4_128',
        'MP4_128_DUAL',
        'MP4_256',
        'MP4_256_DUAL'
    ]
    OGG_FORMATS = [
        'OGG_VORBIS_320',
        'OGG_VORBIS_160',
        'OGG_VORBIS_96'
    ]

    def __init__(
            self,
            url_id: str,
            token_manager: TokenManager,
            quality: str,
            output_folder: str
    ):
        """
        Spotify Downloader
        Author: github.com/DevLARLEY
        """
        self.id, self.id_type = self.get_id_type(url_id)
        self.token_manager = token_manager
        self.quality = quality
        self.output_folder = output_folder

        self.client_bases = self._request_client_bases()
        self.license_url = self._build_license_url(self.client_bases)

        if not exists(self.output_folder):
            mkdir(self.output_folder)

    @staticmethod
    def _get_cdms() -> list[str]:
        if not (cdms := glob.glob(join("cdm", "*.wvd"))):
            logging.error("No CDMs found")
            exit(1)
        return cdms

    @staticmethod
    def _request_client_bases():
        request = requests.get(
            url="https://apresolve.spotify.com",
            params={
                "type": "spclient"
            }
        )

        if request.status_code != 200:
            logging.error(f'Unable to request client bases ({request.status_code}): {request.text}')
            return

        def format_endpoint(endpoint: str):
            domain, port = endpoint.split(':', 1)
            match port:
                case "80":
                    return f'http://{domain}'
                case "443":
                    return f'https://{domain}'

        return list(
            map(
                format_endpoint,
                request.json().get('spclient')
            )
        )

    @staticmethod
    def _build_license_url(client_bases: list) -> str | None:
        if client_bases:
            return f'{client_bases[0]}/widevine-license/v1/audio/license'

    @staticmethod
    def get_id_type(url_id: str) -> tuple[str, IDType]:
        if url_id.startswith('http'):
            url_parse = urlparse(url_id)
            if url_parse.netloc != 'open.spotify.com':
                raise Exception("Invalid domain")
            split = url_parse.path.split('/')
            if len(split) < 3:
                raise Exception("Invalid URL path")
            return split[2], IDType(split[1])

        elif url_id.startswith('spotify:'):
            split = url_id.split(':')
            return split[2], IDType(split[1])

        return url_id, IDType.TRACK

    def _request_album(
            self,
            album_id: str,
            offset: int,
            initial_tracks: list
    ) -> list[tuple[str, IDType]]:
        album_request = requests.get(
            url=f'https://api.spotify.com/v1/albums/{album_id}/tracks',
            params={
                "offset": offset,
                "limit": 50
            },
            headers={
                "Authorization": f'Bearer {self.token_manager.get_access_token()}'
            }
        )

        if album_request.status_code != 200:
            logging.error(f"Unable to request album ({album_request.status_code}): {album_request.text}")
            return []

        album_json = album_request.json()

        tracks = list(
            map(
                lambda track: (track.get('id'), IDType.TRACK),
                album_json.get('items')
            )
        )

        if album_json.get('total') > 50:
            if (tracks_length := len(tracks)) > 0:
                return self._request_album(
                    album_id=album_id,
                    offset=offset + tracks_length,
                    initial_tracks=initial_tracks + tracks
                )
            else:
                return initial_tracks + tracks

        return tracks

    def _request_playlist(
            self,
            playlist_id: str,
            offset: int,
            initial_tracks: list
    ) -> list[tuple[str, IDType]]:
        playlist_request = requests.get(
            url=f'https://api.spotify.com/v1/playlists/{playlist_id}/tracks',
            params={
                "offset": offset,
                "limit": 100
            },
            headers={
                "Authorization": f'Bearer {self.token_manager.get_access_token()}'
            }
        )

        if playlist_request.status_code != 200:
            logging.error(f"Unable to request playlist ({playlist_request.status_code}): {playlist_request.text}")
            return []

        album_json = playlist_request.json()

        tracks = list(
            map(
                lambda item: (item.get('track', {}).get('id'), IDType.TRACK),
                album_json.get('items')
            )
        )

        if album_json.get('total') > 100:
            if (tracks_length := len(tracks)) > 0:
                return self._request_playlist(
                    playlist_id=playlist_id,
                    offset=offset + tracks_length,
                    initial_tracks=initial_tracks + tracks
                )
            else:
                return initial_tracks + tracks

        return tracks

    def _request_show(
            self,
            show_id: str,
            offset: int,
            initial_tracks: list
    ) -> list[tuple[str, IDType]]:
        show_request = requests.get(
            url=f'https://api.spotify.com/v1/shows/{show_id}/episodes',
            params={
                "offset": offset,
                "limit": 50
            },
            headers={
                "Authorization": f'Bearer {self.token_manager.get_access_token()}'
            }
        )

        if show_request.status_code != 200:
            logging.error(f"Unable to request show ({show_request.status_code}): {show_request.text}")
            return []

        show_json = show_request.json()

        tracks = list(
            map(
                lambda track: (track.get('id'), IDType.EPISODE),
                show_json.get('items')
            )
        )

        if show_json.get('total') > 50:
            if (tracks_length := len(tracks)) > 0:
                return self._request_show(
                    show_id=show_id,
                    offset=offset + tracks_length,
                    initial_tracks=initial_tracks + tracks
                )
            else:
                return initial_tracks + tracks

        return tracks

    def get_tracks(self) -> list[tuple[str, IDType]]:
        match self.id_type:
            case IDType.ALBUM:
                return self._request_album(
                    album_id=self.id,
                    offset=0,
                    initial_tracks=[]
                )
            case IDType.PLAYLIST:
                return self._request_playlist(
                    playlist_id=self.id,
                    offset=0,
                    initial_tracks=[]
                )
            case IDType.SHOW:
                return self._request_show(
                    show_id=self.id,
                    offset=0,
                    initial_tracks=[]
                )
            case _:
                return [(self.id, self.id_type)]

    @staticmethod
    def _spotify_id_to_hex(spotify_id: str) -> str:
        id_bytes = spotify_id.encode()
        alphabet = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

        dictionary = bytearray(256)
        for i in range(62):
            dictionary[alphabet[i]] = i & 0xff

        big = bytearray(22)
        for i in range(22):
            big[i] = dictionary[int.from_bytes(id_bytes[i].to_bytes(1, 'big'))]

        out = bytearray()
        while len(big) > 0:
            quotient = bytearray()
            remainder = 0

            for b in big:
                accumulator = int(b & 0xff) + remainder * 62
                digit = int((accumulator - (accumulator % 256)) / 256)
                remainder = int(accumulator % 256)

                if len(quotient) > 0 or digit > 0:
                    quotient += bytes([digit])

            out += bytes([remainder])
            big = quotient

        out.reverse()
        return out.hex()

    def _select_from_quality(
            self,
            file_entries: list
    ) -> str | None:
        for entry in file_entries:
            if entry.get('format') == self.quality:
                return entry.get('file_id', entry.get('fileId'))

        # desired quality wasn't found, get best
        logging.warning('Unable to find desired quality. Falling back to best.')
        if (best := list(
            filter(
                lambda e: e.get('format') in [*self.MP4_FORMATS, *self.OGG_FORMATS],
                sorted(
                    file_entries,
                    key=lambda e: sorted(e.get('format').split('_')),
                    reverse=True
                )
            )
        )):
            return best[0].get('file_id', best[0].get('fileId'))

    def _get_track_metadata(
            self,
            track_id: str
    ) -> tuple[str, str, str] | None:
        metadata_request = requests.get(
            url=f"https://spclient.wg.spotify.com/metadata/4/track/{self._spotify_id_to_hex(track_id)}",
            headers={
                "Accept": "application/json",
                "Authorization": f'Bearer {self.token_manager.get_access_token()}'
            }
        )

        if metadata_request.status_code != 200:
            logging.error(f"Unable to request track metadata ({metadata_request.status_code}): {metadata_request.text}")
            return

        meta_json = metadata_request.json()
        logging.debug(meta_json)

        title, artist = meta_json.get('name'), meta_json.get('artist', [{}])[0].get('name')
        files = meta_json.get('file')

        if not files:
            files = meta_json.get('alternative', [{}])[0].get('file')
        if not files:
            logging.error(f"'{title}' is not available")
            return

        return title, artist, self._select_from_quality(files)

    def _get_episode_metadata(
            self,
            track_id: str
    ) -> tuple[str, str, str] | None:
        metadata_request = requests.get(
            url="https://api-partner.spotify.com/pathfinder/v1/query",
            headers={
                "Accept": "application/json",
                "Authorization": f'Bearer {self.token_manager.get_access_token()}',
            },
            params={
                'operationName': 'getEpisodeOrChapter',
                'variables': json.dumps({
                    "uri": f"spotify:episode:{track_id}"
                }),
                'extensions': json.dumps({
                    "persistedQuery": {
                        "version": 1,
                        "sha256Hash": "9697538fe993af785c10725a40bb9265a20b998ccd2383bd6f586e01303824e9"
                    }
                })
            }
        )

        if metadata_request.status_code != 200:
            logging.error(
                f"Unable to request episode metadata ({metadata_request.status_code}): {metadata_request.text}")
            return

        meta_json = metadata_request.json()
        episode = meta_json.get('data', {}).get('episodeUnionV2')

        title, artist = episode.get('name'), episode.get('creator')
        items = episode.get('audio', {}).get('items', [])
        if not items:
            logging.error(f"'{title}' is not available")
            return

        return title, artist, self._select_from_quality(items)

    @staticmethod
    def _request_pssh(pssh_id: str) -> str | None:
        pssh_request = requests.get(
            url=f"https://seektables.scdn.co/seektable/{pssh_id}.json"
        )

        if pssh_request.status_code != 200:
            logging.error(f"Unable to request PSSH ({pssh_request.status_code}): {pssh_request.text}")
            return

        if not (pssh := pssh_request.json().get('pssh')):
            logging.error(f"Unable to locate PSSH in file manifest: {pssh_request.text}")
            return
        return pssh

    def _get_keys(
            self,
            pssh: str,
            license_url: str
    ) -> list[str] | None:
        device = Device.load(self._get_cdms()[0])
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
        challenge = cdm.get_license_challenge(session_id, PSSH(pssh))

        license_request = requests.post(
            url=license_url,
            headers={
                "Authorization": f'Bearer {self.token_manager.get_access_token()}',
            },
            data=challenge
        )

        if license_request.status_code != 200:
            logging.error(f"Unable to request license ({license_request.status_code}): {license_request.text}")
            return

        try:
            cdm.parse_license(session_id, license_request.content)
        except InvalidSession | InvalidLicenseMessage | InvalidContext | SignatureMismatch:
            logging.error(f"Unable to parse license: {license_request.text}")
            return

        keys = list(
            map(
                lambda key: f"{key.kid.hex}:{key.key.hex()}",
                filter(
                    lambda key: key.type == 'CONTENT',
                    cdm.get_keys(session_id)
                )
            )
        )
        cdm.close(session_id)
        return keys

    def _request_cdn_url(
            self,
            file_id: str
    ) -> str | None:
        cdn_request = requests.get(
            url=f"https://gew4-spclient.spotify.com/storage-resolve/files/audio/interactive/{file_id}",
            params={
                "alt": "json"
            },
            headers={
                'Authorization': f'Bearer {self.token_manager.get_access_token()}'
            }
        )

        if cdn_request.status_code != 200:
            logging.error(f"Unable to request CDN URL ({cdn_request.status_code}): {cdn_request.text}")
            return

        cdn_json = cdn_request.json()
        if not (cdn_url := cdn_json.get('cdnurl', [None])[0]):
            logging.error("No CDN URL found")
            return
        return cdn_url

    @staticmethod
    def _clean_name(file_name: str) -> str:
        allowed = " !#$%&'()+,-.0123456789;=@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{}~"
        return ''.join(
            filter(
                lambda c: c in allowed,
                file_name
            )
        )

    @staticmethod
    def _wget_download(url: str) -> str:
        output_file = wget.download(
            url=url,
            bar=lambda c, t, _: print(
                f'\r[INFO]: {round(c / t * 100)}% [{"#" * round(c / t * 100) + " " * (100 - round(c / t * 100))}] {round(c / 1000000, 2)}MB   ',
                end=''
            )
        )
        print()
        return output_file

    def download(
            self,
            track_info: tuple[str, IDType]
    ):
        track_id, track_type = track_info
        match track_type:
            case IDType.TRACK:
                if metadata := self._get_track_metadata(track_id):
                    title, artist, file_id = metadata
                else:
                    return
            case IDType.EPISODE:
                if metadata := self._get_episode_metadata(track_id):
                    title, artist, file_id = metadata
                else:
                    return
            case _:
                return

        if self.quality in self.MP4_FORMATS:
            if not (pssh := self._request_pssh(file_id)):
                return
            logging.debug(f"PSSH: {pssh}")

            if not (keys := self._get_keys(
                    pssh=pssh,
                    license_url=self.license_url
            )):
                return
            logging.debug(f"Keys: {keys}")

            if not (cdn_url := self._request_cdn_url(file_id)):
                return

            if exists(file_id):
                remove(file_id)

            downloaded = self._wget_download(cdn_url)

            if not exists(downloaded):
                logging.error("Downloaded file doesn't exist")
                return

            clean = self._clean_name(f'{title}{f" - {artist}" if artist else ""}')
            output_file = f"{join(self.output_folder, clean)}.m4a"

            if exists(output_file):
                remove(output_file)

            subprocess.run(
                command := [
                    "mp4decrypt/mp4decrypt",
                    *sum([['--key', i] for i in keys], []),
                    downloaded,
                    output_file
                ],
                shell=False
            )
            logging.debug(' '.join(command))

            if getsize(output_file) == 0:
                logging.error(f"Unable to decrypt {downloaded}")
                return
        elif self.quality in self.OGG_FORMATS:
            playplay_license_request = PlayPlayLicenseRequest(
                version=2,
                token=bytes.fromhex("01e132cae527bd21620e822f58514932"),
                interactivity=Interactivity.INTERACTIVE,
                content_type=AUDIO_TRACK
            )

            # TODO: move to method
            playplay_request = requests.post(
                url=f"https://gew4-spclient.spotify.com/playplay/v1/key/{file_id}",
                headers={
                    "Authorization": f"Bearer {self.token_manager.get_access_token()}",
                },
                data=playplay_license_request.SerializeToString()
            )

            playplay_license_response = PlayPlayLicenseResponse()
            playplay_license_response.ParseFromString(playplay_request.content)

            output = subprocess.check_output(
                [
                    'playplay/playplay',
                    file_id,
                    obfuscated := playplay_license_response.obfuscated_key.hex()
                ],
                shell=False
            )
            key = bytes.fromhex(output.strip().decode('utf-8'))
            logging.debug(f'obfuscated: {obfuscated}, deobfuscated: {key.hex()}')

            if not key:
                logging.error('Unable to decrypt key')
                return

            if not (cdn_url := self._request_cdn_url(file_id)):
                return

            if exists(file_id):
                remove(file_id)

            downloaded = self._wget_download(cdn_url)

            cipher = AES.new(
                key=key,
                mode=AES.MODE_CTR,
                counter=Counter.new(
                    128,
                    initial_value=int.from_bytes(b'r\xe0g\xfb\xdd\xcb\xcfw\xeb\xe8\xbcd?c\r\x93', "big")
                )
            )
            decrypted_buffer = cipher.decrypt(
                open(downloaded, 'rb').read()
            )

            if not decrypted_buffer.startswith(b"OggS"):
                logging.error("Decryption failed! The cause of this is still unknown, but 'OGG_VORBIS_160' should work.")
                return

            clean = self._clean_name(f'{title}{f" - {artist}" if artist else ""}')
            output_file = f"{join(self.output_folder, clean)}.ogg"

            with open(output_file, 'wb') as fw:
                fw.write(decrypted_buffer[167:])
        else:
            return

        remove(downloaded)
        logging.info(f'Finished: {clean}')
        time.sleep(1)  # anti-timeout
