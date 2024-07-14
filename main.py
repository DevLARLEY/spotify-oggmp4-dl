import argparse
import logging

from config_manager import cM
from spotify import Spotify
from token_manager import TokenManager

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="Spotify Downloader")
    parser.add_argument(
        '--id',
        type=str,
        help='Spotify URL/URI/ID',
        required=True
    )
    parser.add_argument(
        '--quality',
        help='Quality level',
        default='MP4_128',
        required=False,
        choices=[
            'MP4_128',
            'MP4_128_DUAL',
            'MP4_256',
            'MP4_256_DUAL',
            'OGG_VORBIS_320',
            'OGG_VORBIS_160',
            'OGG_VORBIS_96',
            'AAC_24'
        ]
    )
    parser.add_argument(
        '--output',
        type=str,
        default='.',
        help='Output path',
        required=False,
    )
    parser.add_argument(
        '--debug',
        action="store_true",
        default=False,
        help='Print debug information',
        required=False
    )
    args = parser.parse_args()

    # TODO: add metadata

    cM.initialize()
    logging.basicConfig(format='[%(levelname)s]: %(message)s', level=logging.DEBUG if args.debug else logging.INFO)

    token_manager = TokenManager()
    token_manager.query_sp_dc()

    spotify = Spotify(
        url_id=args.id,
        token_manager=token_manager,
        quality=args.quality,
        output_folder=args.output
    )

    for track in spotify.get_tracks():
        spotify.download(track)
