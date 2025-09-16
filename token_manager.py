import hashlib
import hmac
import logging
import math
import time

import requests
from curl_cffi import requests as curl_requests

from config_manager import cM


class TokenManager:
    TOKEN_URL = 'https://open.spotify.com/api/token'

    SPOTIFY_SECRETS_JSON = "https://raw.githubusercontent.com/Thereallo1026/spotify-secrets/refs/heads/main/secrets/secretDict.json"
    HOTP_PERIOD = 30
    HOTP_DIGITS = 6

    def __init__(self):
        self.sp_dc = None
        self.access_token = None
        self.access_token_expire = -1

        version, secret_cipher_bytes = self.get_latest_secret()
        self.version = version
        self.secret = self.derive_secret_number(secret_cipher_bytes).encode()

    @staticmethod
    def derive_secret_number(secret_cipher_bytes: list[int]) -> str:
        transformed = [byte ^ ((i % 33) + 9) for i, byte in enumerate(secret_cipher_bytes)]
        return "".join(str(n) for n in transformed)

    def get_latest_secret(self) -> tuple[int, list[int]]:
        response = requests.get(self.SPOTIFY_SECRETS_JSON)
        response.raise_for_status()
        secrets = response.json()
        latest_version = max(int(v) for v in secrets.keys())
        return latest_version, secrets[str(latest_version)]

    def query_sp_dc(self):
        if sp_dc := cM.simple_get('sp_dc'):
            self.sp_dc = sp_dc
        else:
            logging.info("sp_dc: ")
            self.sp_dc = input()
            cM.simple_set('sp_dc', self.sp_dc)

        self.access_token = self.get_access_token()

    def generate_hotp(self, timestamp: int) -> str:
        counter = math.floor(timestamp / 1000 / self.HOTP_PERIOD)
        counter_bytes = counter.to_bytes(8, byteorder='big')

        h = hmac.new(self.secret, counter_bytes, hashlib.sha1)
        hmac_result = h.digest()

        offset = hmac_result[-1] & 0x0F
        binary = (
            (hmac_result[offset] & 0x7F) << 24
            | (hmac_result[offset + 1] & 0xFF) << 16
            | (hmac_result[offset + 2] & 0xFF) << 8
            | (hmac_result[offset + 3] & 0xFF)
        )

        return str(binary % (10 ** self.HOTP_DIGITS)).zfill(self.HOTP_DIGITS)

    def _request_access_token(
            self,
            sp_dc: str
    ) -> tuple[str, str]:
        server_time = int(time.time() * 1000)
        hotp = self.generate_hotp(server_time)

        token_request = curl_requests.get(
            url=self.TOKEN_URL,
            params={
                'reason': 'init',
                'productType': 'web-player',
                'totp': str(hotp),
                'totpServer': str(hotp),
                'totpVer': str(self.version),
            },
            cookies={
                'sp_dc': sp_dc,
            }
        )

        if token_request.status_code != 200:
            logging.error(f"Unable to request token ({token_request.status_code}): {token_request.text}")
            exit(1)

        if (token_json := token_request.json()).get('isAnonymous'):
            logging.error("sp_dc cookie is invalid")
            cM.simple_set('sp_dc', None)
            exit(1)

        access_token = token_json.get('accessToken')
        cM.simple_set('accessToken', access_token)

        access_token_expire = token_json.get('accessTokenExpirationTimestampMs')
        cM.simple_set('accessTokenExpire', access_token_expire)

        return access_token, access_token_expire

    def get_access_token(self):
        if int(time.time() * 1000) >= cM.simple_get('accessTokenExpire'):
            self.access_token, self.access_token_expire = self._request_access_token(self.sp_dc)
        if not self.access_token:
            return cM.simple_get('accessToken')
        return self.access_token
