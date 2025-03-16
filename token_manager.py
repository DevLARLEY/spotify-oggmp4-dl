import hashlib
import hmac
import math
import struct
import time
from curl_cffi import requests as curl_requests

from config_manager import cM
import logging


class TokenManager:
    TOKEN_URL = 'https://open.spotify.com/get_access_token'

    HOTP_SECRET = b'5507145853487499592248630329347'
    HOTP_PERIOD = 30

    def __init__(self):
        self.sp_dc = None
        self.access_token = None
        self.access_token_expire = -1

    def query_sp_dc(self):
        if sp_dc := cM.simple_get('sp_dc'):
            self.sp_dc = sp_dc
        else:
            logging.info("sp_dc: ")
            self.sp_dc = input()
            cM.simple_set('sp_dc', self.sp_dc)

        self.access_token = self.get_access_token()

    @staticmethod
    def _generate_hotp(secret: bytes, counter: int, digits: int = 6) -> str:
        counter_bytes = struct.pack(">Q", counter)

        hmac_digest = hmac.new(secret, counter_bytes, hashlib.sha1).digest()

        offset = hmac_digest[-1] & 0x0F
        binary_code = (
                (hmac_digest[offset] & 0x7F) << 24 |
                (hmac_digest[offset + 1] & 0xFF) << 16 |
                (hmac_digest[offset + 2] & 0xFF) << 8 |
                (hmac_digest[offset + 3] & 0xFF)
        )

        otp = binary_code % (10 ** digits)

        return str(otp).zfill(digits)

    def _request_access_token(
            self,
            sp_dc: str
    ) -> tuple[str, str]:
        timestamp = int(time.time() * 1000)
        counter = math.floor(timestamp / 1000 / self.HOTP_PERIOD)
        hotp = self._generate_hotp(self.HOTP_SECRET, counter)

        token_request = curl_requests.get(
            url=self.TOKEN_URL,
            params={
                'productType': 'web-player',
                'totp': hotp,
                'totpVer': '5'
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
