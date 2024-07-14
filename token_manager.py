from time import time_ns
import requests

from config_manager import cM
import logging


class TokenManager:
    TOKEN_URL = 'https://open.spotify.com/get_access_token'

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

    def _request_access_token(
            self,
            sp_dc: str
    ) -> tuple[str, str]:
        token_request = requests.get(
            url=self.TOKEN_URL,
            headers={'Cookie': f'sp_dc={sp_dc}'}
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
        if (time_ns() // 1_000_000) >= cM.simple_get('accessTokenExpire'):
            self.access_token, self.access_token_expire = self._request_access_token(self.sp_dc)
        if not self.access_token:
            return cM.simple_get('accessToken')
        return self.access_token
