import hmac
from hashlib import md5
from random import SystemRandom

from werkzeug.http import parse_dict_header


class HTTPDigestAuth:
    def __init__(self, realm: str = None, qop: str = 'auth'):
        self.scheme = 'Digest'
        self.realm = realm or 'Authentication Required'
        self.qop = qop
        self.algorithm = 'md5'
        self.random = SystemRandom()
        self.random.random()

    @property
    def authenticate_header(self) -> str:
        nonce = self.generate_random()
        opaque = self.generate_random()
        return ('{0} realm="{1}",nonce="{2}",opaque="{3}",algorithm="{4}"'
                ',qop="{5}"').format(
            self.scheme, self.realm, nonce,
            opaque, self.algorithm, self.qop)

    def parse_header(self, auth_header: str):
        if not auth_header.startswith('Digest '):
            return None
        header_values = auth_header.removeprefix('Digest ')
        return parse_dict_header(header_values)

    def authenticate(self, auth: dict, stored_password: str) -> bool:
        if not auth or 'username' not in auth or 'realm' not in auth \
                or 'nonce' not in auth or 'response' not in auth \
                or 'cnonce' not in auth or 'nc' not in auth:
            return False
        a1 = auth['username'] + ':' + auth['realm'] + ':' + stored_password
        ha1 = md5(a1.encode('utf-8')).hexdigest()
        a2 = auth['method'] + ':' + auth['uri']
        ha2 = md5(a2.encode('utf-8')).hexdigest()
        a3 = ha1 + ':' + auth['nonce'] + ':' + auth['nc'] + ':' + \
            auth['cnonce'] + ':auth:' + ha2
        response = md5(a3.encode('utf-8')).hexdigest()
        print(response, auth['response'])
        return hmac.compare_digest(response, auth['response'])

    def generate_random(self) -> str:
        return md5(str(self.random.random()).encode('utf-8')).hexdigest()
