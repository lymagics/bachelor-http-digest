from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from auth.digest import HTTPDigestAuth
from users.selectors import user_get


class DigestAuthentication(authentication.BaseAuthentication):
    """
    HTTP Digest Authentication class.
    """
    def __init__(self) -> None:
        super().__init__()
        self.auth = HTTPDigestAuth()

    def authenticate(self, request: Request):
        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            return None
        digest = self.auth.parse_header(auth_header)
        if not digest:
            return None

        if 'username' not in digest:
            return None
        user = user_get(digest['username'])
        if user is None:
            return None
        digest['method'] = request.method

        if not self.auth.authenticate(digest, user.password):
            error = 'Digest authentication failed.'
            raise AuthenticationFailed(error)
        return (user, None)
    
    def authenticate_header(self, request):
        return self.auth.authenticate_header
