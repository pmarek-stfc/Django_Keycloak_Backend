import json
import logging
import requests

from django.conf import settings
from django.contrib.auth.models import User
from requests_oauthlib import OAuth2Session

logger = logging.getLogger(__name__)


class KeycloakBackend(object):
    """Integrating Django with Keycloak using OpenID Connect (OIDC)"""

    def authenticate(self, request=None):
        """
            Verifies a set of credentials. Checks them against each
            authentication backend, and returns a User object if the
            credentials are valid for a backend. If the credentials
            aren’t valid for any backend or if a backend raises
            an exception, it returns None

        """
        try:
            token = self._redirection(request)
            userinfo = self._handle_token(token)
            return self._handle_userinfo(userinfo)
        except Exception as e:
            logger.exception("Something happened while logging in", exc_info=e)
            return None

    def get_user(self, user_id):
        """
            Returns the authenticated user object.
            This method is only ever called after successful validation.

        """

        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def _redirection(self, request):
        """
            Gets a token from Keycloak backend and then returns it.

        :param request:
        :return: token
        """

        authorization_code_url = request.build_absolute_uri()
        client_id = settings.KEYCLOAK_CLIENT_ID
        client_secret = settings.KEYCLOAK_CLIENT_SECRET
        token_url = settings.KEYCLOAK_TOKEN_URL
        state = request.session['OAUTH2_STATE']
        redirect_uri = request.session['OAUTH2_REDIRECT_URI']

        oauth2_session = OAuth2Session(client_id,
                                       scope='openid email profile',
                                       redirect_uri=redirect_uri,
                                       state=state)
        token = oauth2_session.fetch_token(token_url,
                                           client_secret=client_secret,
                                           authorization_response=authorization_code_url)
        return token


    def _handle_token(self, token):
        """
            Sends an access token obtained in '_redirection' method to the resource server
            django app. The resource server validates the token and sends appropriate 
            response back which is then handled.

        :param token:
        :return: username
        """

        token = token['access_token']
        headers = {
            'Authorization': 'Bearer {}'.format(token)
        }
        # Firstly, send token towards the resource server
        # Secondly, extract headers from response sent by the server
        response = requests.get('http://localhost:8001/verify', headers=headers).headers

        convert_to_json = json.loads(response['user_info'])
        username = convert_to_json['preferred_username']
        return username

    def _handle_userinfo(self, userinfo):
        """
            Returns user object which is then processed by 'get_user' method

        :param userinfo:
        :return: user
        """

        username = userinfo
        try:
            user = User.objects.get(username=username)
            # Update these fields each time, in case they have changed
            user.save()
            return user
        except User.DoesNotExist:
            user = User(username=username)
            user.save()
            return user
