from oauth.oauth import OAuthToken
from oauth_backend.models import Token, DataStore


class SSODataStore(DataStore):
    def __init__(self, oauth_request=None):
        """To serve as a Piston datastore we'll need provide this signature.

        We later won't use the oauth_request, so we can ignore it here.
        """
        super(SSODataStore, self).__init__()

    def lookup_token(self, token_type, token_field):
        """
        :param token_type: type of token to lookup
        :param token_field: token to look up

        :note: token_type should always be 'access' as only such tokens are
               stored in database

        :returns: OAuthToken object
        """
        assert token_type == 'access'

        try:
            token = Token.objects.get(token=token_field)
            # Piston expects OAuth tokens to have 'consumer' and 'user' atts.
            # (see piston.authentication.OAuthAuthentication.is_authenticated)
            oauthtoken = OAuthToken(token.token, token.token_secret)
            oauthtoken.consumer = token.consumer
            oauthtoken.user = token.consumer.user
            return oauthtoken
        except Token.DoesNotExist:
            return None
