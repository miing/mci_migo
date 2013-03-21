# Copyright 2012 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from datetime import datetime

from django.http import HttpResponseBadRequest, HttpResponseNotFound

from api.v10.decorators import (
    plain_user_required, named_operation)
from api.v10.handlers import (
    LazrRestfulHandler,
    RootHandler,
    api_error,
)
from identityprovider.signals import application_token_created


class RootHandler(RootHandler):
    allowed_methods = ('GET',)

    response = {
        "registrations_collection_link": "%s/api/1.1/registration",
        "captchas_collection_link": "%s/api/1.1/captchas",
        "authentications_collection_link": "%s/api/1.1/authentications",
        "resource_type_link": "%s/api/1.1/#service-root",
        "accounts_collection_link": "%s/api/1.1/accounts",
    }

    wadl_template = 'api/wadl1.1.xml'


class AuthenticationHandler(LazrRestfulHandler):
    """All these methods assume that they're run behind Basic Auth."""
    allowed_methods = ('GET', 'POST', 'PUT')
    response = {
        "total_size": 0,
        "start": None,
        "resource_type_link": "%s/api/1.1/#authentications",
        "entries": []
    }

    def update(self, request):
        if not 'ws.op' in request.PUT:
            return api_error(HttpResponseBadRequest,
                             'No operation name given.')
        return self.named_operation(request, request.PUT)

    @plain_user_required
    @named_operation
    def authenticate(self, request):
        data = request.data
        account = request.user
        token_name = data.get('token_name')
        token_data = data.get('token')

        def create_token():
            token = account.create_oauth_token(token_name)
            application_token_created.send(
                sender=self, openid_identifier=account.openid_identifier)
            return token

        def refresh_token():
            token = get_token()
            if token is not None:
                token.updated_at = datetime.utcnow()
                token.save()
            return token

        def get_token():
            tokens = account.oauth_tokens()
            if not tokens.count():
                # account has no tokens
                return
            filter_spec = {
                'name': token_name,
            }
            if token_data is not None:
                filter_spec.update(token=token_data)
            tokens = tokens.filter(**filter_spec)
            if not tokens.count():
                # token was not found
                return

            # token was found so we update and return it
            token = tokens[0]
            return token

        token = None
        if request.method == 'GET':
            token = get_token()
        elif request.method == 'POST':
            token = create_token()
        elif request.method == 'PUT':
            token = refresh_token()

        if token is None:
            return HttpResponseNotFound()
        return token.serialize()
