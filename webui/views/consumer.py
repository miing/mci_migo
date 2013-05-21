# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

# This module is based on code from Janrain's python-openid project.
# Please see the license file in the thirdparty/python-openid directory.

from urlparse import urljoin

from django.conf import settings
from django.contrib import messages
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.template.context import RequestContext
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import csrf_exempt

from openid import fetchers
from openid.consumer import consumer
from openid.consumer.discover import DiscoveryFailure
from openid.extensions import sreg
from openid.message import OPENID1_URL_LIMIT
from openid.yadis.constants import YADIS_HEADER_NAME, YADIS_CONTENT_TYPE
from openid.server.trustroot import RP_RETURN_TO_URL_TYPE
from openid.store.memstore import MemoryStore

from identityprovider import teams
from identityprovider.views.utils import require_testing_enabled

TEAMS_REQUESTED = ['canonical-partner-dev', 'hwdb-team', 'otherteam']
SREG_DONT_REQUEST = 0
SREG_OPTIONAL = 1
SREG_REQUIRED = 2
OP_CANCELLED = _('OpenID authentication cancelled.')
OP_FAILURE = _('OpenID authentication failed.')
OP_SETUP_NEEDED = _('OpenID Provider reports setup needed (not currently '
                    'logged in).')
OP_SUCCESS = _('OpenID authentication succeeded')


store = None
fetchers.setDefaultFetcher(fetchers.Urllib2Fetcher())


def get_base_url(request):
    """Return the OpenID 'trust root' for the given django request.

    Given a Django web request object, returns the OpenID 'trust root'
    for that request; namely, the absolute URL to the site root which
    is serving the Django request.  The trust root will include the
    proper scheme and authority.  It will lack a port if the port is
    standard (80, 443).
    """
    name = request.META.get('HTTP_HOST', '')
    try:
        name = name[:name.index(':')]
    except:
        pass

    try:
        port = int(request.META['SERVER_PORT'])
    except:
        port = 80

    proto = request.META['SERVER_PROTOCOL']
    is_https = 'HTTPS' in request.META and bool(request.META['HTTPS'])

    if 'HTTPS' in proto or is_https:
        proto = 'https'
    else:
        proto = 'http'

    if port in [80, 443] or not port:
        port = ''
    else:
        port = ':%s' % (port,)

    url = "%s://%s%s/" % (proto, name, port)
    return url


def to_regular_dict(request_data):
    """Convert a django request MutliValueDict into a standard python dict.

    MutliValueDict (e.g., request.GET, request.POST) are converted to a dict
    whose values are the first value from each of the MultiValueDict's value
    lists. This avoids the OpenID library's refusal to deal with dicts whose
    values are lists, because in OpenID, each key in the query arg set can have
    at most one value.

    """
    return dict((k, v) for k, v in request_data.iteritems())


def get_consumer(request):
    """Get a Consumer object to perform OpenID authentication."""
    global store
    # use a MemoryStore since this is used with settings.TESTING enabled only
    if store is None:
        store = MemoryStore()
    return consumer.Consumer(request.session, store)


def get_view_full_url(request, view_name_or_obj, args=None, kwargs=None):
    relative_url = reverse(view_name_or_obj, args=args, kwargs=kwargs)
    full_path = request.META.get('SCRIPT_NAME', '') + relative_url
    return urljoin(get_base_url(request), full_path)


def render_index_page(request, **template_args):
    template_args['consumer_url'] = get_view_full_url(request, start_open_id)
    assert settings.SSO_ROOT_URL
    template_args['openid'] = settings.SSO_ROOT_URL
    template_args['sreg_fields'] = [
        {'name': 'nickname', 'label': 'Nickname', 'default': SREG_REQUIRED},
        {'name': 'fullname', 'label': 'Full name', 'default': SREG_REQUIRED},
        {'name': 'email', 'label': 'Email', 'default': SREG_REQUIRED},
        {'name': 'language', 'label': 'Language', 'default': SREG_OPTIONAL},
        {'name': 'timezone', 'label': 'Time zone', 'default': SREG_OPTIONAL},
        {'name': 'dob', 'label': 'Date of Birth <em>(not supported)</em>',
            'default': SREG_DONT_REQUEST},
        {'name': 'gender', 'label': 'Gender <em>(not supported)</em>',
            'default': SREG_DONT_REQUEST},
        {'name': 'country', 'label': 'Country <em>(not supported)</em>',
            'default': SREG_DONT_REQUEST},
        {'name': 'postalcode', 'label': 'Postal Code <em>(not supported)</em>',
            'default': SREG_DONT_REQUEST}
    ]
    template_args['sreg_states'] = [SREG_REQUIRED, SREG_OPTIONAL,
                                    SREG_DONT_REQUEST]

    response = render(
        request, 'consumer/index.html', template_args)
    response[YADIS_HEADER_NAME] = get_view_full_url(request, rpXRDS)
    return response


@require_testing_enabled
@csrf_exempt
def start_open_id(request):
    """Start the OpenID authentication process.

    Renders an authentication form and accepts its POST.

    * Renders an error message if OpenID cannot be initiated

    * Requests some Simple Registration data using the OpenID
      library's Simple Registration machinery

    * Generates the appropriate trust root and return URL values for
      this application (tweak where appropriate)

    * Generates the appropriate redirect based on the OpenID protocol
      version.

    The view is CSRF exempt as we want to avoid passing the CSRF token
    to the provider as part of the request.
    """
    if request.POST:
        # Start OpenID authentication.
        openid_url = request.POST['openid_identifier']
        c = get_consumer(request)

        try:
            auth_request = c.begin(openid_url)
        except DiscoveryFailure, e:
            # Some other protocol-level failure occurred.
            error = _("OpenID discovery error: %s") % (str(e),)
            messages.error(request, error)
            # Render the page with an error.
            return render_index_page(request)

        if request.POST['mode'] == 'immediate':
            immediate = True
        else:
            immediate = False

        # Add Simple Registration request information.  Some fields
        # are optional, some are required.  It's possible that the
        # server doesn't support sreg or won't return any of the
        # fields.
        if request.POST.get('sreg', False):
            req_fields = [[], [], []]

            for field in sreg.data_fields.keys():
                try:
                    index = int(request.POST.get('sreg_%s' % field))
                except (TypeError, ValueError):
                    index = SREG_DONT_REQUEST
                req_fields[index].append(field)

            sreg_request = sreg.SRegRequest(optional=req_fields[SREG_OPTIONAL],
                                            required=req_fields[SREG_REQUIRED])
            auth_request.addExtension(sreg_request)

        if request.POST.get('teams', False):
            req_teams = request.POST.get('request_teams', '')
            auth_request.addExtension(teams_request_from_string(req_teams))

        # Compute the trust root and return URL values to build the
        # redirect information.
        trust_root = get_view_full_url(request, start_open_id)
        return_to = get_view_full_url(request, finish_open_id)

        if bool(request.POST.get('forcelongurl')):
            return_to += '?a=' + ('a' * OPENID1_URL_LIMIT)

        # Send the browser to the server either by sending a redirect
        # URL or by generating a POST form.
        if auth_request.shouldSendRedirect():
            url = auth_request.redirectURL(trust_root, return_to, immediate)
            return HttpResponseRedirect(url)
        else:
            # Beware: this renders a template whose content is a form
            # and some javascript to submit it upon page load.  Non-JS
            # users will have to click the form submit button to
            # initiate OpenID authentication.
            form_id = 'openid_message'
            form_html = auth_request.formMarkup(trust_root, return_to,
                                                immediate, {'id': form_id})
            context = RequestContext(request, {'html': form_html})
            return render(request, 'consumer/request_form.html', context)

    return render_index_page(request)


def teams_request_from_string(teams_str):
    req_teams = [t.strip() for t in teams_str.split(',') if t.strip()]
    return teams.TeamsRequest(req_teams)


@require_testing_enabled
@csrf_exempt
def finish_open_id(request):
    """Finish the OpenID authentication process.

    Invoke the OpenID library with the response from the OpenID server and
    render a page detailing the result.

    The view is CSRF exempt as we need to POST back from the provider
    sometimes when handling long query strings and that fails without the
    exemption.
    """
    result = {}

    # Because the object containing the query parameters is a
    # MultiValueDict and the OpenID library doesn't allow that, we'll
    # convert it to a normal dict.

    # OpenID 2 can send arguments as either POST body or GET query
    # parameters.
    request_args = to_regular_dict(request.GET)
    if request.method == 'POST':
        request_args.update(to_regular_dict(request.POST))

    if request_args:
        c = get_consumer(request)

        # Get a response object indicating the result of the OpenID
        # protocol.
        return_to = get_view_full_url(request, finish_open_id)
        response = c.complete(request_args, return_to)

        # Get a Simple Registration response object if response
        # information was included in the OpenID response.
        sreg_response = {}
        teams_response = {}
        if response.status == consumer.SUCCESS:
            sreg_response = sreg.SRegResponse.fromSuccessResponse(response)
            teams_response = teams.TeamsResponse.fromSuccessResponse(response)

        result = {}
        # Map different consumer status codes to template contexts.
        if response.status == consumer.CANCEL:
            messages.error(request, OP_CANCELLED)
        elif response.status == consumer.SETUP_NEEDED:
            messages.error(request, OP_SETUP_NEEDED)
        elif response.status == consumer.SUCCESS:
            result = {
                'url': response.getDisplayIdentifier(),
                'sreg': sreg_response and sreg_response.items(),
                'teams': teams_response and teams_response.is_member
            }
            messages.success(request, OP_SUCCESS)
        else:
            assert response.status == consumer.FAILURE
            msg = OP_FAILURE
            if isinstance(response, consumer.FailureResponse):
                # In a real application, this information should be
                # written to a log for debugging/tracking OpenID
                # authentication failures. In general, the messages are
                # not user-friendly, but intended for developers.
                msg += ' (%s)' % response.message
            messages.error(request, msg)

    return render_index_page(request, **result)


@require_testing_enabled
def rpXRDS(request):
    """Return a relying party verification XRDS document."""
    args = {
        'type_uris': [RP_RETURN_TO_URL_TYPE],
        'endpoint_uris': [get_view_full_url(request, finish_open_id)],
    }
    response = render(request, 'server/openidapplication-xrds.xml',
                      args)
    response['Content-Type'] = YADIS_CONTENT_TYPE
    return response
