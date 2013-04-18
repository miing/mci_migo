# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

import logging
import re
import urllib
import urlparse

from datetime import (
    datetime,
    timedelta,
)

from openid import oidutil
from openid.extensions import (
    ax,
    pape,
)
from openid.extensions.sreg import (
    SRegRequest,
    SRegResponse,
)
from openid.message import (
    IDENTIFIER_SELECT,
    registerNamespaceAlias,
)
from openid.server.server import (
    BROWSER_REQUEST_MODES,
    ENCODE_URL,
    CheckIDRequest,
    ProtocolError,
    Server,
)
from openid.server.trustroot import TrustRoot
from openid.urinorm import urinorm
from openid.yadis.constants import YADIS_HEADER_NAME

from django.conf import settings
from django.contrib import auth, messages
from django.core.urlresolvers import reverse
from django.http import (
    Http404,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseForbidden,
    HttpResponseRedirect,
)
from django.template import (
    RequestContext,
    loader,
)
from django.shortcuts import (
    get_object_or_404,
    render_to_response,
)
from django.utils.decorators import decorator_from_middleware
from django.utils import translation
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import csrf_exempt
from gargoyle.decorators import switch_is_active
from oauth.oauth import OAuthRequest
from oauth_backend.models import Token

import identityprovider.signed as signed

from identityprovider.const import (
    AX_DATA_FIELDS,
    LAUNCHPAD_TEAMS_NS,
)
from identityprovider.forms import (
    AXFetchRequestForm,
    PreAuthorizeForm,
    SRegRequestForm,
    TeamsRequestForm,
)

from identityprovider.middleware.xrds import XRDSMiddleware
from identityprovider.models import (
    Account,
    DjangoOpenIDStore,
    OpenIDAuthorization,
    OpenIDRPConfig,
    OpenIDRPSummary,
    twofactor,
    get_team_memberships_for_user,
)
from identityprovider.models.authtoken import create_token
from identityprovider.models.twofactor import is_twofactor_enabled
from identityprovider.teams import TeamsRequest
from identityprovider.views import utils

SITE_REQUIRES_VERIFIED = _(
    'The site {rp_name} requires that you verify your email address before '
    'accessing its contents.')

accept_xrds = decorator_from_middleware(XRDSMiddleware)
registerNamespaceAlias(LAUNCHPAD_TEAMS_NS, 'lp')
logger = logging.getLogger('sso')


# moved from views.i18n to be able to split django apps and
# avoid circular deps
def set_language_info(request, response, lang):
    if lang not in settings.SUPPORTED_LANGUAGES:
        lang = 'en'
    if hasattr(request, 'session'):
        request.session['django_language'] = lang
    else:
        response.set_cookie(settings.LANGUAGE_COOKIE_NAME, lang)


@csrf_exempt
@accept_xrds
def openid_provider(request, lang=None):
    if lang not in settings.SUPPORTED_LANGUAGES:
        # Next we check for a primary language.
        if lang is not None:
            lang = lang.split('_')[0]  # e.g. de_CH becomes de.
        if lang not in settings.SUPPORTED_LANGUAGES:
            lang = translation.get_language_from_request(request)
    translation.activate(lang)
    openid_server = _get_openid_server()
    querydict = dict(request.REQUEST.items())
    logger.debug("querydict = " + str(querydict))
    try:
        orequest = openid_server.decodeRequest(querydict)
        response = _process_openid_request(request, orequest, openid_server)
    except ProtocolError, e:
        response = _handle_openid_error(e)
    set_language_info(request, response, lang)
    return response


def _process_openid_request(request, orequest, openid_server):
    if not orequest:
        context = RequestContext(request)
        return render_to_response('server/server_info.html', context)

    if orequest.mode in ("checkid_immediate", "checkid_setup"):
        if (utils.get_rpconfig(orequest.trust_root) is None and
                getattr(settings, 'SSO_RESTRICT_RP', True)):
            # This is an untrusted RP.  We don't play with these for now.
            logger.debug("Untrusted RP: %s" % orequest.trust_root)
            token = create_token(16)
            request.session[token] = signed.dumps(orequest,
                                                  settings.SECRET_KEY)
            response = HttpResponseRedirect('/%s/+untrusted' % token)
        else:
            response = _handle_user_response(request, orequest)
    else:
        oresponse = openid_server.handleRequest(orequest)
        response = _django_response(request, oresponse)

    return response


def _handle_openid_error(error):
    if error.whichEncoding() == ENCODE_URL:
        url = error.encodeToURL()
        return HttpResponseRedirect(url)
    else:
        response = HttpResponse(error.encodeToKVForm())
        response['Content-Type'] = 'text/plain;charset=utf-8'
        return response


def _handle_user_response(request, orequest):
    response = None
    if orequest.immediate:
        rp_config = utils.get_rpconfig(orequest.trust_root)
        auto_authorized = _is_auto_authorized_rp(rp_config)
        if (auto_authorized and twofactor.is_authenticated(request) and
                _is_identity_owner(request.user, orequest)):
            if orequest.idSelect():
                oresponse = orequest.answer(
                    True, identity=request.user.openid_identity_url)
            else:
                oresponse = orequest.answer(True)
            _add_sreg(request, orequest, oresponse)
            _add_ax(request, orequest, oresponse)
            _check_team_membership(request, orequest, oresponse,
                                   immediate=True)
            response = _django_response(request, oresponse, True)
        else:
            oresponse = orequest.answer(False)
            response = _django_response(request, oresponse)
    elif not _is_valid_openid_for_this_site(orequest.identity):
        context = RequestContext(request, {
            'trust_root': orequest.trust_root,
            'identifier': orequest.identity,
            'continue_url': orequest.answer(False).encodeToURL(),
        })
        response = render_to_response('server/invalid_identifier.html',
                                      context)
    elif _openid_is_authorized(request, orequest):
        if orequest.idSelect():
            oresponse = orequest.answer(
                True, identity=request.user.openid_identity_url)
        else:
            oresponse = orequest.answer(True)
        _add_sreg(request, orequest, oresponse)
        _add_ax(request, orequest, oresponse)
        _check_team_membership(request, orequest, oresponse, immediate=True)
        response = _django_response(request, oresponse, True)
    elif (twofactor.is_authenticated(request) and not
          _is_identity_owner(request.user, orequest)):
        oresponse = orequest.answer(False)
        response = _django_response(request, oresponse, True)
    else:
        token = create_token(16)
        request.session[token] = signed.dumps(orequest,
                                              settings.SECRET_KEY)
        response = HttpResponseRedirect('/%s/+decide' % token)
    referer = request.META.get('HTTP_REFERER')
    if referer:
        response.set_cookie('openid_referer', referer)
    return response


def _is_valid_openid_for_this_site(identity):
    try:
        identity = urinorm(identity)
        idparts = urlparse.urlparse(identity)
        srvparts = urlparse.urlparse(settings.SSO_ROOT_URL)
        if identity == IDENTIFIER_SELECT:
            return True

        if (idparts.port != srvparts.port or
                idparts.scheme != srvparts.scheme):
            return False

        if (idparts.hostname != srvparts.hostname and
                not srvparts.hostname.endswith(".%s" % idparts.hostname)):
            return False

        accept_path_patterns = [
            '^/$',
            '^/\+id/[a-zA-Z0-9\-_\.]+$',
            '^/~[a-zA-Z0-9\-_\.]+$',
        ]
        for pattern in accept_path_patterns:
            if re.match(pattern, idparts.path) is not None:
                return True
        return False
    except:
        return False


def _get_orequest(request, token):
    """Returns the OpenID request for the given request from the
    user's browser.  May throw an exception if there is no OpenID
    request, or if it is invalid."""
    raw_orequest = request.session.get(token, None)
    return signed.loads(raw_orequest, settings.SECRET_KEY)


def decide(request, token):
    try:
        orequest = _get_orequest(request, token)
        rpconfig = utils.get_rpconfig(orequest.trust_root)
    except:
        return HttpResponse("Invalid OpenID transaction")

    if not request.user.is_authenticated():
        # XXX: need to remove this circular dep to the webui app
        from webui.views import ui
        return ui.LoginView.as_view()(request, token, rpconfig=rpconfig)

    if (not request.user.is_verified and
            rpconfig is not None and not rpconfig.allow_unverified):
        messages.warning(
            request,
            SITE_REQUIRES_VERIFIED.format(rp_name=rpconfig.displayname),
        )
        return HttpResponseRedirect(reverse('account-emails'))

    site_requires_twofactor = twofactor.site_requires_twofactor_auth(
        request, token, rpconfig)
    if (not twofactor.is_authenticated(request) or
            (site_requires_twofactor and not twofactor.is_upgraded(request))):
        if is_twofactor_enabled(request):
            return HttpResponseRedirect(reverse('twofactor', args=[token]))
        else:
            return _process_decide(request, orequest, decision=False)

    if ('ok' in request.POST or
            (rpconfig is not None and rpconfig.auto_authorize)):
        return _process_decide(request, orequest, decision=True)

    sreg_request = SRegRequest.fromOpenIDRequest(orequest)
    ax_request = ax.FetchRequest.fromOpenIDRequest(orequest)
    teams_request = TeamsRequest.fromOpenIDRequest(orequest)
    try:
        summary = OpenIDRPSummary.objects.get(
            account=request.user, trust_root=orequest.trust_root,
            openid_identifier=request.user.openid_identity_url)
        approved_data = summary.get_approved_data()
    except OpenIDRPSummary.DoesNotExist:
        approved_data = {}

    ax_form = (AXFetchRequestForm(
        request, ax_request, rpconfig, approved_data=approved_data.get('ax'))
        if ax_request else None)
    sreg_form = SRegRequestForm(request, sreg_request, rpconfig,
                                approved_data=approved_data.get('sreg'))
    teams_form = TeamsRequestForm(request, teams_request, rpconfig,
                                  approved_data=approved_data.get('teams'))
    context = RequestContext(request, {
        'account': request.user,
        'trust_root': orequest.trust_root,
        'rpconfig': rpconfig,
        'ax_form': ax_form,
        'sreg_form': sreg_form,
        'teams_form': teams_form,
        'token': token,
        'sane_trust_root': _request_has_sane_trust_root(orequest)
    })
    return render_to_response('server/decide.html', context)


def _request_has_sane_trust_root(openid_request):
    """Return True if the RP's trust root looks sane."""
    assert openid_request is not None, (
        'Could not find the OpenID request')
    trust_root = TrustRoot.parse(openid_request.trust_root)
    return trust_root.isSane()


def pre_authorize(request):
    logger.debug("HTTP_REFERER for this request: %s\n >>> \n" %
                 request.META.get('HTTP_REFERER', 'None'))
    form = PreAuthorizeForm(request.REQUEST)
    if form.is_valid():
        try:
            trust_root, callback, referer = _get_valid_pre_auth_data(request,
                                                                     form)
        except:
            # Unauthorized trust root or referrer.
            _clear_pre_auth_session_data(request)
            return HttpResponseBadRequest()

        if twofactor.is_authenticated(request):
            logger.debug("Approved for %s, %s\n >>> \n" %
                         (referer, request.user))
            client_id = request.session.session_key
            hours = getattr(settings, 'PRE_AUTHORIZATION_VALIDITY', 2)
            expires = datetime.utcnow() + timedelta(hours=hours)
            OpenIDAuthorization.objects.authorize(
                request.user, trust_root, expires, client_id)
            return HttpResponseRedirect(callback)
        else:
            request.session['pre_auth_referer'] = referer
            request.session['pre_auth_referer_for'] = trust_root
            next = "%s?%s" % (request.META.get('PATH_INFO'),
                              request.META.get('QUERY_STRING', ''))
            return HttpResponseRedirect('/+login?next=%s' %
                                        urllib.quote(next))
    else:
        _clear_pre_auth_session_data(request)
        return HttpResponseBadRequest()


def _get_valid_pre_auth_data(request, form):
    trust_root = form.cleaned_data['trust_root']
    callback = form.cleaned_data['callback']
    http_referer = _get_pre_auth_referer(request, trust_root)

    if http_referer is None:
        raise Exception("Pre-auth not approved")

    for line in getattr(settings, 'OPENID_PREAUTHORIZATION_ACL', []):
        referer, acl_trust_root = line
        if http_referer.startswith(referer) and trust_root == acl_trust_root:
            return (trust_root, callback, http_referer)
    raise Exception("Pre-auth not approved")


def _get_pre_auth_referer(request, trust_root):
    sess_referer = request.session.get('pre_auth_referer', None)
    sess_referer_for = request.session.get('pre_auth_referer_for', None)
    if sess_referer is not None and sess_referer_for is not None:
        _clear_pre_auth_session_data(request)
        if sess_referer_for == trust_root:
            logger.debug("getting referer %s from session" % sess_referer)
            logger.debug("http referer was %s" %
                         request.META.get('HTTP_REFERER', ''))
            return sess_referer
        else:
            return None
    else:
        return request.META.get('HTTP_REFERER', None)


def _clear_pre_auth_session_data(request):
    try:
        del request.session['pre_auth_referer']
        del request.session['pre_auth_referer_for']
    except:
        pass


def cancel(request, token):
    try:
        raw_orequest = request.session.get(token, None)
        orequest = signed.loads(raw_orequest, settings.SECRET_KEY)
    except:
        return HttpResponse("Invalid OpenID transaction")
    if twofactor.is_authenticated(request):
        return _process_decide(request, orequest, decision=False)
    else:
        oresponse = orequest.answer(False, settings.SSO_PROVIDER_URL)
        response = _django_response(request, oresponse)
        return response


def xrds(request):
    logger.debug("xrds()")
    context = {
        'endpoint_url': settings.SSO_PROVIDER_URL,
    }
    resp = render_to_response('server/openidapplication-xrds.xml', context)
    resp['Content-type'] = 'application/xrds+xml'
    return resp


@accept_xrds
def identity_page(request, identifier):
    account = get_object_or_404(Account, openid_identifier=identifier)
    if not account.is_active:
        raise Http404()
    context = {
        'provider_url': settings.SSO_PROVIDER_URL,
        'identity_url': account.openid_identity_url,
        'display_name': account.displayname,
    }
    resp = render_to_response('server/person.html', context)
    resp[YADIS_HEADER_NAME] = "%s/+xrds" % account.openid_identity_url
    return resp


def xrds_identity_page(request, identifier):
    account = get_object_or_404(Account, openid_identifier=identifier)
    if not account.is_active:
        raise Http404()
    context = {
        'provider_url': settings.SSO_PROVIDER_URL,
        'identity_url': account.openid_identity_url,
    }
    resp = render_to_response('server/person-xrds.xml', context)
    resp['Content-type'] = 'application/xrds+xml'
    return resp


def _openid_is_authorized(request, openid_request):
    logger.debug("openid_is_authorized(%s, %s)" %
                 (openid_request.identity, openid_request.trust_root))

    rpconfig = utils.get_rpconfig(openid_request.trust_root)

    if (not twofactor.is_authenticated(request) or
            not _is_identity_owner(request.user, openid_request)):
        logger.debug("openid_is_authorized() -> False (id_owner)")
        return False
    elif (twofactor.site_requires_twofactor_auth(request, None, rpconfig) and
            not twofactor.is_upgraded(request)):
        logger.debug("openid_is_authorized() -> False (rpconfig)")
        return False

    elif _should_reauthenticate(openid_request, request.user):
        logger.debug("openid_is_authorized() -> True (should_reauthenticate)")
        auth.logout(request)
        return False

    elif _is_auto_authorized_rp(rpconfig):
        logger.debug("openid_is_authorized() -> True (rpconfig)")
        return True

    else:
        ret = OpenIDAuthorization.objects.is_authorized(
            request.user, openid_request.trust_root,
            request.session.session_key)
        logger.debug("openid_is_authorized() -> %s" % ret)
        return ret


def _is_auto_authorized_rp(rp):
    return rp is not None and rp.auto_authorize


def _should_reauthenticate(openid_request, user):
    """Should the user re-enter their password?

    Return True if the user entered their password more than
    max_auth_age seconds ago. Return False otherwise.

    The max_auth_age parameter is defined in the OpenID Provider
    Authentication Policy Extension.
    http://openid.net/
        specs/openid-provider-authentication-policy-extension-1_0-07.html

    This parameter contains the maximum number of seconds before which
    an authenticated user must enter their password again. By default,
    there is no such maximum and if the user is logged in Launchpad, they
    can simply click-through to Sign In the relying party.

    But if the relaying party provides a value for that parameter, the
    user most have logged in not more than that number of seconds ago,
    Otherwise, they'll have to enter their password again.
    """
    pape_request = pape.Request.fromOpenIDRequest(openid_request)

    # If there is no parameter, the login is valid.
    if pape_request is None or pape_request.max_auth_age is None:
        logger.debug("No pape request")
        return False

    try:
        max_auth_age = int(pape_request.max_auth_age)
    except ValueError:
        logger.debug("pape:max_auth_age parameter should be an integer: %s" %
                     pape_request.max_auth_age)
        return False

    # we use now() here because last_login maps to django's auth model
    # which uses localtime.
    cutoff = datetime.now() - timedelta(seconds=max_auth_age)
    logger.debug("%s" % user.last_login)
    return user.last_login <= cutoff


def _django_response(request, oresponse, auth_success=False, orequest=None):
    """ Convert an OpenID response into a Django HttpResponse """
    webresponse = _get_openid_server().encodeResponse(oresponse)
    # This is a workaround for the fact the the openid library returns bare
    # HTML form markup instead of a complete HTML document. See
    # https://github.com/openid/python-openid/pull/31/files which has been
    # merged, but not released.
    if webresponse.body and oresponse.request.mode in BROWSER_REQUEST_MODES:
        response = HttpResponse(
            oidutil.autoSubmitHTML(webresponse.body), mimetype='text/html')
    else:
        response = HttpResponse(webresponse.body, mimetype='text/plain')
    response.status_code = webresponse.code
    for key, value in webresponse.headers.items():
        response[key] = value
        logger.debug("response[%s] = %s" % (key, value))
    logger.debug("response_body = " + webresponse.body)
    if auth_success and isinstance(oresponse.request, CheckIDRequest):
        logger.debug("oresponse.fields = " + str(oresponse.fields))
        approved_data = _get_approved_data(request, orequest)
        OpenIDRPSummary.objects.record(
            request.user,
            oresponse.request.trust_root,
            None,
            approved_data)
    return response


def _get_approved_data(request, orequest):
    """Given an HTTP request and an OpenID request, return a nested dict of
    values requested in the request and approved by the user.
    """
    if not orequest:
        return None

    approved_data = {}
    rpconfig = utils.get_rpconfig(orequest.trust_root)

    sreg_request = SRegRequest.fromOpenIDRequest(orequest)
    sreg_form = SRegRequestForm(request, sreg_request, rpconfig)
    if sreg_form.has_data:
        approved_data['sreg'] = {
            'requested': sreg_form.data.keys(),
            'approved': sreg_form.data_approved_for_request.keys()}

    ax_request = ax.FetchRequest.fromOpenIDRequest(orequest)
    if ax_request:
        ax_form = AXFetchRequestForm(request, ax_request, rpconfig)
        if ax_form.has_data:
            approved_data['ax'] = {
                'requested': ax_form.data.keys(),
                'approved': ax_form.data_approved_for_request.keys()}

    args = orequest.message.getArgs(LAUNCHPAD_TEAMS_NS)
    team_names = args.get('query_membership')
    if team_names:
        team_names = team_names.split(',')
        teams_form = TeamsRequestForm(
            request,
            TeamsRequest.fromOpenIDRequest(orequest),
            rpconfig,
        )
        approved_data['teams'] = {
            'requested': team_names,
            'approved': teams_form.teams_approved_by_user}

    return approved_data


def _is_identity_owner(user, openid_request):
    assert user is not None, (
        "user should be logged in by now.")
    ret = (openid_request.idSelect() or
           openid_request.identity == user.openid_identity_url)
    logger.debug("_is_identity_owner() -> %s" % ret)
    return ret


def _add_sreg(request, openid_request, openid_response):
    # Add sreg result data
    sreg_request = SRegRequest.fromOpenIDRequest(openid_request)
    rpconfig = utils.get_rpconfig(openid_request.trust_root)
    form = SRegRequestForm(request, sreg_request, rpconfig)
    if form.data_approved_for_request:
        sreg_response = SRegResponse.extractResponse(
            sreg_request, form.data_approved_for_request)
        openid_response.addExtension(sreg_response)


def _add_ax(request, openid_request, openid_response):
    ax_request = ax.FetchRequest.fromOpenIDRequest(openid_request)
    if ax_request:
        rpconfig = utils.get_rpconfig(openid_request.trust_root)
        form = AXFetchRequestForm(request, ax_request, rpconfig)
        if form.data_approved_for_request:
            ax_response = ax.FetchResponse(ax_request)
            for k, v in form.data_approved_for_request.iteritems():
                ax_response.addValue(AX_DATA_FIELDS.getNamespaceURI(k), v)
            openid_response.addExtension(ax_response)


def _process_decide(request, orequest, decision):
    oresponse = orequest.answer(
        decision, identity=request.user.openid_identity_url)
    if decision:
        # If they use PAPE, let them know of the last logged in time.
        pape_request = pape.Request.fromOpenIDRequest(orequest)
        if pape_request:
            last_login = request.user.last_login
            pape_response = pape.Response(
                auth_time=last_login.strftime('%Y-%m-%dT%H:%M:%SZ'))
            oresponse.addExtension(pape_response)

        OpenIDAuthorization.objects.authorize(
            request.user,
            orequest.trust_root,
            client_id=request.session.session_key)
        _add_sreg(request, orequest, oresponse)
        _add_ax(request, orequest, oresponse)
        # if there's no submitted POST data, this is an auto-authorized
        # (immediate) request
        immediate = not request.POST
        _check_team_membership(request, orequest, oresponse,
                               immediate=immediate)
    r = _django_response(request, oresponse, decision, orequest)
    if r.content:
        # Only user-visible content is generated from this view.  Wrap
        # it up and set the Content-Type.
        r.content = loader.render_to_string("server/post-assertion.html", {
            'form': r.content})
        r['Content-Type'] = 'text/html'
        # Also, as this is POSTing to another server, disabled CSRF
        # protection.
        r.csrf_exempt = True
    return r


def _get_openid_server():
    logger.debug("_get_server()")
    store = DjangoOpenIDStore()
    openid_server = Server(store, op_endpoint=settings.SSO_PROVIDER_URL)
    return openid_server


def _check_team_membership(request, orequest, oresponse, immediate=True):
    """Perform team membership checks.

    If any team membership checks have been requested as part of
    the OpenID request, annotate the response with the list of
    teams the user is actually a member of.
    """
    assert request.user is not None, (
        'Must be logged in to calculate team membership')
    if request.user.person is None:
        return
    args = orequest.message.getArgs(LAUNCHPAD_TEAMS_NS)
    team_names = args.get('query_membership')
    if not team_names:
        return
    team_names = team_names.split(',')
    if immediate:
        try:
            summary = OpenIDRPSummary.objects.get(
                account=request.user, trust_root=orequest.trust_root,
                openid_identifier=request.user.openid_identifier)
            approved_data = summary.get_approved_data()
        except OpenIDRPSummary.DoesNotExist:
            approved_data = {}
        if 'teams' in approved_data:
            teams = ','.join(approved_data['teams'].get('approved', []))
        else:
            rpconfig = utils.get_rpconfig(orequest.trust_root)
            teams = ','.join(get_team_memberships_for_user(
                team_names, request.user,
                rpconfig and rpconfig.can_query_any_team))
    else:
        form = TeamsRequestForm(
            request,
            TeamsRequest.fromOpenIDRequest(orequest),
            utils.get_rpconfig(orequest.trust_root),
        )
        teams = ','.join(form.teams_approved_by_user)
    oresponse.fields.namespaces.addAlias(LAUNCHPAD_TEAMS_NS, 'lp')
    oresponse.fields.setArg(LAUNCHPAD_TEAMS_NS, 'is_member', teams)


def untrusted(request, token):
    raw_orequest = request.session.get(token, None)
    orequest = signed.loads(raw_orequest, settings.SECRET_KEY)
    context = RequestContext(request, {
        'trust_root': orequest.trust_root,
    })
    return render_to_response('server/untrusted.html', context)


@switch_is_active('LOGIN_BY_TOKEN')
def login_by_token(request):
    headers = {
        'Authorization': request.META.get('HTTP_AUTHORIZATION', '')
    }
    orequest = OAuthRequest.from_request(
        request.method, request.build_absolute_uri(), headers=headers,
        query_string=request.META['QUERY_STRING'])
    if (orequest is None or
            not 'oauth_token' in orequest.parameters or
            not 'oauth_consumer_key' in orequest.parameters):
        return HttpResponseForbidden()

    oauthtoken = orequest.get_parameter('oauth_token')
    consumer_key = orequest.get_parameter('oauth_consumer_key')

    # get the entire token via the key from the db
    tokens = Token.objects.filter(
        token=oauthtoken, consumer__user__username=consumer_key)
    tokens = tokens.order_by('-created_at')
    if not tokens:
        return HttpResponseForbidden()
    token = tokens[0]

    user = auth.authenticate(token=token)
    if user is None:
        return HttpResponseForbidden()
    auth.login(request, user)

    next_step = request.GET.get('next')
    rpconfig = None
    if next_step:
        rpconfig = OpenIDRPConfig.objects.for_url(next_step)
    if next_step:
        if rpconfig or utils.is_safe_redirect_url(next_step):
            return HttpResponseRedirect(next_step)
        else:
            msg = _("Unknown redirect URL '{url}'")
            messages.warning(request, msg.format(url=next_step))

    return HttpResponseRedirect('/')
