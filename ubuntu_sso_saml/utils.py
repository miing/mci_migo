from identityprovider.models import OpenIDRPConfig


def get_rpconfig_from_request(request):
    from saml2idp.registry import find_processor
    from saml2idp.exceptions import CannotHandleAssertion

    rpconfig = None

    try:
        proc = find_processor(request)
    except CannotHandleAssertion:
        return

    trust_root = proc._request_params['ACS_URL']
    rpconfig = OpenIDRPConfig.objects.for_url(trust_root)

    return rpconfig
