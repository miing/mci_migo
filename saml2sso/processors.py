# Copyright 2012-2013 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
from django.conf import settings
from gargoyle import gargoyle
from identityprovider.models import OpenIDRPConfig
from saml2idp import exceptions, google_apps, salesforce


__all__ = [
    'GoogleAppsProcessor',
    'SalesForceProcessor',
    'SalesForceAttributeProcessor',
]


class CanonicalOverrides(object):

    def _get_canonical_email(self, account):
        preferred = None
        # user has @canonical email address?
        emails = account.emailaddress_set.filter(
            email__endswith='@canonical.com')
        if emails:
            for email in emails:
                # prefer emails formatted like first.last@canonical.com
                if '.' in email.email.split('@')[0]:
                    preferred = email.email
                    break
            else:
                preferred = emails[0].email
        return preferred

    def _determine_subject(self):
        account = self._django_request.user
        preferred = account.preferredemail

        # check if RP prefers @canonical emails
        trust_root = self._request_params.get('ACS_URL')
        if trust_root is not None:
            rpconfig = OpenIDRPConfig.objects.for_url(trust_root)
            if rpconfig is not None and rpconfig.prefer_canonical_email:
                canonical_email = self._get_canonical_email(account)
                if canonical_email is not None:
                    preferred = canonical_email

        self._subject = preferred

    def _validate_user(self):
        user = self._django_request.user
        if gargoyle.is_active('SAML2', user):
            return
        raise exceptions.UserNotAuthorized(
            'User account not enabled for SAML authentication.')


class GoogleAppsProcessor(CanonicalOverrides, google_apps.Processor):
    """
    Google Apps SAML 2.0 Processor, specific to Canonical Identity Provider.
    """


class SalesForceProcessor(CanonicalOverrides, salesforce.Processor):
    """
    SalesForce SAML 2.0 Processor, specific to Canonical Identity Provider.
    """


class SalesForceAttributeProcessor(CanonicalOverrides, salesforce.Processor):
    """
    SalesForce SAML 2.0 Processor, specific to Canonical Identity Provider.
    Adds attributes for the customer portal.
    """

    def _get_canonical_email(self, account):
        """
        For the SalesForce portal, use email+portal@canonical.com.
        """
        email = super(SalesForceAttributeProcessor,
                      self)._get_canonical_email(account)
        if email is not None:
            address, domain = email.split('@')
            email = '%s+portal@%s' % (address, domain)
            return email

    def _format_assertion(self):
        self._assertion_params['ATTRIBUTES'] = {
            'organization_id': settings.ORGANIZATION_ID,
            'portal_id': settings.PORTAL_ID,
        }
        super(SalesForceAttributeProcessor, self)._format_assertion()
