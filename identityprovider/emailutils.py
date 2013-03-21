import logging

from email.header import Header
from email.utils import formataddr
from urlparse import urljoin

from django.conf import settings
from django.core.urlresolvers import reverse
from django.core.mail import send_mail
from django.template import RequestContext
from django.template.loader import render_to_string
from django.utils.translation import ugettext_lazy as _
from gargoyle import gargoyle

from identityprovider.models import Account, AuthToken, EmailAddress
from identityprovider.models.const import EmailStatus, TokenType


def format_address(address, name=None):
    r"""Formats a name and address to be used as an email header.

        >>> format_address('foo@bar.com', 'Name')
        'Name <foo@bar.com>'
        >>> format_address('foo@bar.com', '')
        'foo@bar.com'
        >>> format_address(u'foo@bar.com')
        'foo@bar.com'

    It handles unicode and characters that need quoting as well.

        >>> format_address('foo.bar@canonical.com', u'F\xf4\xf4 Bar')
        '=?utf-8?b?RsO0w7QgQmFy?= <foo.bar@canonical.com>'

        >>> format_address('foo.bar@canonical.com', 'Foo [Baz] Bar')
        '"Foo \\[Baz\\] Bar" <foo.bar@canonical.com>'

    Really long names doesn't get folded, since we're not constructing
    an e-mail header here.

        >>> formatted_address = format_address(
        ...     'long.name@example.com',
        ...     'a '*100)
        >>> '\n' in formatted_address
        False
    """
    if name is None:
        if isinstance(address, unicode):
            return address.encode('utf8')
        else:
            return address
    if isinstance(name, str):
        name = name.decode('utf-8')
    name = str(Header(name, 'utf8'))
    # Using Header to encode the name has the side-effect that long
    # names are folded, so let's unfold it again.
    name = ''.join(name.splitlines())
    return formataddr((name, address)).encode('utf8')


def send_templated_email(subject, template, context, email, from_address=None):
    # Build a RequestContext so the custom context processors are used
    context = RequestContext(None, context)
    msg = render_to_string(template, context_instance=context)

    if from_address is None:
        from_address = format_address(settings.NOREPLY_FROM_ADDRESS)
    if not isinstance(email, (tuple, list)):
        email = [email]
    return send_mail(
        subject,
        msg,
        from_address,
        [format_address(e) for e in email]
    )


def send_branded_email(subject, template, context, email, from_address=None):
    if from_address is None:
        from_address = format_address(
            settings.NOREPLY_FROM_ADDRESS,
            settings.BRAND_DESCRIPTION
        )
    subject = u"%s: %s" % (settings.BRAND_DESCRIPTION, subject)
    return send_templated_email(subject, template, context, email,
                                from_address)


def _should_add_invalidation_link(email):
    account = Account.objects.get_by_email(email)
    if gargoyle.is_active('ALLOW_UNVERIFIED', account):
        emails = EmailAddress.objects.filter(email=email)
        result = (emails.count() == 0 or
                  emails.filter(status=EmailStatus.NEW).count() > 0)
        return result
    return False


def _context_for_email_request(account, email, token_type, redirection_url,
                               requester_email=None, **kwargs):
    token = AuthToken.objects.create(
        requester=account, requester_email=requester_email,
        email=email, token_type=token_type,
        redirection_url=redirection_url, **kwargs)

    name = getattr(account, 'displayname', kwargs.get('displayname'))
    context = {
        'requester': name,
        'requester_email': token.requester_email,
        'toaddress': token.email,
        'token': token.token,
        'token_url': token.absolute_url,
    }

    # only send invalidation links for those email addresses that either:
    # * are unknown to the system, or
    # * are in the system but are not validated
    if _should_add_invalidation_link(email):
        invalidate_email_token = AuthToken.objects.create(
            requester=account, requester_email=requester_email,
            email=email, token_type=TokenType.INVALIDATEEMAIL,
            redirection_url=redirection_url)
        context['invalidate_email_url'] = invalidate_email_token.absolute_url

    return context, token


def send_impersonation_email(email):
    """Send an email to user warning of attempted registration"""
    url = urljoin(settings.SSO_ROOT_URL, reverse('forgot_password'))
    context = {
        'forgotten_password_url': url,
    }
    send_branded_email(
        _("Warning"), 'email/impersonate-warning.txt', context, email)


def send_new_user_email(account, email, redirection_url=None, platform='all',
                        **kwargs):
    if platform not in ('all', 'desktop', 'mobile', 'web'):
        msg = ('Invalid platform requested during send_new_user_email: %s. '
               'Using default platform ("all").')
        logging.error(msg, platform)
        platform = 'all'

    if platform in ('all', 'desktop'):
        # 'all' is part of the v2.0 API workflow, where Accounts are created
        # as soon as the user registers, so there is no need to pass info
        # like displayname or password to be stored in the token.
        context, token = _context_for_email_request(
            account, email, TokenType.VALIDATEEMAIL, redirection_url)
    else:
        context, token = _context_for_email_request(
            account, email, TokenType.NEWPERSONLESSACCOUNT, redirection_url,
            **kwargs)

    if platform == 'all':
        template = 'email/welcome.txt'
    else:
        template = 'email/{0}-newuser.txt'.format(platform)

    send_branded_email(
        _('Finish your registration'), template, context, email)


def send_password_reset_email(account, email, redirection_url=None):
    context, token = _context_for_email_request(
        account, email, TokenType.PASSWORDRECOVERY, redirection_url,
        requester_email=email)
    send_branded_email(
        _('Forgotten Password'), 'email/forgottenpassword.txt', context, email)
    return token


def send_validation_email_request(account, email, redirection_url=None):
    if account.preferredemail is None:
        preferredemail_email = None
    else:
        preferredemail_email = account.preferredemail.email

    context, token = _context_for_email_request(
        account, email, TokenType.VALIDATEEMAIL, redirection_url,
        requester_email=preferredemail_email)
    send_branded_email(
        _("Validate your email address"), 'email/validate-email.txt',
        context, email)


def send_preferred_changed_notification(email, new_preferred):
    send_branded_email(
        _('E-mail change notification'), 'email/preferred-changed.txt',
        {'new_preferred': new_preferred}, email)


def send_invitation_after_password_reset(email):
    url = urljoin(settings.SSO_ROOT_URL, reverse('new_account'))
    send_branded_email(
        _("Password reset request"), 'email/invitation.txt',
        {'email': email, 'signup': url}, email,
    )


def send_action_required_warning(account, days_of_warning, action):
    assert action in ('suspend', 'delete')

    preferredemail = account.preferredemail
    assert preferredemail is not None
    email = preferredemail.email
    context, token = _context_for_email_request(
        account, email, TokenType.VALIDATEEMAIL, redirection_url=None)
    context.update(dict(
        emails_url=urljoin(settings.SSO_ROOT_URL, reverse('account-emails')),
        created=account.date_created, action=action,
        days_of_warning=days_of_warning,
    ))
    if action == 'suspend':
        subject = _('Account to be suspended - action required')
    else:
        subject = _('Account to be deleted - action required')
    send_branded_email(
        subject, 'email/account-action-required.txt', context, email,
    )


def send_action_applied_notice(email, display_name, days_of_warning, action):
    assert action in ('suspend', 'delete')

    if action == 'suspend':
        subject = _('Account suspended')
        template = 'email/account-suspend-applied.txt'
    else:
        subject = _('Account deleted')
        template = 'email/account-delete-applied.txt'
    context = dict(
        action=action, display_name=display_name,
        days_of_warning=days_of_warning,
    )
    send_branded_email(subject, template, context, email)
