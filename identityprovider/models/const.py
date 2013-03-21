# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
from django.utils.translation import ugettext_lazy as _


class BaseConst(object):
    @classmethod
    def _get_choices(cls):
        attrs = [(getattr(cls, attr), attr) for attr in dir(cls)
                 if not attr.startswith('_')]
        attrs.sort()
        return attrs


class AccountCreationRationale(BaseConst):
    """The rationale for the creation of a given account.

    Launchpad automatically creates user accounts under certain
    circumstances. The owners of these accounts may discover Launchpad
    at a later date and wonder why Launchpad knows about them, so we
    need to make it clear why a certain account was automatically created.
    """
    UNKNOWN = 1
    BUGIMPORT = 2
    SOURCEPACKAGEIMPORT = 3
    POFILEIMPORT = 4
    KEYRINGTRUSTANALYZER = 5
    FROMEMAILMESSAGE = 6
    SOURCEPACKAGEUPLOAD = 7
    OWNER_CREATED_LAUNCHPAD = 8
    OWNER_CREATED_SHIPIT = 9
    OWNER_CREATED_UBUNTU_WIKI = 10
    USER_CREATED = 11
    OWNER_CREATED_UBUNTU_SHOP = 12
    OWNER_CREATED_UNKNOWN_TRUSTROOT = 13
    OWNER_SUBMITTED_HARDWARE_TEST = 14
    BUGWATCH = 15


class AccountStatus(BaseConst):
    NOACCOUNT = 10
    ACTIVE = 20
    DEACTIVATED = 30
    SUSPENDED = 40

    _verbose = {
        # The account has not yet been activated.
        NOACCOUNT: _("Not activated"),
        # The account is active.
        ACTIVE: _("Active"),
        # The account has been deactivated by the account's owner.
        DEACTIVATED: _("Deactivated (by user)"),
        # The account has been suspended by an admin.
        SUSPENDED: _("Suspended (by admin)"),
    }

    @classmethod
    def _get_choices(cls):
        return sorted(cls._verbose.items())


class EmailStatus(BaseConst):
    NEW = 1
    VALIDATED = 2
    # 2013-01-18, nessita: as per SQL query in the SSO production DB:
    # SELECT COUNT(*) FROM emailaddress WHERE status = 3;
    # result 0 rows
    # we're never using the status to OLD, so do not use!!!
    __OLD = 3
    PREFERRED = 4


class TokenType(BaseConst):
    """Login token type.

    Tokens are emailed to users in workflows that require email address
    validation, such as forgotten password recovery or account merging.
    We need to identify the type of request so we know what workflow
    is being processed.
    """
    PASSWORDRECOVERY = 1
    ACCOUNTMERGE = 2
    NEWACCOUNT = 3  # Apparently unused since a while (nessita, 2013-01-09)
    VALIDATEEMAIL = 4
    VALIDATETEAMEMAIL = 5
    VALIDATEGPG = 6
    VALIDATESIGNONLYGPG = 7
    PROFILECLAIM = 8
    NEWPROFILE = 9
    TEAMCLAIM = 10
    BUGTRACKER = 11
    NEWPERSONLESSACCOUNT = 12
    INVALIDATEEMAIL = 13
