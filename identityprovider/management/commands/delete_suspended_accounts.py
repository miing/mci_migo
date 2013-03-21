from identityprovider.models.const import AccountStatus
from identityprovider.management.commands import suspend_unverified_accounts


class Command(suspend_unverified_accounts.Command):

    account_action = 'delete'
    account_status = AccountStatus.SUSPENDED
    action = 'deletion'
    action_after_days = 'DELETE_UNVERIFIED_ACCOUNT_AFTER_DAYS'
    warn_before_days = 'WARN_DELETE_UNVERIFIED_ACCOUNT_BEFORE_DAYS'
    help = ('Notify owners of suspended unverified accounts about upcoming '
            'deletion, and delete suspended accounts already notified.')
