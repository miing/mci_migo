import logging

from datetime import datetime, timedelta

from django.conf import settings
from django.core.management.base import BaseCommand

from identityprovider import emailutils
from identityprovider.models import Account
from identityprovider.models.const import AccountStatus, EmailStatus


class Command(BaseCommand):

    account_action = 'suspend'
    account_status = AccountStatus.ACTIVE
    action = 'suspension'
    action_after_days = 'SUSPEND_UNVERIFIED_ACCOUNT_AFTER_DAYS'
    warn_before_days = 'WARN_SUSPEND_UNVERIFIED_ACCOUNT_BEFORE_DAYS'
    help = ('Notify owners of unverified accounts about upcoming suspension, '
            'and suspend unverified accounts already notified.')

    def _filter_by_date(self, queryset, threshold):
        # do not care about time of creation, just the day has to match
        result = queryset.filter(
            date_created__year=threshold.year,
            date_created__month=threshold.month,
            date_created__day=threshold.day)
        return result

    def _notify(self, accounts):
        for account in accounts:
            if account.preferredemail is None:
                logging.warning('Can not notify %r about %s since no '
                                'preferredemail is set.', account, self.action)
                continue

            days_of_warning = getattr(settings, self.warn_before_days)
            try:
                emailutils.send_action_required_warning(
                    account, days_of_warning, self.account_action)
            except:
                logging.exception('Error while notifying %s for %r:',
                                  self.action, account)
            else:
                logging.info('Notified %r about future account %s.',
                             account, self.action)

    def _do_action(self, accounts):
        for account in accounts:
            # copy the account before performing the action for future logging
            copied = Account.objects.get(id=account.id)
            days_of_warning = getattr(settings, self.warn_before_days)

            # need to cache the email before changing the account
            email = None
            if account.preferredemail is not None:
                email = account.preferredemail.email
            else:
                logging.warning('Can not notify %r about %s since no '
                                'preferredemail is set.', copied, self.action)
            try:
                getattr(account, self.account_action)()
            except:
                logging.exception('Error while applying %s to %r:',
                                  self.action, copied)
            else:
                logging.info('Account %s for %s succeeded.',
                             self.action, copied)
                if email is not None:
                    try:
                        emailutils.send_action_applied_notice(
                            email, copied.displayname,
                            days_of_warning, self.account_action)
                    except:
                        logging.exception(
                            'Error while notifying %s to %r:',
                            self.action, copied)

    def handle(self, *args, **options):
        # grab all active accounts with zero verified emails
        accounts = Account.objects.filter(
            status=self.account_status).exclude(
                emailaddress__status__in=[EmailStatus.PREFERRED,
                                          EmailStatus.VALIDATED])
        now = datetime.utcnow()
        do_action_days = getattr(settings, self.action_after_days)
        notify_days = do_action_days - getattr(settings, self.warn_before_days)
        assert notify_days > 0

        # filter those that were created 'notify_days' ago for notification
        notification_threshold = now - timedelta(days=notify_days)
        need_notification = self._filter_by_date(accounts,
                                                 notification_threshold)
        self._notify(need_notification)

        # filter those that were created 'do_action_days' ago for action
        action_threshold = now - timedelta(days=do_action_days)
        need_action = self._filter_by_date(accounts, action_threshold)
        self._do_action(need_action)
