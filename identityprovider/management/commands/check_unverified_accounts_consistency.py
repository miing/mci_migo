import logging

from datetime import datetime, timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from identityprovider.models import Account
from identityprovider.models.const import AccountStatus, EmailStatus


class Command(BaseCommand):

    def handle(self, *args, **options):
        # grab all suspended accounts with zero verified emails
        accounts = Account.objects.filter(
            status=AccountStatus.SUSPENDED).exclude(
                emailaddress__status__in=[EmailStatus.PREFERRED,
                                          EmailStatus.VALIDATED])
        now = datetime.utcnow().date()
        delete_days = settings.DELETE_UNVERIFIED_ACCOUNT_AFTER_DAYS
        # filter those that are older than 'delete_days' ago minus one second
        # to detect account that weren't properly deleted
        threshold = now - timedelta(days=delete_days)
        amount = accounts.filter(date_created__lt=threshold).count()
        if amount > 0:
            msg = ('found %s suspended and unverified accounts older than %s '
                   'days (those should be deleted).')
            logging.warning('check_unverified_accounts_consistency: ' + msg,
                            amount, delete_days)
            raise CommandError(msg % (amount, delete_days))
        else:
            logging.info('check_unverified_accounts_consistency: no accounts '
                         'found in inconsistent state.')
