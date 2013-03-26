# -*- coding: utf-8 -*-

from datetime import datetime

from django.core.exceptions import ValidationError
from django.db import IntegrityError
from mock import Mock, patch

from identityprovider.models import (
    Account,
    EmailAddress,
    InvalidatedEmailAddress,
)
from identityprovider.models.const import EmailStatus
from identityprovider.models.emailaddress import (
    PHONE_EMAIL_DOMAIN,
    EmailAddressQuerySet,
)
from identityprovider.tests.utils import SSOBaseTestCase


class EmailAddressQuerySetTestCase(SSOBaseTestCase):

    def setUp(self):
        super(EmailAddressQuerySetTestCase, self).setUp()
        self.qs = EmailAddressQuerySet(model=EmailAddress)

    def test_verified_list_only_verified_emails(self):
        emails = self.qs.verified()
        for email in emails:
            self.assertTrue(email.is_verified)


class EmailAddressManagerTestCase(SSOBaseTestCase):
    fixtures = ['test']

    def test_create_from_phone_id(self):
        account = Account.objects.get_by_email('test@canonical.com')
        new_email = EmailAddress.objects.create_from_phone_id('tel:+123',
                                                              account)
        self.assertEqual(new_email.status, EmailStatus.NEW)
        self.assertEqual(new_email.account, account)
        self.assertEqual(new_email.email, 'tel#+123@%s' % PHONE_EMAIL_DOMAIN)

    def test_get_from_phone_id(self):
        account = Account.objects.get_by_email('test@canonical.com')
        new_email = EmailAddress.objects.create_from_phone_id('tel:+123',
                                                              account)
        email = EmailAddress.objects.get_from_phone_id('tel:+123')
        self.assertEqual(email, new_email)

    def test_get_from_phone_id_not_exist(self):
        self.assertRaises(
            EmailAddress.DoesNotExist,
            EmailAddress.objects.get_from_phone_id, 'tel:+123')

    def test_verified(self):
        emails = EmailAddress.objects.verified()
        for email in emails:
            self.assertTrue(email.is_verified)


class EmailAddressTestCase(SSOBaseTestCase):
    fixtures = ['test']

    def test_emailaddress_with_account(self):
        account = Account.objects.get_by_email('test@canonical.com')
        email = EmailAddress.objects.get(email='test@canonical.com')
        self.assertEqual(account, email.account)

    def test_emailaddress_is_verifiable(self):
        email = EmailAddress.objects.get(email='test@canonical.com')
        self.assertTrue(email.is_verifiable)
        unverifiable_email = 'test@%s' % PHONE_EMAIL_DOMAIN
        email = EmailAddress(email=unverifiable_email)
        self.assertFalse(email.is_verifiable)

    def test_emailaddress_is_verified(self):
        email = EmailAddress.objects.get(email='test@canonical.com')
        assert email.status == EmailStatus.PREFERRED
        self.assertTrue(email.is_verified)
        email.status = EmailStatus.VALIDATED
        self.assertTrue(email.is_verified)
        email.status = EmailStatus.NEW
        self.assertFalse(email.is_verified)

    def test_emailaddress_invalidate(self):
        email = EmailAddress.objects.get(email='test@canonical.com')
        invalidated = email.invalidate()
        self.assertTrue(isinstance(invalidated, InvalidatedEmailAddress))
        self.assertEqual(email.email, invalidated.email)
        self.assertEqual(email.account, invalidated.account)
        self.assertEqual(email.date_created, invalidated.date_created)
        # is not available anymore
        emails = EmailAddress.objects.filter(email='test@canonical.com')
        self.assertFalse(emails.exists())

    def test_emailaddress_invalidate_with_person(self):
        email_address = self.factory.make_email_address()
        account = self.factory.make_account(email=email_address)
        person = self.factory.make_person(account=account)
        # set up email with lp_person instead of account
        email = EmailAddress.objects.get(email=email_address)
        email.account = None
        email.lp_person = person.id
        email.save()

        invalidated = email.invalidate()
        self.assertTrue(isinstance(invalidated, InvalidatedEmailAddress))
        self.assertEqual(email.email, invalidated.email)
        self.assertEqual(person.account, invalidated.account)
        self.assertEqual(email.date_created, invalidated.date_created)
        # is not available anymore
        emails = EmailAddress.objects.filter(email=email_address)
        self.assertFalse(emails.exists())

    @patch('identityprovider.models.emailaddress.logging')
    def test_emailaddress_invalidate_without_account(self, mock_logger):
        email_address = self.factory.make_email_address()
        self.factory.make_account(email=email_address)
        # set up email with lp_person instead of account
        email = EmailAddress.objects.get(email=email_address)
        email.account = None
        # invalid person id
        email.lp_person = 12345
        email.save()

        invalidated = email.invalidate()
        self.assertEqual(invalidated, None)
        mock_logger.warning.assert_called_once_with(
            "Could not create invalidated entry for %s, "
            "no associated account found" % email_address
        )
        # original is not available anymore
        emails = EmailAddress.objects.filter(email=email_address)
        self.assertFalse(emails.exists())


class InvalidatedEmailAddressTestCase(SSOBaseTestCase):

    def test_date_created_not_default(self):
        self.assertRaises(
            IntegrityError,
            InvalidatedEmailAddress.objects.create, email='foo@foo.com')

    def test_email_valid(self):
        for valid in ('a@a.com', 'aaaa.bbbb@foo.com', 'a@foo.net'):
            email = InvalidatedEmailAddress.objects.create(
                email=valid, date_created=datetime.utcnow())
            email.full_clean()  # no failure

    def test_email_invalid(self):
        for invalid in ('', '.', '@', '@foo', '@foo.x', 'a@foo.x', 'foo@bar',
                        'a@@a.com'):
            email = InvalidatedEmailAddress.objects.create(
                email=invalid, date_created=datetime.utcnow())
            self.assertRaises(
                ValidationError, email.full_clean)

    def test_unicode(self):
        email = u'zaraza♥foo@example.com'
        invalid = InvalidatedEmailAddress.objects.create(
            email=email, date_created=datetime.utcnow())
        self.assertEqual(email, unicode(invalid))

    def test_date_invalidated(self):
        some_date = datetime(2005, 05, 23)
        invalid = InvalidatedEmailAddress.objects.create(
            email='foo@example.com', date_created=datetime.utcnow(),
            date_invalidated=some_date)

        self.assertEqual(invalid.date_invalidated, some_date)

    def test_date_invalidated_default(self):
        mock_date = Mock()
        mock_date.return_value = datetime.utcnow()
        InvalidatedEmailAddress._meta.get_field_by_name(
            'date_invalidated')[0].default = mock_date
        invalid = InvalidatedEmailAddress.objects.create(
            email='foo@example.com', date_created=datetime.utcnow())

        self.assertEqual(invalid.date_invalidated, mock_date.return_value)

    def test_account_notified(self):
        invalid = InvalidatedEmailAddress.objects.create(
            email='foo@example.com', date_created=datetime.utcnow())
        self.assertFalse(invalid.account_notified)
