from django.core.exceptions import ValidationError
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import SSOBaseUnittestTestCase
from identityprovider.validators import (
    Errors,
    validate_password_policy,
)


class PasswordPolicyValidatorTestCase(SSOBaseUnittestTestCase):

    def test_password_too_short(self):
        self.assertRaises(
            ValidationError, validate_password_policy, 'abcd3Fg')

    def test_password_missing_uppercase(self):
        self.assertEqual(validate_password_policy('abcd3fgh'), None)

    def test_password_missing_number(self):
        self.assertEqual(validate_password_policy('abcdEfgh'), None)

    def test_password_all_lowercase(self):
        self.assertEqual(validate_password_policy('abcdefgh'), None)

    def test_password_invalid_chars(self):
        self.assertRaises(
            ValidationError, validate_password_policy, u'abcd\xe1Fgh')

    def test_valid_password(self):
        self.assertEqual(validate_password_policy('abcD3fgh'), None)

    def test_default_password_is_validated(self):
        self.assertEqual(validate_password_policy(DEFAULT_USER_PASSWORD), None)


class ErrorsTestCase(SSOBaseUnittestTestCase):

    def test_collect_no_key(self):
        errors = Errors()
        with errors.collect():
            raise ValidationError('Some Error')
        self.assertEqual(errors['__all__'], ['Some Error'])

    def test_collect_no_key_merges_dict(self):
        errors = Errors()
        with errors.collect():
            raise ValidationError({'k': 'v', 'x': 'y'})
        self.assertEqual(errors['k'], ['v'])
        self.assertEqual(errors['x'], ['y'])

    def test_collect_with_key(self):
        errors = Errors()
        with errors.collect('key'):
            raise ValidationError('Some Error')
        self.assertEqual(errors['key'], ['Some Error'])

    def test_collect_with_key_flattens_dict(self):
        errors = Errors()
        with errors.collect('key'):
            raise ValidationError({'k': 'v', 'x': 'y'})
        self.assertEqual(sorted(errors['key'][0]), ['v', 'y'])
