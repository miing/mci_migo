from ssoclient.v2.http import ApiException


class InvalidData(ApiException):
    error_code = "INVALID_DATA"


class AlreadyRegistered(ApiException):
    error_code = "ALREADY_REGISTERED"


class CaptchaRequired(ApiException):
    error_code = "CAPTCHA_REQUIRED"


class CaptchaFailure(ApiException):
    error_code = "CAPTCHA_FAILURE"


class AccountSuspended(ApiException):
    error_code = "ACCOUNT_SUSPENDED"


class AccountDeactivated(ApiException):
    error_code = "ACCOUNT_DEACTIVATED"


class InvalidCredentials(ApiException):
    error_code = "INVALID_CREDENTIALS"


class ResourceNotFound(ApiException):
    error_code = "RESOURCE_NOT_FOUND"


class CanNotResetPassword(ApiException):
    error_code = "CAN_NOT_RESET_PASSWORD"

