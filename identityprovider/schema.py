from adminaudit.schema import AdminAuditSchema
from configglue.contrib import (
    DevServerSchema,
    DjangoJenkinsSchema,
    DjangoOpenIdAuthSchema,
    NexusSchema,
    PreflightSchema,
    RavenSchema,
)
from configglue.schema import (
    BoolOption,
    Section,
    DictOption,
    IntOption,
    ListOption,
    StringOption,
    TupleOption,
    merge,
)
from django_configglue.schema import schemas
from oops_dictconfig.configglue_options import OopsOption

from saml2sso.schema import Saml2IdpSchema


DjangoSchema = schemas.get('1.3')


class UpperCaseDictOption(DictOption):
    """ A DictOption with all upper-case keys. """
    def parse(self, section, parser=None, raw=False):
        parsed = super(UpperCaseDictOption, self).parse(
            section, parser, raw)
        result = {}
        for k, v in parsed.items():
            result[k.upper()] = v
        return result


class SSOSchema(DjangoSchema):
    # default
    db_connections = ListOption(item=UpperCaseDictOption(
        spec={'id': StringOption(),
              'host': StringOption(),
              'name': StringOption(),
              'user': StringOption(),
              'password': StringOption(),
              'port': StringOption()},
        strict=True))
    db_statement_timeout_millis = IntOption(
        default=0, help='0 disables timeout')
    extra_pythonpath = ListOption(item=StringOption())
    handler_timeout_millis = IntOption(default=10000)
    oops_dir = StringOption(help='Absolute path to the directory oops'
                                 ' reports will be stored in')
    pgconnect_timeout = IntOption(default=10)
    google_analytics_id = StringOption()
    support_phone = StringOption()

    #i18n
    class i18n(Section):
        supported_languages = ListOption(
            item=StringOption(),
            help="List of currently supported languages")
        language_names = DictOption(
            help="Mapping between language-code and name in that language")

    # api
    class api(Section):
        api_host = StringOption()
        api_url = StringOption()
        api_use_internal = BoolOption(default=False)
        oauth_data_store = StringOption()

    # branding
    class branding(Section):
        brand = StringOption()
        brand_descriptions = DictOption(item=StringOption(), spec={
            'ubuntu': StringOption(default='Ubuntu Single Sign On'),
            'launchpad': StringOption(default='Launchpad Login Service'),
            'ubuntuone': StringOption(default='Ubuntu One'),
        })

    # captcha
    class captcha(Section):
        captcha_use_proxy = BoolOption()
        captcha_proxies = DictOption()
        captcha_api_url = StringOption()
        captcha_api_url_secure = StringOption()
        captcha_image_url_pattern = StringOption(raw=True)
        captcha_verify_url = StringOption()
        captcha_public_key = StringOption()
        captcha_private_key = StringOption()
        disable_captcha_verification = BoolOption()
        email_whitelist_regexp_list = ListOption(
            item=StringOption(raw=True)
        )

    # debug
    class debug(Section):
        openid_debug = BoolOption()
        testing = BoolOption()

    # email
    class email(Section):
        noreply_from_address = StringOption()
        feedback_to_address = StringOption()

    # send warning emails/perform cleanup actions on accounts
    class warnings(Section):
        suspend_unverified_account_after_days = IntOption(
            default=90,
            help='Unverified accounts will be suspended after this period',
        )
        delete_unverified_account_after_days = IntOption(
            default=180,
            help=('Suspended and unverified accounts will be deleted after '
                  'this period'),
        )
        warn_suspend_unverified_account_before_days = IntOption(
            default=15,
            help=('Warning emails about upcoming unverified account '
                  'suspension will be sent with this buffer of notification'),
        )
        warn_delete_unverified_account_before_days = IntOption(
            default=15,
            help=('Warning emails about upcoming unverified and suspended '
                  'account deletion will be sent with this buffer of '
                  'notification'),
        )

    # openid
    class openid(Section):
        pre_authorization_validity = IntOption()
        openid_preauthorization_acl = ListOption(
            item=TupleOption(length=2))

    # readonly
    class readonly(Section):
        app_servers = ListOption(item=UpperCaseDictOption(
            spec={'server_id': StringOption(),
                  'host': StringOption(),
                  'port': StringOption(),
                  'scheme': StringOption(default='http'),
                  'virtual_host': StringOption(),
                  },
            strict=True))
        readonly_secret = StringOption(raw=True)
        dbfailover_attempts = IntOption()
        dbfailover_flag_dir = StringOption()
        dbrecover_interval = IntOption()
        dbrecover_attempts = IntOption()
        dbrecover_multiplier = IntOption()
        read_only_mode = BoolOption(default=False)

    class salesforce_portal_attributes(Section):
        organization_id = StringOption()
        portal_id = StringOption()

    # sso
    class sso(Section):
        sso_media_root = StringOption()
        sso_restrict_rp = BoolOption()
        sso_root_url = StringOption()
        sso_provider_url = StringOption()
        sso_account_update_url = StringOption(
            null=True,
            help="URL to POST when account data has changed")
        embedded_trust_root = StringOption()
        max_password_reset_tokens = IntOption(default=5)
        combo_url = StringOption(default="/combo/")
        combine = BoolOption(default=False)

    class twofactor(Section):
        hotp_drift = IntOption()
        hotp_backwards_drift = IntOption()
        twofactor_service_ident = StringOption(default='UbuntuSSO')
        twofactor_ttl = IntOption(
            default=8 * 3600,
            help="Number of seconds for the twofactor session to be valid")
        twofactor_freshness = IntOption(
            default=15 * 60,
            help="Number of seconds for the twofactor session to be "
                 "considered 'fresh'")
        twofactor_max_attempts = IntOption(
            default=18,
            help="Maximum allowed number of attempts to authenticate with a "
                 "two factor device before the account is locked")
        twofactor_paper_codes = IntOption(
            default=25,
            help="Number of backup codes given to the user in printable lists")
        twofactor_paper_codes_warn_renewal = IntOption(
            default=3,
            help="Number of unused codes left on printed code sheet before "
                 "warning the user")
        twofactor_paper_codes_allow_generation = IntOption(
            default=twofactor_paper_codes.default,
            help="Number of unused codes left on printed code sheet before "
                 "allowing the user to generate new codes")

    class profile(Section):
        profile_filename = StringOption(
            default="sso.profile",
            help="Filename of the file created by the profile middleware")
        profile_pattern = StringOption(
            default="identityprovider\..*",
            help="Regex pattern for limiting functions to be considered for "
                 "profiling")

    class static_urls(Section):
        support_form_url = StringOption()
        twofactor_faq_url = StringOption()
        yubikey_personalize_url = StringOption()

        apps_url = StringOption()
        photos_url = StringOption()
        music_url = StringOption()
        cloud_url = StringOption()

        terms_of_service_url = StringOption()
        privacy_url = StringOption()

    # settings for testing (acceptance, api)
    class testing(Section):
        # We use sso_test_account_* credentials also on pay and u1 projects.
        # The helpers from u1testutils.sso.data.User will create a user data
        # object based on this values and the email_address_pattern.
        sso_test_account_full_name = StringOption()
        sso_test_account_email = StringOption()
        sso_test_account_password = StringOption()
        # We shouldn't need test_account_* credentials.
        # TODO refactor and remove them. All the tests that rely on this config
        # should create a new user. -- elopio 2013-04-22
        test_account_email = StringOption()
        test_account_password = StringOption()
        email_address_pattern = StringOption(
            raw=True, default=r'isdtest+%s@canonical.com')
        imap_server = StringOption()
        imap_port = IntOption(default=993)
        imap_use_ssl = BoolOption(default=True)
        imap_username = StringOption()
        imap_password = StringOption()
        test_discover_root = StringOption()
        test_discover_top_level = StringOption()

    class statsd(Section):
        statsd_client = StringOption(
            default='django_statsd.clients.normal')
        statsd_host = StringOption(
            default='localhost')
        statsd_port = IntOption(default=8125)
        statsd_prefix = StringOption(null=True)

    class django_statsd(Section):
        statsd_patches = ListOption()

    class django_debug_toolbar(Section):
        debug_toolbar_media_root = StringOption(null=True)
        debug_toolbar_config = UpperCaseDictOption(
            spec={
                'EXTRA_SIGNALS': ListOption(),
                'SHOW_TEMPLATE_CONTEXT': BoolOption(default=True),
                'INTERCEPT_REDIRECTS': BoolOption(default=False),
                'ENABLE_STACKTRACES': BoolOption(default=True),
                'SQL_WARNING_THRESHOLD': IntOption(default=500),
                'SHOW_TOOLBAR_CALLBACK': StringOption(null=True),
                'TAG': StringOption(null=True),
            })
        debug_toolbar_panels = TupleOption(
            default=(
                'debug_toolbar.panels.version.VersionDebugPanel',
                'debug_toolbar.panels.timer.TimerDebugPanel',
                'debug_toolbar.panels.settings_vars.SettingsVarsDebugPanel',
                'debug_toolbar.panels.headers.HeaderDebugPanel',
                'debug_toolbar.panels.request_vars.RequestVarsDebugPanel',
                'debug_toolbar.panels.sql.SQLDebugPanel',
                'debug_toolbar.panels.template.TemplateDebugPanel',
                #'debug_toolbar.panels.cache.CacheDebugPanel',
                'debug_toolbar.panels.signals.SignalDebugPanel',
                'debug_toolbar.panels.logger.LoggingPanel',
            ))

    class south(Section):
        south_database_adapters = DictOption()

    class django_secure(Section):
        secure_ssl_redirect = BoolOption(default=True)
        secure_hsts_seconds = IntOption(default=300)
        secure_hsts_include_subdomains = BoolOption(default=True)
        secure_frame_deny = BoolOption(default=True)
        secure_content_type_nosniff = BoolOption(default=True)
        secure_browser_xss_filter = BoolOption(default=True)

    # override django section
    class django(DjangoSchema.django):
        caches = DictOption(item=UpperCaseDictOption())
        session_cookie_secure = BoolOption(default=True)
        session_cookie_httponly = BoolOption(default=True)

    class oopses(Section):
        oopses = OopsOption()


# merge all contrib schemas into the base schema
# order matters
schema = merge(
    SSOSchema,
    DevServerSchema,
    DjangoJenkinsSchema,
    DjangoOpenIdAuthSchema,
    NexusSchema,
    PreflightSchema,
    RavenSchema,
    Saml2IdpSchema,
    AdminAuditSchema,
)
