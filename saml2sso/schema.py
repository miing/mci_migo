"""
Configglue schema.
You can ignore this file if you are not using configglue.
"""
from configglue.schema import (
    DictOption,
    ListOption,
    Schema,
    Section,
    StringOption,
    TupleOption,
)


class Saml2IdpSchema(Schema):
    """
    Configglue schema for saml2idp for upstream tag 0.16.
    """
    __version__ = '0.16'

    class saml2(Section):
        saml2idp_config = DictOption()
        saml2idp_remotes = DictOption(
            item=DictOption(spec={
                'acs_url': StringOption(),
                'processor': StringOption(),
                'links': ListOption(item=TupleOption(length=2, raw=True)),
            }),
        )
