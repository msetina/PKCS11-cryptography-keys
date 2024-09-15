from urllib.parse import quote

from pkcs11_cryptography_keys.utils.exceptions import UriException
from pkcs11_cryptography_keys.utils.library_properties import LibraryProperties

from .definitions import CK_INFO_translation, ParameterMatch


class LibraryPropertiesURI(LibraryProperties):
    def __init__(self, properties: dict, set_flags: list[str]) -> None:
        super().__init__(properties, set_flags)

    def check_uri_parameter(self, tag: str, value, logger) -> ParameterMatch:
        if tag in CK_INFO_translation:
            ck_tag = CK_INFO_translation[tag]
            if ck_tag in self._properties and value != self._properties[ck_tag]:
                raise UriException(
                    "PKCS11 library does not corespond to URI parameters. {0} -> {1} != {2}".format(
                        tag, value, self._properties[ck_tag]
                    )
                )
            else:
                return ParameterMatch.Found
        else:
            return ParameterMatch.NotFound

    def gen_uri_tags(self):
        for tag in CK_INFO_translation:
            ck_tag = CK_INFO_translation[tag]
            val = quote(self._properties[ck_tag])
            yield tag, val
