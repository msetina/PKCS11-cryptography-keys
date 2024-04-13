from importlib import import_module

import PyKCS11

from pkcs11_cryptography_keys.card_token.PKCS11_key_definition import (
    KeyObjectTypes,
    KeyTypes,
    PKCS11KeyIdent,
    PKCS11KeyUsage,
    _key_head,
    _key_usage,
)

_key_types = {
    KeyTypes.EC: "pkcs11_cryptography_keys.card_token.EC_key_definition",
    KeyTypes.RSA: "pkcs11_cryptography_keys.card_token.RSA_key_definition",
}


class PKCS11KeypairDefinition(object):
    def __init__(
        self, module_name: str, generation_mechanism: PyKCS11.Mechanism
    ) -> None:
        self._module_name = module_name
        self._generation_mechanism = generation_mechanism
        self._templates: dict[KeyObjectTypes, list] = {}
        self._is_loaded = False

    def get_module_name(self) -> str:
        return self._module_name

    def get_generation_mechanism(self) -> PyKCS11.Mechanism:
        return self._generation_mechanism

    def set_template(self, key: KeyObjectTypes, template: list) -> None:
        self._templates[key] = template

    def get_template(self, key: KeyObjectTypes) -> list:
        return self._templates[key]

    def set_is_loaded(self, is_loaded: bool):
        self._is_loaded = is_loaded

    def is_loaded(self):
        return self._is_loaded


class PKCS11KeyPair(PKCS11KeyIdent):
    def __init__(
        self, key_usage: PKCS11KeyUsage, key_id: bytes, label: str | None = None
    ):
        PKCS11KeyIdent.__init__(self, key_id, label)
        self._key_usage = key_usage

    def _prep_key_usage(self, template: list, tag: KeyObjectTypes):
        for k, v in _key_usage[tag].items():
            val = self._key_usage.get(k)
            if val:
                template.append((v, PyKCS11.CK_TRUE))
            else:
                template.append((v, PyKCS11.CK_FALSE))

    def get_keypair_templates(self, **kwargs) -> PKCS11KeypairDefinition | None:
        ls = [KeyObjectTypes.private, KeyObjectTypes.public]
        if "key_type" in kwargs:
            key_type: KeyTypes = kwargs["key_type"]
            if key_type in _key_types:
                module_name = _key_types[key_type]
                module = import_module(module_name)
                if (
                    module is not None
                    and hasattr(module, "key_type")
                    and hasattr(module, "prep_key")
                ):
                    returns = PKCS11KeypairDefinition(**module.key_type)
                    for tag in ls:
                        template = []
                        if tag in _key_head:
                            template.extend(_key_head[tag])
                            params = module.get_params(**kwargs)
                            params.update({"template": template, "tag": tag})
                            module.prep_key(**params)
                            template.append(
                                (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE)
                            )
                            if tag == KeyObjectTypes.private:
                                template.append(
                                    (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE)
                                )
                            is_loaded = module.load_key(**params)
                            returns.set_is_loaded(is_loaded)
                            self._prep_key_usage(template, tag)
                            self._prep_key_idents(template)
                            returns.set_template(tag, template)
                    return returns
        return None
