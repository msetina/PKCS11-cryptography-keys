import PyKCS11

from pkcs11_cryptography_keys.card_token.PKCS11_key_definition import (
    KeyObjectTypes,
)

key_type = {
    "generation_mechanism": PyKCS11.MechanismRSAGENERATEKEYPAIR,
    "module_name": "pkcs11_cryptography_keys.keys.rsa",
}


def get_params(**kwargs):
    params = {}
    params.update(kwargs)
    return params


def prep_key(template: list, tag: KeyObjectTypes, **kwargs):
    if "RSA_length" in kwargs:
        key_length = kwargs["RSA_length"]
        if tag in [KeyObjectTypes.private, KeyObjectTypes.public]:
            template.extend(
                [
                    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
                ]
            )
            if tag == KeyObjectTypes.public:
                template.extend(
                    [
                        (PyKCS11.CKA_MODULUS_BITS, key_length),
                    ]
                )
