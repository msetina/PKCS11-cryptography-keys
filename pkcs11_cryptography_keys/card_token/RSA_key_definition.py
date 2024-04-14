import PyKCS11
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from pkcs11_cryptography_keys.card_token.PKCS11_key_definition import (
    KeyObjectTypes,
    to_biginteger_bytes,
)

key_type = {
    "generation_mechanism": PyKCS11.MechanismRSAGENERATEKEYPAIR,
    "module_name": "pkcs11_cryptography_keys.keys.rsa",
}


def get_params(**kwargs) -> dict:
    params = {}
    if "RSA_length" in kwargs and "RSA_private_key" in kwargs:
        raise Exception(
            "Only one parameter is allowed. RSA_private_key for loading or RSA_length for generating"
        )
    params.update(kwargs)
    return params


def prep_key(template: list, tag: KeyObjectTypes, **kwargs) -> None:
    if "RSA_length" in kwargs or "RSA_private_key" in kwargs:
        if tag in [KeyObjectTypes.private, KeyObjectTypes.public]:
            template.extend(
                [
                    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
                ]
            )
            if tag == KeyObjectTypes.public and "RSA_length" in kwargs:
                key_length = kwargs["RSA_length"]
                template.extend(
                    [
                        (PyKCS11.CKA_MODULUS_BITS, key_length),
                    ]
                )


def load_key(template: list, tag: KeyObjectTypes, **kwargs) -> bool:
    ret = False
    if "RSA_private_key" in kwargs and isinstance(
        kwargs["RSA_private_key"], RSAPrivateKey
    ):
        private = kwargs["RSA_private_key"]
        pn = private.private_numbers()
        pubn = private.public_key().public_numbers()
        if tag in [KeyObjectTypes.private, KeyObjectTypes.public]:
            template.extend(
                [
                    (PyKCS11.CKA_MODULUS, to_biginteger_bytes(pubn.n)),
                    (PyKCS11.CKA_PUBLIC_EXPONENT, to_biginteger_bytes(pubn.e)),
                ]
            )
            if tag == KeyObjectTypes.private:
                template.extend(
                    [
                        (
                            PyKCS11.CKA_PRIVATE_EXPONENT,
                            to_biginteger_bytes(pn.d),
                        ),
                        (PyKCS11.CKA_PRIME_1, to_biginteger_bytes(pn.p)),
                        (PyKCS11.CKA_PRIME_2, to_biginteger_bytes(pn.q)),
                        (PyKCS11.CKA_EXPONENT_1, to_biginteger_bytes(pn.dmp1)),
                        (PyKCS11.CKA_EXPONENT_2, to_biginteger_bytes(pn.dmq1)),
                        (PyKCS11.CKA_COEFFICIENT, to_biginteger_bytes(pn.iqmp)),
                    ]
                )
            ret = True
    return ret

    # CKA_MODULUS Big integer Modulus n
    # CKA_PUBLIC_EXPONENT Big integer Public exponent e
    # CKA_PRIVATE_EXPONENT Big integer Private exponent d
    # CKA_PRIME_1 Big integer Prime p
    # CKA_PRIME_2 Big integer Prime q
    # CKA_EXPONENT_1 Big integer Private exponent d modulo p-1
    # CKA_EXPONENT_2 Big integer Private exponent d modulo q-1
    # CKA_COEFFICIENT Big integer CRT coefficient q-1 mod p
