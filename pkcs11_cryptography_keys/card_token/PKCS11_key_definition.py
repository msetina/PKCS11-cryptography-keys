from enum import Enum

import PyKCS11
from cryptography.x509 import KeyUsage


class KeyTypes(Enum):
    EC = 1
    RSA = 2


class KeyObjectTypes(Enum):
    private = 1
    public = 2
    certificate = 3


class OperationTypes(Enum):
    CRYPT = 1
    SIGN = 2
    WRAP = 3
    DERIVE = 4
    RECOVER = 5


x509Operations = {
    OperationTypes.SIGN: [
        "digital_signature",
        "content_commitment",
        "crl_sign",
    ],  # key_cert_sign
    OperationTypes.CRYPT: ["data_encipherment"],
    OperationTypes.DERIVE: [
        "key_agreement"
    ],  # "encipher_only","decipher_only",
    OperationTypes.WRAP: ["key_encipherment"],
    OperationTypes.RECOVER: ["digital_signature", "content_commitment"],
}


# key_cert_sign=False,
# crl_sign=False,


_key_classes = {
    PyKCS11.CKO_PRIVATE_KEY: KeyObjectTypes.private,
    PyKCS11.CKO_PUBLIC_KEY: KeyObjectTypes.public,
    PyKCS11.CKO_CERTIFICATE: KeyObjectTypes.certificate,
}

_key_head = {
    KeyObjectTypes.private: [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
    ],
    KeyObjectTypes.public: [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
        (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
    ],
    KeyObjectTypes.certificate: [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
        (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
    ],
}

_key_usage = {
    KeyObjectTypes.private: {
        OperationTypes.CRYPT: PyKCS11.CKA_DECRYPT,
        OperationTypes.SIGN: PyKCS11.CKA_SIGN,
        OperationTypes.WRAP: PyKCS11.CKA_UNWRAP,
        OperationTypes.DERIVE: PyKCS11.CKA_DERIVE,
        OperationTypes.RECOVER: PyKCS11.CKA_SIGN_RECOVER,
    },
    KeyObjectTypes.public: {
        OperationTypes.CRYPT: PyKCS11.CKA_ENCRYPT,
        OperationTypes.SIGN: PyKCS11.CKA_VERIFY,
        OperationTypes.WRAP: PyKCS11.CKA_WRAP,
        OperationTypes.RECOVER: PyKCS11.CKA_VERIFY_RECOVER,
    },
}


def to_biginteger_bytes(value: int) -> bytes:
    value = int(value)
    bit_length = value.bit_length() + 7
    return value.to_bytes(bit_length // 8, byteorder="big")


class PKCS11KeyUsage(object):
    def __init__(
        self,
        crypt: bool,
        sign: bool,
        wrap: bool,
        recover: bool,
        derive: bool | None = None,
    ) -> None:
        self._usage: dict[OperationTypes, bool | None] = {}
        self._usage[OperationTypes.CRYPT] = crypt
        self._usage[OperationTypes.SIGN] = sign
        self._usage[OperationTypes.WRAP] = wrap
        self._usage[OperationTypes.DERIVE] = derive
        self._usage[OperationTypes.RECOVER] = recover

    @classmethod
    def from_X509_KeyUsage(cls, key_usage: KeyUsage):
        crypt: bool = False
        sign: bool = False
        wrap: bool = False
        recover: bool = False
        derive: bool = False
        if key_usage.digital_signature:
            sign = True
        if key_usage.content_commitment:
            sign = True
        if key_usage.crl_sign:
            sign = True
        if key_usage.key_cert_sign:
            sign = True
        if key_usage.data_encipherment:
            crypt = True
        if key_usage.key_agreement:
            derive = True
        if key_usage.key_encipherment:
            wrap = True
        if key_usage.digital_signature:
            recover = True
        if key_usage.content_commitment:
            recover = True
        return cls(crypt, sign, wrap, recover, derive)

    def get(self, key: OperationTypes) -> bool | None:
        return self._usage.get(key, False)

    # Prepares a dict of parameters for X509.KeyUsage
    def get_X509_usage(self, is_ca: bool) -> dict:
        usages = {
            "digital_signature": False,
            "content_commitment": False,
            "key_encipherment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        }
        for k, v in self._usage.items():
            if k in x509Operations:
                uses = x509Operations[k]
                for u in uses:
                    if v:
                        usages[u] = True
                        if is_ca and u == "digital_signature":
                            usages["key_cert_sign"] = True

        return usages

    def __eq__(self, value: object) -> bool:
        ret = False
        if isinstance(value, PKCS11KeyUsage):
            ret = True
            for k, v in value._usage.items():
                if k in self._usage:
                    if v != self._usage[k]:
                        ret = False
                else:
                    ret = False
        return ret


class PKCS11KeyUsageAll(PKCS11KeyUsage):
    def __init__(self) -> None:
        super().__init__(True, True, True, True, True)


class PKCS11KeyUsageAllNoDerive(PKCS11KeyUsage):
    def __init__(self) -> None:
        super().__init__(True, True, True, True, False)


class PKCS11KeyUsageSignature(PKCS11KeyUsage):
    def __init__(self) -> None:
        super().__init__(False, True, False, True, False)


class PKCS11KeyUsageEncyrption(PKCS11KeyUsage):
    def __init__(self) -> None:
        super().__init__(True, False, True, False, False)


class PKCS11KeyIdent(object):
    def __init__(self, key_id: bytes, label: str | None = None) -> None:
        self._key_id = key_id
        self._label = label

    def _prep_key_idents(self, template: list) -> None:
        if self._label is not None:
            template.append((PyKCS11.CKA_LABEL, self._label))
        template.append((PyKCS11.CKA_ID, self._key_id))


def read_key_usage_from_key(session, key_ref) -> PKCS11KeyUsage | None:
    # check key class and produce tag
    class_attr = session.getAttributeValue(key_ref, [PyKCS11.CKA_CLASS])
    if (
        len(class_attr) == 1
        and class_attr[0] is not None
        and class_attr[0] in _key_classes
    ):
        tag = _key_classes[class_attr[0]]
        atr_template = []
        usage_list = []
        for k, v in _key_usage[tag].items():
            atr_template.append(v)
            usage_list.append(str(k).replace("OperationTypes.", "").lower())
        attrs = session.getAttributeValue(key_ref, atr_template)
        rezult = dict(zip(usage_list, attrs))
        return PKCS11KeyUsage(**rezult)
    else:
        return None
