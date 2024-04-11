from enum import Enum

import PyKCS11


class KeyTypes(Enum):
    EC = 1
    RSA = 2


class KeyObjectTypes(Enum):
    private = 1
    public = 2
    certificate = 3


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
        "crypt": PyKCS11.CKA_DECRYPT,
        "sign": PyKCS11.CKA_SIGN,
        "wrap": PyKCS11.CKA_UNWRAP,
        "derive": PyKCS11.CKA_DERIVE,
        "recover": PyKCS11.CKA_SIGN_RECOVER,
    },
    KeyObjectTypes.public: {
        "crypt": PyKCS11.CKA_ENCRYPT,
        "sign": PyKCS11.CKA_VERIFY,
        "wrap": PyKCS11.CKA_WRAP,
        "recover": PyKCS11.CKA_VERIFY_RECOVER,
    },
}


class PKCS11KeyUsage(object):
    def __init__(
        self,
        crypt: bool,
        sign: bool,
        wrap: bool,
        recover: bool,
        derive: bool | None = None,
    ) -> None:
        self._usage: dict[str, bool | None] = {}
        self._usage["crypt"] = crypt
        self._usage["sign"] = sign
        self._usage["wrap"] = wrap
        self._usage["derive"] = derive
        self._usage["recover"] = recover

    def get(self, key: str) -> bool | None:
        return self._usage.get(key, False)

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


class PKCS11KeyIdent(object):
    def __init__(self, key_id: bytes, label: str | None = None) -> None:
        self._key_id = key_id
        self._label = label

    def _prep_key_idents(self, template: list):
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
            usage_list.append(k)
        attrs = session.getAttributeValue(key_ref, atr_template)
        rezult = dict(zip(usage_list, attrs))
        return PKCS11KeyUsage(**rezult)
    else:
        return None
