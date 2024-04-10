import PyKCS11
from asn1crypto.keys import ECDomainParameters, NamedCurve

_key_usage = {
    "private": {
        "crypt": PyKCS11.CKA_DECRYPT,
        "sign": PyKCS11.CKA_SIGN,
        "wrap": PyKCS11.CKA_UNWRAP,
        "derive": PyKCS11.CKA_DERIVE,
        "recover": PyKCS11.CKA_SIGN_RECOVER,
    },
    "public": {
        "crypt": PyKCS11.CKA_ENCRYPT,
        "sign": PyKCS11.CKA_VERIFY,
        "wrap": PyKCS11.CKA_WRAP,
        "recover": PyKCS11.CKA_VERIFY_RECOVER,
    },
}

_key_head = {
    "private": [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
    ],
    "public": [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
        (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
    ],
}


def _prep_key_idents(template: list, settings: dict, tag: str):
    if "label" in settings:
        label = settings["label"]
        template.append((PyKCS11.CKA_LABEL, label))
    if "id" in settings:
        id = settings["id"]
        template.append((PyKCS11.CKA_ID, id))


def _prep_key_usage(template: list, settings: dict, tag: str):
    if "key_usage" in settings:
        key_usage = settings["key_usage"]
        for k, v in _key_usage[tag].items():
            if k in key_usage:
                if key_usage[k]:
                    template.append((v, PyKCS11.CK_TRUE))
                else:
                    template.append((v, PyKCS11.CK_FALSE))


def _prep_RSA_key(template: list, settings: dict, tag: str):
    if "RSA_length" in settings:
        key_length = settings["RSA_length"]
        if tag in ["private", "public"]:
            template.extend(
                [
                    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
                ]
            )
            if tag == "public":
                template.extend(
                    [
                        (PyKCS11.CKA_MODULUS_BITS, key_length),
                    ]
                )


def _prep_EC_key(template: list, settings: dict, tag: str):
    if "EC_curve" in settings:
        curve = settings["EC_curve"]
        # Setup the domain parameters, unicode conversion needed for the curve string
        domain_params = ECDomainParameters(
            name="named", value=NamedCurve(curve.name)
        )
        ec_params = domain_params.dump()
        if tag in ["private", "public"]:
            template.extend(
                [
                    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                ]
            )
            if tag == "public":
                template.extend(
                    [
                        (PyKCS11.CKA_EC_PARAMS, ec_params),
                    ]
                )


_key_types = {"EC": _prep_EC_key, "RSA": _prep_RSA_key}


def get_keypair_templates(settings: dict) -> dict[str, list]:
    ret = {}
    ls = ["private", "public"]
    if "key_type" in settings:
        kt = settings["key_type"]
        if kt in _key_types:
            for tag in ls:
                template = []
                if tag in _key_head:
                    template.extend(_key_head[tag])
                    _key_types[kt](template, settings, tag)
                    template.append((PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE))
                    if tag == "private":
                        template.append(
                            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE)
                        )
                    _prep_key_usage(template, settings, tag)
                    _prep_key_idents(template, settings, tag)
                    ret[tag] = template
    return ret


_key_classes = {
    PyKCS11.CKO_PRIVATE_KEY: "private",
    PyKCS11.CKO_PUBLIC_KEY: "public",
}


def read_key_usage_from_key(session, key_ref) -> dict[str, bool | int] | None:
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
        return rezult
    else:
        return None
