import PyKCS11
from asn1crypto.keys import ECDomainParameters, NamedCurve

from pkcs11_cryptography_keys.card_token.PKCS11_key_definition import (
    KeyObjectTypes,
)

key_type = {
    "generation_mechanism": PyKCS11.MechanismECGENERATEKEYPAIR,
    "module_name": "pkcs11_cryptography_keys.keys.ec",
}


def get_params(**kwargs):
    params = {}
    params.update(kwargs)
    return params


def prep_key(template: list, tag: KeyObjectTypes, **kwargs):
    if "EC_curve" in kwargs:
        curve = kwargs["EC_curve"]
        # Setup the domain parameters, unicode conversion needed for the curve string
        domain_params = ECDomainParameters(
            name="named", value=NamedCurve(curve.name)
        )
        ec_params = domain_params.dump()
        if tag in [KeyObjectTypes.private, KeyObjectTypes.public]:
            template.extend(
                [
                    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                ]
            )
            if tag == KeyObjectTypes.public:
                template.extend(
                    [
                        (PyKCS11.CKA_EC_PARAMS, ec_params),
                    ]
                )
