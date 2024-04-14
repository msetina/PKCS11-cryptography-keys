import PyKCS11
from asn1crypto.keys import ECDomainParameters, NamedCurve
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from pkcs11_cryptography_keys.card_token.PKCS11_key_definition import (
    KeyObjectTypes,
)

key_type = {
    "generation_mechanism": PyKCS11.MechanismECGENERATEKEYPAIR,
    "module_name": "pkcs11_cryptography_keys.keys.ec",
}


def get_params(**kwargs) -> dict:
    params = {}
    if "EC_curve" in kwargs and "EC_private_key" in kwargs:
        raise Exception(
            "Only one parameter is allowed. EC_private_key for loading or EC_curve for generating"
        )
    params.update(kwargs)
    return params


def prep_key(template: list, tag: KeyObjectTypes, **kwargs) -> None:
    if "EC_curve" in kwargs or "EC_private_key" in kwargs:
        if tag in [KeyObjectTypes.private, KeyObjectTypes.public]:
            template.extend(
                [
                    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                ]
            )
            if tag == KeyObjectTypes.public and "EC_curve" in kwargs:
                curve = kwargs["EC_curve"]
                # Setup the domain parameters, unicode conversion needed for the curve string
                domain_params = ECDomainParameters(
                    name="named", value=NamedCurve(curve.name)
                )
                ec_params = domain_params.dump()
                template.extend(
                    [
                        (PyKCS11.CKA_EC_PARAMS, ec_params),
                    ]
                )


def load_key(template: list, tag: KeyObjectTypes, **kwargs) -> bool:
    ret = False
    if "EC_private_key" in kwargs and isinstance(
        kwargs["EC_private_key"], EllipticCurvePrivateKey
    ):
        private = kwargs["EC_private_key"]
        key_val = private.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )
        point = private.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        if tag in [KeyObjectTypes.private, KeyObjectTypes.public]:
            domain_params = ECDomainParameters(
                name="named", value=NamedCurve(private.curve.name)
            )
            ec_params = domain_params.dump()
            template.extend(
                [
                    (PyKCS11.CKA_EC_PARAMS, ec_params),
                ]
            )
            if tag == KeyObjectTypes.private:
                template.extend(
                    [
                        (PyKCS11.CKA_VALUE, key_val),
                    ]
                )
            if tag == KeyObjectTypes.public:
                template.extend(
                    [
                        (PyKCS11.CKA_EC_POINT, point),
                    ]
                )
            ret = True
    return ret


# PRIVATE
# CKA_EC_PARAMS Byte array DER-encoding of an ANSI X9.62
# Parameters value
# CKA_VALUE Big integer ANSI X9.62 private value d

# PUBLIC
# CKA_EC_PARAMS Byte array DER-encoding of an ANSI X9.62 Parameters
# value
# CKA_EC_POINT Byte array DER-encoding of ANSI X9.62 ECPoint value Q
