from typing import Union

from pkcs11_cryptography_keys.keys import ec, rsa

PKCS11PrivateKeyTypes = Union[
    rsa.RSAPrivateKeyPKCS11, ec.EllipticCurvePrivateKeyPKCS11
]

PKCS11PublicKeyTypes = Union[
    rsa.RSAPublicKeyPKCS11, ec.EllipticCurvePublicKeyPKCS11
]
