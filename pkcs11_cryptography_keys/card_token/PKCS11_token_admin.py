import PyKCS11
from asn1crypto.keys import ECDomainParameters, NamedCurve
from asn1crypto.core import UTF8String


# Token representation
class PKCS11TokenAdmin:
    def __init__(self, session, keyid: bytes, label: str):
        # session for interacton with the card
        self._session = session
        # id of key read from private key
        self._keyid = keyid
        # label of the key
        self._label = label

    # Delete keypair from the card
    def delete_key_pair(self):
        ret = False
        if self._session is not None:
            public_objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                    (PyKCS11.CKA_ID, self._keyid),
                ]
            )
            for pub_o in public_objects:
                self._session.destroyObject(pub_o)
            private_objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_ID, self._keyid),
                ]
            )
            for priv_o in private_objects:
                self._session.destroyObject(priv_o)
                ret = True
        return ret

    # Delete certificate from the card
    def delete_certificate(self):
        ret = False
        if self._session is not None:
            cert_objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                    (PyKCS11.CKA_ID, self._keyid),
                ]
            )
            for co in cert_objects:
                self._session.destroyObject(co)
                ret = True
        return ret

    # Create RSA keypair on the card
    def create_rsa_key_pair(self, key_length: int):
        ret = None
        if self._session is not None:
            public_template = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
                (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
                (PyKCS11.CKA_VERIFY_RECOVER, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_LABEL, self._label),
                (PyKCS11.CKA_MODULUS_BITS, key_length),
                (PyKCS11.CKA_ID, self._keyid),
            ]

            private_template = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_LABEL, self._label),
                (PyKCS11.CKA_ID, self._keyid),
            ]

            (pub_key, priv_key) = self._session.generateKeyPair(
                public_template,
                private_template,
                mecha=PyKCS11.MechanismRSAGENERATEKEYPAIR,
            )
            ret = (pub_key, priv_key)
        return ret

    # Create EC keypair on the card
    def create_ec_key_pair(self, curve: str):
        ret = None
        if self._session is not None:
            # Setup the domain parameters, unicode conversion needed for the curve string
            domain_params = ECDomainParameters(
                name="named", value=NamedCurve(curve)
            )
            ec_params = domain_params.dump()

            ec_public_tmpl = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
                (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                (PyKCS11.CKA_EC_PARAMS, ec_params),
                (PyKCS11.CKA_LABEL, self._label),
                (PyKCS11.CKA_ID, self._keyid),
            ]

            ec_priv_tmpl = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
                (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_LABEL, self._label),
                (PyKCS11.CKA_ID, self._keyid),
            ]

            (pub_key, priv_key) = self._session.generateKeyPair(
                ec_public_tmpl,
                ec_priv_tmpl,
                mecha=PyKCS11.MechanismECGENERATEKEYPAIR,
            )
            ret = (pub_key, priv_key)
        return ret

    # Write certificate to the card
    def write_certificate(self, subject: str, cert: bytes):
        ret = False
        sub = UTF8String(subject)
        if self._session is not None:
            cert_template = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
                (PyKCS11.CKA_LABEL, self._label),
                (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509),
                (PyKCS11.CKA_MODIFIABLE, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_VALUE, cert),  # must be BER-encoded
                (
                    PyKCS11.CKA_SUBJECT,
                    bytes(sub),
                ),  # must be set and DER, see Table 24, X.509 Certificate Object Attributes
                (
                    PyKCS11.CKA_ID,
                    self._keyid,
                ),  # must be set,
            ]
            # create the certificate object
            self._session.createObject(cert_template)
            ret = True
        return ret
