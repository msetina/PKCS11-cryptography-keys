import PyKCS11
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from .PKCS11_object import PKCS11Object


# Token representation
class PKCS11Token(PKCS11Object):
    def __init__(self, session, keyid: bytes, pk_ref):
        super().__init__(session, pk_ref)
        # id of key read from private key
        self._keyid = keyid

    # extension to cryptography API to allow simple access to certificates written on the cards

    # Certificate linked to private key on the card
    def certificate(self):
        if self._session is not None:
            pk11objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                    (PyKCS11.CKA_ID, self._keyid),
                ]
            )
            all_attributes = [
                PyKCS11.CKA_VALUE,
            ]
            certificate = None
            for pk11object in pk11objects:
                try:
                    attributes = self._session.getAttributeValue(
                        pk11object, all_attributes
                    )
                except PyKCS11.PyKCS11Error:
                    continue

                attr_dict = dict(list(zip(all_attributes, attributes)))
                cert = bytes(attr_dict[PyKCS11.CKA_VALUE])
                cert_o = x509.load_der_x509_certificate(
                    cert, backend=default_backend()
                )
                certificate = cert_o.public_bytes(
                    encoding=serialization.Encoding.PEM
                )
            return certificate

    # A list of Certificates from the card
    # Some cards have the CA chain written on the card
    def certificate_with_ca_chain(self):
        if self._session is not None:
            pk11objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                ]
            )
            ca_chain = []
            for pk11object in pk11objects:
                try:
                    attributes = self._session.getAttributeValue(
                        pk11object, [PyKCS11.CKA_VALUE]
                    )
                except PyKCS11.PyKCS11Error:
                    continue

                cert = bytes(attributes[0])
                cert_o = x509.load_der_x509_certificate(
                    cert, backend=default_backend()
                )
                ca_chain.append(
                    cert_o.public_bytes(encoding=serialization.Encoding.PEM)
                )
            return b"".join(ca_chain)

    # Get id and label for the Private key
    def get_id_and_label(self) -> tuple:
        if self._session is not None and self._private_key is not None:
            attributes = self._session.getAttributeValue(
                self._private_key, [PyKCS11.CKA_ID, PyKCS11.CKA_LABEL]
            )
            return bytes(attributes[0]), attributes[1].strip().strip("\x00")
        return None, None
