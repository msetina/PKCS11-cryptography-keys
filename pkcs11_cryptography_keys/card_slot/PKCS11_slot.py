import PyKCS11
from cryptography import x509
from cryptography.hazmat.backends import default_backend


# Token representation
class PKCS11Slot:
    def __init__(self, session):
        # session for interacton with the card
        self._session = session

    # list certificate information in a form of dict.
    def list_cert_data(self):
        if self._session != None:
            pk11objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                ]
            )
            all = {}
            for pk11object in pk11objects:
                try:
                    attributes = self._session.getAttributeValue(
                        pk11object, [PyKCS11.CKA_VALUE, PyKCS11.CKA_LABEL]
                    )
                except PyKCS11.PyKCS11Error as e:
                    continue

                cert = bytes(attributes[0])
                cert = x509.load_der_x509_certificate(
                    cert, backend=default_backend()
                )
                data = {}
                data["issuer"] = {}
                for issuer_data in cert.issuer:
                    if issuer_data.oid._name == "Unknown OID":
                        data["issuer"][issuer_data.oid.dotted_string] = (
                            issuer_data.oid,
                            issuer_data.value,
                        )
                    else:
                        data["issuer"][issuer_data.oid._name] = (
                            issuer_data.oid,
                            issuer_data.value,
                        )
                data["personal"] = {}
                for pers_data in cert.subject:
                    if pers_data.oid._name == "Unknown OID":
                        data["personal"][pers_data.oid.dotted_string] = (
                            pers_data.oid,
                            pers_data.value,
                        )
                    else:
                        data["personal"][pers_data.oid._name] = (
                            pers_data.oid,
                            pers_data.value,
                        )
                data["extensions"] = {True: {}, False: {}}
                for exten in cert.extensions:
                    if exten.oid._name == "Unknown OID":
                        data["extensions"][exten.critical][
                            exten.oid.dotted_string
                        ] = (exten.oid, exten.value)
                    else:
                        data["extensions"][exten.critical][exten.oid._name] = (
                            exten.oid,
                            exten.value,
                        )
                yield ({attributes[1]: data})

    # list private keys
    def list_private_keys(self):
        if self._session != None:
            pk11objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                ]
            )
            for pk11object in pk11objects:
                try:
                    attributes = self._session.getAttributeValue(
                        pk11object, [PyKCS11.CKA_ID, PyKCS11.CKA_LABEL]
                    )
                except PyKCS11.PyKCS11Error as e:
                    continue

                yield ({attributes[1]: bytes(attributes[0])})

    # list public keys
    def list_public_keys(self):
        if self._session != None:
            pk11objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                ]
            )
            for pk11object in pk11objects:
                try:
                    attributes = self._session.getAttributeValue(
                        pk11object, [PyKCS11.CKA_ID, PyKCS11.CKA_LABEL]
                    )
                except PyKCS11.PyKCS11Error as e:
                    continue

                yield ({attributes[1]: bytes(attributes[0])})

    # list certificates
    def list_certificates(self):
        if self._session != None:
            pk11objects = self._session.findObjects(
                [
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                ]
            )
            for pk11object in pk11objects:
                try:
                    attributes = self._session.getAttributeValue(
                        pk11object, [PyKCS11.CKA_ID, PyKCS11.CKA_LABEL]
                    )
                except PyKCS11.PyKCS11Error as e:
                    continue

                yield ({attributes[1]: bytes(attributes[0])})
