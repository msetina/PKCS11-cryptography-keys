uri_key = "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;token=A%20token;id=%01;object=Test%20key?module-path=/usr/lib/softhsm/libsofthsm2.so;pin-value=1234"
uri = "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;token=A%20token?module-path=/usr/lib/softhsm/libsofthsm2.so;pin-value=1234"


class TestURI:
    def test_uri(self):

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11KeyUsage,
            PKCS11URIAdminSession,
        )

        a_session = PKCS11URIAdminSession(uri_key, True)
        with a_session as admin:
            key_usage = PKCS11KeyUsage(True, False, False, False, False)
            PK = admin.create_key_pair(
                key_usage, key_type=KeyTypes.RSA, RSA_length=2048
            )
            assert PK is not None
            id, label = PK.get_id_and_label()
            assert id == b"\x01"
            print(id, b"\x01", label)
            assert label == "Test key"
            admin.delete_key_pair()
