_pkcs11lib = "/usr/lib/softhsm/libsofthsm2.so"


class TestCertificates:

    def test_create_cert(self):

        import datetime

        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            RSAPublicNumbers,
        )
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        from pkcs11_cryptography_keys import (
            KeyTypes,
            PKCS11AdminSession,
            PKCS11KeySession,
            PKCS11KeyUsageAllNoDerive,
            PKCS11SlotSession,
            list_token_labels,
        )

        email = "signer@example.net"
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "USA"),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, "Signature"
                ),
                x509.NameAttribute(NameOID.SURNAME, "Signature"),
                x509.NameAttribute(NameOID.GIVEN_NAME, "User"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Signature User"),
            ]
        )
        one_day = datetime.timedelta(1, 0, 0)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(
            datetime.datetime.today() + (one_day * 30)
        )
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )

        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]),
            critical=False,
        )
        for label in list_token_labels(_pkcs11lib):
            create_session = PKCS11AdminSession(
                label, "1234", True, "sig_token", b"254", _pkcs11lib
            )
            with create_session as current_admin:
                keydef = PKCS11KeyUsageAllNoDerive()
                rsa_priv_key = current_admin.create_key_pair(
                    keydef, key_type=KeyTypes.RSA, RSA_length=2048
                )
                assert rsa_priv_key is not None

            key_session = PKCS11KeySession(
                label, "1234", "sig_token", _pkcs11lib
            )
            with key_session as PK:
                if PK:
                    pub_k = PK.public_key()
                    builder = builder.public_key(pub_k)
                    builder = builder.issuer_name(
                        x509.Name(
                            [
                                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                                x509.NameAttribute(
                                    NameOID.ORGANIZATION_NAME, "The Firm"
                                ),
                                x509.NameAttribute(
                                    NameOID.COMMON_NAME, "Main CA"
                                ),
                            ]
                        )
                    )
                    certificate = builder.sign(
                        PK,
                        algorithm=hashes.SHA256(),
                    )

            admin_session = PKCS11AdminSession(
                label, "1234", True, pksc11_lib=_pkcs11lib
            )
            with admin_session as token_admin:
                token_admin.write_certificate(certificate)

            slot_session = PKCS11SlotSession(
                label, "1234", pksc11_lib=_pkcs11lib
            )
            cnt = 0
            val = None
            with slot_session as slot:
                for nm, c in slot.list_cert_data():
                    if nm == "sig_token":
                        val = c["certificate"]["personal"]["commonName"][1]
                        cnt = cnt + 1
            assert cnt == 1
            assert val == "Signature User"

            with create_session as current_admin:
                a = current_admin.delete_certificate()
                assert a
                r = current_admin.delete_key_pair()
                assert r
