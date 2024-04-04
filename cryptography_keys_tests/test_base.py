_pkcs11lib = "/usr/lib/softhsm/libsofthsm2.so"


class TestBasic:

    def test_labels(self):
        from pkcs11_cryptography_keys import list_token_labels

        cnt = 0
        for label in list_token_labels(_pkcs11lib):
            print(label)
            cnt = cnt + 1
        assert cnt == 1
