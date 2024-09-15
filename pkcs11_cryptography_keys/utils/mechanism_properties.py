class MechanismProperties(object):
    def __init__(
        self, mechanism, properties: dict, set_flags: list[str]
    ) -> None:
        self._mechanism = mechanism
        self._properties = properties
        self._set_flags = set_flags

    @classmethod
    def read_from_slot(cls, library, slot, mechanism_type):
        ti = library.getMechanismInfo(slot, mechanism_type)
        properties = {}
        for property, value in ti.to_dict().items():
            if isinstance(value, str):
                properties[property] = value.strip()
            else:
                properties[property] = value
        set_flags = ti.flags2text()
        return cls(mechanism_type, properties, set_flags)

    @classmethod
    def gen_mechanism_properties(cls, library, slot):
        for mi in library.getMechanismList(slot):
            yield cls.read_from_slot(library, slot, mi)

    def get_mechanism_type(self):
        return self._mechanism

    def gen_tags(self):
        for tag, val in self._properties.items():
            yield tag, val

    def gen_set_flags(self):
        for flag in self._set_flags:
            yield flag

    def is_token_present(self):
        if "CKF_TOKEN_PRESENT" in self._set_flags:
            return True
        else:
            return False

    def is_hardware_supported(self):
        if "CKF_HW" in self._set_flags:
            return True
        else:
            return False

    def can_encrypt(self):
        if "CKF_ENCRYPT" in self._set_flags:
            return True
        else:
            return False

    def can_decrypt(self):
        if "CKF_DECRYPT" in self._set_flags:
            return True
        else:
            return False

    def can_do_digest(self):
        if "CKF_DIGEST" in self._set_flags:
            return True
        else:
            return False

    def can_sign(self):
        if "CKF_SIGN" in self._set_flags:
            return True
        else:
            return False

    def can_sign_recover(self):
        if "CKF_SIGN_RECOVER" in self._set_flags:
            return True
        else:
            return False

    def can_verify(self):
        if "CKF_VERIFY" in self._set_flags:
            return True
        else:
            return False

    def can_verify_recover(self):
        if "CKF_VERIFY_RECOVER" in self._set_flags:
            return True
        else:
            return False

    def can_generate(self):
        if "CKF_GENERATE" in self._set_flags:
            return True
        else:
            return False

    def can_generate_keypair(self):
        if "CKF_GENERATE_KEY_PAIR" in self._set_flags:
            return True
        else:
            return False

    def can_wrap(self):
        if "CKF_WRAP" in self._set_flags:
            return True
        else:
            return False

    def can_unwrap(self):
        if "CKF_UNWRAP" in self._set_flags:
            return True
        else:
            return False

    def can_derive(self):
        if "CKF_DERIVE" in self._set_flags:
            return True
        else:
            return False

    def has_extensions(self):
        if "CKF_EXTENSION" in self._set_flags:
            return True
        else:
            return False

    def get_min_key_size(self):
        return self._properties["ulMinKeySize"]

    def get_max_key_size(self):
        return self._properties["ulMaxKeySize"]
