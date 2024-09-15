from enum import Enum


class PinState(Enum):
    Uninitialized = -1
    OK = 0
    CountLow = 1
    FinalTry = 2
    Locked = 3
    ToBeChanged = 10


class TokenProperties(object):
    def __init__(self, properties: dict, set_flags: list[str]) -> None:
        self._properties = properties
        self._set_flags = set_flags

    @classmethod
    def read_from_slot(cls, library, slot):
        ti = library.getTokenInfo(slot)
        properties = {}
        for property, value in ti.to_dict().items():
            if isinstance(value, str):
                properties[property] = value.strip().strip("\x00")
            else:
                properties[property] = value
        set_flags = ti.flags2text()
        return cls(properties, set_flags)

    def gen_tags(self):
        for tag, val in self._properties.items():
            yield tag, val

    def gen_set_flags(self):
        for flag in self._set_flags:
            yield flag

    def is_initialized(self):
        if "CKF_TOKEN_INITIALIZED" in self._set_flags:
            return True
        else:
            return False

    def is_login_required(self):
        if "CKF_LOGIN_REQUIRED" in self._set_flags:
            return True
        else:
            return False

    def is_read_only(self):
        if "CKF_WRITE_PROTECTED" in self._set_flags:
            return True
        else:
            return False

    def has_RNG(self):
        if "CKF_RNG" in self._set_flags:
            return True
        else:
            return False

    def has_clock(self):
        if "CKF_CLOCK_ON_TOKEN" in self._set_flags:
            return True
        else:
            return False

    def has_proteced_authentication_path(self):
        if "CKF_PROTECTED_AUTHENTICATION_PATH" in self._set_flags:
            return True
        else:
            return False

    def has_dual_crypto_operations(self):
        if "CKF_DUAL_CRYPTO_OPERATIONS" in self._set_flags:
            return True
        else:
            return False

    def get_max_session_count(self):
        return self._properties["ulMaxSessionCount"]

    def get_max_rw_session_count(self):
        return self._properties["ulMaxRwSessionCount"]

    def get_session_count(self):
        return self._properties["ulSessionCount"]

    def get_rw_session_count(self):
        return self._properties["ulRwSessionCount"]

    def get_total_public_memory(self):
        return self._properties["ulTotalPublicMemory"]

    def get_free_public_memory(self):
        return self._properties["ulFreePublicMemory"]

    def get_total_private_memory(self):
        return self._properties["ulTotalPrivateMemory"]

    def get_free_private_memory(self):
        return self._properties["ulFreePrivateMemory"]

    def get_label(self):
        return self._properties["label"]

    def get_manufacturer_id(self):
        return self._properties["manufacturerID"]

    def get_model(self):
        return self._properties["model"]

    def get_serialNumber(self):
        return self._properties["serialNumber"]

    def get_hardware_version(self):
        return self._properties["hardwareVersion"]

    def get_firmware_version(self):
        return self._properties["firmwareVersion"]

    def get_max_pin_length(self):
        return self._properties["ulMaxPinLen"]

    def get_min_pin_length(self):
        return self._properties["ulMinPinLen"]

    def check_pin_length(self, pin: str):
        l = len(pin)
        ret = False
        if l >= self.get_min_pin_length() and l < self.get_max_pin_length():
            ret = True
        return ret

    def get_user_pin_state(self):
        ret = PinState.OK
        if "CKF_USER_PIN_INITIALIZED" not in self._set_flags:
            return PinState.Uninitialized
        if "CKF_USER_PIN_LOCKED" in self._set_flags:
            ret = PinState.Locked
        elif "CKF_USER_PIN_FINAL_TRY" in self._set_flags:
            ret = PinState.FinalTry
        elif "CKF_USER_PIN_COUNT_LOW" in self._set_flags:
            ret = PinState.CountLow
        elif "CKF_USER_PIN_TO_BE_CHANGED" in self._set_flags:
            ret = PinState.ToBeChanged
        return ret

    def get_so_pin_state(self):
        ret = PinState.OK
        if not self.is_initialized():
            return PinState.Uninitialized
        if "CKF_SO_PIN_LOCKED" in self._set_flags:
            ret = PinState.Locked
        elif "CKF_SO_PIN_FINAL_TRY" in self._set_flags:
            ret = PinState.FinalTry
        elif "CKF_SO_PIN_COUNT_LOW" in self._set_flags:
            ret = PinState.CountLow
        elif "CKF_SO_PIN_TO_BE_CHANGED" in self._set_flags:
            ret = PinState.ToBeChanged
        return ret
