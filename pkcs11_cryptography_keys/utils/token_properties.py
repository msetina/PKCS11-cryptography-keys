from enum import Enum

from .token_enums import (
    TokenPINProperties,
    TokenPrivateMemory,
    TokenPropertiesEnum,
    TokenPublicMemory,
    TokenSession,
)
from .token_flag_enums import (
    TokenAuthentication,
    TokenFeatures,
    TokenInit,
    TokenOperability,
    TokenSOPIN,
    TokenUserPIN,
)


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
        if TokenInit.TOKEN_INITIALIZED.value in self._set_flags:
            return True
        else:
            return False

    def is_login_required(self):
        if TokenAuthentication.LOGIN_REQUIRED.value in self._set_flags:
            return True
        else:
            return False

    def is_read_only(self):
        if TokenOperability.WRITE_PROTECTED.value in self._set_flags:
            return True
        else:
            return False

    def has_RNG(self):
        if TokenFeatures.RNG.value in self._set_flags:
            return True
        else:
            return False

    def has_clock(self):
        if TokenFeatures.CLOCK_ON_TOKEN.value in self._set_flags:
            return True
        else:
            return False

    def has_proteced_authentication_path(self):
        if (
            TokenAuthentication.PROTECTED_AUTHENTICATION_PATH.value
            in self._set_flags
        ):
            return True
        else:
            return False

    def has_dual_crypto_operations(self):
        if TokenOperability.DUAL_CRYPTO_OPERATIONS.value in self._set_flags:
            return True
        else:
            return False

    def get_max_session_count(self):
        return self._properties[TokenSession.ulMaxSessionCount.value]

    def get_max_rw_session_count(self):
        return self._properties[TokenSession.ulMaxRwSessionCount.value]

    def get_session_count(self):
        return self._properties[TokenSession.ulSessionCount.value]

    def get_rw_session_count(self):
        return self._properties[TokenSession.ulRwSessionCount.value]

    def get_total_public_memory(self):
        return self._properties[TokenPublicMemory.ulTotalPublicMemory.value]

    def get_free_public_memory(self):
        return self._properties[TokenPublicMemory.ulFreePublicMemory.value]

    def get_total_private_memory(self):
        return self._properties[TokenPrivateMemory.ulTotalPrivateMemory.value]

    def get_free_private_memory(self):
        return self._properties[TokenPrivateMemory.ulFreePrivateMemory.value]

    def get_label(self):
        return self._properties[TokenPropertiesEnum.label.value]

    def get_manufacturer_id(self):
        return self._properties[TokenPropertiesEnum.manufacturerID.value]

    def get_model(self):
        return self._properties[TokenPropertiesEnum.model.value]

    def get_serialNumber(self):
        return self._properties[TokenPropertiesEnum.serialNumber.value]

    def get_hardware_version(self):
        return self._properties[TokenPropertiesEnum.hardwareVersion.value]

    def get_firmware_version(self):
        return self._properties[TokenPropertiesEnum.firmwareVersion.value]

    def get_max_pin_length(self):
        return self._properties[TokenPINProperties.ulMaxPinLen.value]

    def get_min_pin_length(self):
        return self._properties[TokenPINProperties.ulMinPinLen.value]

    def check_pin_length(self, pin: str):
        l = len(pin)
        ret = False
        if l >= self.get_min_pin_length() and l < self.get_max_pin_length():
            ret = True
        return ret

    def get_user_pin_state(self):
        ret = PinState.OK
        if TokenInit.USER_PIN_INITIALIZED.value not in self._set_flags:
            return PinState.Uninitialized
        if TokenUserPIN.USER_PIN_LOCKED.value in self._set_flags:
            ret = PinState.Locked
        elif TokenUserPIN.USER_PIN_FINAL_TRY.value in self._set_flags:
            ret = PinState.FinalTry
        elif TokenUserPIN.USER_PIN_COUNT_LOW.value in self._set_flags:
            ret = PinState.CountLow
        elif TokenUserPIN.USER_PIN_TO_BE_CHANGED.value in self._set_flags:
            ret = PinState.ToBeChanged
        return ret

    def get_so_pin_state(self):
        ret = PinState.OK
        if not self.is_initialized():
            return PinState.Uninitialized
        if TokenSOPIN.SO_PIN_LOCKED.value in self._set_flags:
            ret = PinState.Locked
        elif TokenSOPIN.SO_PIN_FINAL_TRY.value in self._set_flags:
            ret = PinState.FinalTry
        elif TokenSOPIN.SO_PIN_COUNT_LOW.value in self._set_flags:
            ret = PinState.CountLow
        elif TokenSOPIN.SO_PIN_TO_BE_CHANGED.value in self._set_flags:
            ret = PinState.ToBeChanged
        return ret
