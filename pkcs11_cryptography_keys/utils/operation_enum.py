from enum import Enum


class OperationEnum(str, Enum):
    DIGEST = "CKF_DIGEST"
    SIGN = "CKF_SIGN"
    VERIFY = "CKF_VERIFY"
    ENCRYPT = "CKF_ENCRYPT"
    DECRYPT = "CKF_DECRYPT"
    DERIVE = "CKF_DERIVE"
    SIGN_RECOVER = "CKF_SIGN_RECOVER"
    VERIFY_RECOVER = "CKF_VERIFY_RECOVER"
    WRAP = "CKF_WRAP"
    UNWRAP = "CKF_UNWRAP"


class KeyGenerateEnum(str, Enum):
    GENERATE_KEY_PAIR = "CKF_GENERATE_KEY_PAIR"
    GENERATE = "CKF_GENERATE"


class HardwareSupport(str, Enum):
    HardwareSupport = "CKF_HW"
