from enum import Enum


class TokenPropertiesEnum(str, Enum):
    label = "label"
    manufacturerID = "manufacturerID"
    model = "model"
    serialNumber = "serialNumber"
    hardwareVersion = "hardwareVersion"
    firmwareVersion = "firmwareVersion"


class TokenSession(str, Enum):
    ulMaxSessionCount = "ulMaxSessionCount"
    ulSessionCount = "ulSessionCount"
    ulMaxRwSessionCount = "ulMaxRwSessionCount"
    ulRwSessionCount = "ulRwSessionCount"


class TokenPINProperties(str, Enum):
    ulMaxPinLen = "ulMaxPinLen"
    ulMinPinLen = "ulMinPinLen"


class TokenPublicMemory(str, Enum):
    ulTotalPublicMemory = "ulTotalPublicMemory"
    ulFreePublicMemory = "ulFreePublicMemory"


class TokenPrivateMemory(str, Enum):
    ulTotalPrivateMemory = "ulTotalPrivateMemory"
    ulFreePrivateMemory = "ulFreePrivateMemory"
