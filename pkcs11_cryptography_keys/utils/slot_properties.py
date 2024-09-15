class SlotProperties(object):
    def __init__(self, properties: dict, set_flags: list[str]) -> None:
        self._properties = properties
        self._set_flags = set_flags

    @classmethod
    def read_from_slot(cls, library, slot):
        ti = library.getSlotInfo(slot)
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

    def is_token_present(self):
        if "CKF_TOKEN_PRESENT" in self._set_flags:
            return True
        else:
            return False

    def is_removable(self):
        if "CKF_REMOVABLE_DEVICE" in self._set_flags:
            return True
        else:
            return False

    def is_hardware_slot(self):
        if "CKF_HW_SLOT" in self._set_flags:
            return True
        else:
            return False

    def get_slot_description(self):
        return self._properties["slotDescription"]

    def get_manufacturer_id(self):
        return self._properties["manufacturerID"]

    def get_hardware_version(self):
        return self._properties["hardwareVersion"]

    def get_firmware_version(self):
        return self._properties["firmwareVersion"]
