class LibraryProperties(object):
    def __init__(self, properties: dict, set_flags: list[str]) -> None:
        self._properties = properties
        self._set_flags = set_flags

    @classmethod
    def read_from_slot(cls, library):
        ti = library.getInfo()
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

    def get_library_description(self):
        return self._properties["libraryDescription"]

    def get_manufacturer_id(self):
        return self._properties["manufacturerID"]
