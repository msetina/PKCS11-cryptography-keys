from importlib import import_module

from ..card_token.PKCS11_key_definition import KeyTypes
from ..card_token.PKCS11_keypair import get_key_definition

_key_mnemonic = {
    KeyTypes.EC: ["ECDSA", "EC_KEY", "ECDH1"],
    KeyTypes.RSA: ["RSA"],
}


def get_mechanism_definition(mechanism_name: str):
    ret = None
    for key_type, mnemo_lst in _key_mnemonic.items():
        for mnemo in mnemo_lst:
            if mnemo in mechanism_name:
                mod_nm = get_key_definition(key_type)
                if mod_nm is not None:
                    mod = import_module(mod_nm)
                    if mod is not None and hasattr(mod, "key_type"):
                        mm = mod.key_type
                        if "module_name" in mm:
                            k_mod_nm = mm["module_name"]
                            k_mod = import_module(k_mod_nm)
                            if hasattr(k_mod, "get_mechanism_definition"):
                                ret = k_mod.get_mechanism_definition(
                                    mechanism_name
                                )
                                if ret is not None:
                                    ret["key_type"] = key_type
                                else:
                                    ret = {"key_type": key_type}

    return ret
