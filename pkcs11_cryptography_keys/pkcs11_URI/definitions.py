from PyKCS11 import (
    CKO_CERTIFICATE,
    CKO_DATA,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
)

PKCS11_type_translation: dict[str, int] = {
    "cert": CKO_CERTIFICATE,
    "data": CKO_DATA,
    "private": CKO_PRIVATE_KEY,
    "public": CKO_PUBLIC_KEY,
    "secret-key": CKO_SECRET_KEY,
}

CK_TOKEN_INFO_translation = {
    "token": "label",
    "manufacturer": "manufacturerID",
    "model": "model",
    "serial": "serialNumber",
}
CK_INFO_translation = {
    "library-description": "libraryDescription",
    "library-version": "libraryVersion",
    "library-manufacturer": "manufacturerID",
}
CK_SLOT_INFO_translation = {
    "slot-manufacturer": "manufacturerID",
    "slot-description": "slotDescription",
}
CK_SESSION_INFO_translation = {"slot-id": "slotID"}
