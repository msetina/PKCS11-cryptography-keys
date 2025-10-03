from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from ..keys.AES_wrap import wrap_name_map


class ECDH_ephemeral(object):
    def __init__(self, kdf_hash: HashAlgorithm, key_size_bytes: int):
        self._kdf_hash = kdf_hash
        self._key_size_bytes = key_size_bytes

    @classmethod
    def create_for_wrap(cls, wrap_name: str, kdf_hash: HashAlgorithm):
        if wrap_name in wrap_name_map:
            key_props = wrap_name_map[wrap_name]
            key_length_bytes = key_props["key_length_bytes"]
            return cls(kdf_hash, key_length_bytes)

    def get_key_size_bytes(self):
        return self._key_size_bytes

    def derive_key_concat_kdf(
        self, peer_pub_key: EllipticCurvePublicKey, other_info_for_kdf: bytes
    ):
        # Generate a new ephemeral EC private key for key agreement
        ephemeral_private_key = generate_private_key(peer_pub_key.curve)
        # This is `Z` in SP 800-56A terms
        secret_key = ephemeral_private_key.exchange(ECDH(), peer_pub_key)
        ephemeral_public_key = ephemeral_private_key.public_key()

        # Perform key derivation.
        kdf = ConcatKDFHash(
            algorithm=self._kdf_hash,
            length=self._key_size_bytes,
            otherinfo=other_info_for_kdf,  # This is the `SharedInfo` or `OtherInfo`
            backend=default_backend(),
        )
        return kdf.derive(secret_key), ephemeral_public_key
