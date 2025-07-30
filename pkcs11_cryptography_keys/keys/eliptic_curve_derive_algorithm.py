import abc

from cryptography.hazmat.primitives import hashes


class EllipticCurveKDFAlgorithm(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def hash_algorithm(
        self,
    ) -> hashes.HashAlgorithm | None:
        """
        The digest algorithm used with this KDF.
        """

    @property
    @abc.abstractmethod
    def other_info(
        self,
    ) -> bytes | None:
        """
        The other info/shared data provided for the KDF.
        """

    @property
    @abc.abstractmethod
    def key_length(
        self,
    ) -> int:
        """
        Length of the derived key.
        """


class ECDH_noKDF(EllipticCurveKDFAlgorithm):
    def __init__(self):
        pass

    @property
    def hash_algorithm(
        self,
    ) -> hashes.HashAlgorithm | None:
        return None

    @property
    def other_info(
        self,
    ) -> bytes | None:
        return None

    @property
    def key_length(
        self,
    ) -> int:
        return 0


class ECDH_KDF(EllipticCurveKDFAlgorithm):
    def __init__(
        self,
        hash_algorithm: hashes.HashAlgorithm,
        key_length: int,
        other_info: bytes | None = None,
    ):
        self._hash_algorithm = hash_algorithm
        self._key_length = key_length
        self._other_info = other_info

    @property
    def hash_algorithm(
        self,
    ) -> hashes.HashAlgorithm | None:
        return self._hash_algorithm

    @property
    def other_info(
        self,
    ) -> bytes | None:
        return self._other_info

    @property
    def key_length(
        self,
    ) -> int:
        return self._key_length
