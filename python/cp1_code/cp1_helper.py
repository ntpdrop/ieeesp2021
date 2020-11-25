import hashlib

from bitstring import BitArray

_PROTOCOL_VERSION = '00'


def generate_address_hash(nonce: str, address: str, hash_length: int = 6) -> str:
    """
    Creates the MD5 hash by combining the nonce with the address.
    :return the first hash_len bit of the the generated MD5 hash.
    """
    combined_str = (nonce + address).encode('ASCII')
    hash_digest = hashlib.md5(combined_str).digest()
    bin_value = BitArray(bytes=hash_digest).bin
    bin_value = bin_value[0:hash_length]
    return bin_value


def generate_version_hash(nonce: str, version: str, hash_length: int = 2) -> str:
    """
    Creates the MD5 hash for the version number by combining it with the nonce.
    """
    return generate_address_hash(nonce, version, hash_length)