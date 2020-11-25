import logging

from Crypto.Cipher import AES
from bitstring import BitArray


def _repair_key(key: str) -> str:
    while len(key) < 32:
        key += ' '
    key = key[:32]
    return key


def _repair_data(data: str) -> str:
    while len(data) % 16 != 0:
        data += ' '
    return data


def decrypt_bits(encrypted_bits, decryption_key_bytes) -> bytes:
    """
    Decrypted the given block of bits (128) with the given key in the AES ECB mode.
    :param encrypted_bits: the bits (as a string of format '01011') to decrypt
    :param decryption_key_bytes: the key as bytes (of length 16, 24 or 32)
    :return: the decrypted bits as UTF8 string.
    """
    decryption_key_bytes = _repair_key(decryption_key_bytes)
    cipher = AES.new(decryption_key_bytes, AES.MODE_ECB)
    encrypted_bytes = BitArray(bin=encrypted_bits).bytes
    data = cipher.decrypt(encrypted_bytes)
    return data


def decrypt_bits_utf8_decoded(encrypted_bits, decryption_key_bytes) -> str:
    """
    Decrypted the given block of bits (128) with the given key in the AES ECB mode and returns it as an UTF-string
    :param encrypted_bits: the bits (as a string of format '01011') to decrypt
    :param decryption_key_bytes: the key as bytes (of length 16, 24 or 32)
    :return: the decrypted bits as UTF8 string.
    """
    return decrypt_bits(encrypted_bits, decryption_key_bytes).decode("utf-8")


def decrypt_bits_raw(encrypted_bits, decryption_key_bytes) -> str:
    """
    Decrypted the given block of bits (128) with the given key in the AES ECB mode.
    :param encrypted_bits: the bits (as a string of format '01011') to decrypt
    :param decryption_key_bytes: the key as bytes (of length 16, 24 or 32)
    :return: the decrypted bits (128) without any transformation.
    """
    decryption_key = _repair_key(decryption_key_bytes)
    cipher = AES.new(decryption_key_bytes, AES.MODE_ECB)
    encrypted_bytes = BitArray(bin=encrypted_bits).bytes
    data = cipher.decrypt(encrypted_bytes)
    return BitArray(bytes=data).bin


class NTPSecret:
    def __init__(self, payload_bytes: str, key_bytes: str, log: logging.Logger = logging.getLogger('NTPSecret-logger')):
        """
        A data container which gets string data, encrypts them with AES and makes them available, bit-wise.
        :param payload_bytes: the payload to encrypt as bytes (16 bytes)
        :param key_bytes: the key to encrypt (16, 24 or 32 byte)
        :param log: a logger for this instance.
        """
        self.log = log
        self._msg = payload_bytes
        self._key = key_bytes
        self._encoded_data = self.__encode(payload_bytes, key_bytes)
        self._encoded_bits = self.__encode_bits()
        self._position_counter = 0
        self.total_payload_length = len(payload_bytes)

    @staticmethod
    def __encode(payload_bytes, key_bytes):
        payload = _repair_data(payload_bytes)
        key_bytes = _repair_key(key_bytes)
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        ciphertext = cipher.encrypt(payload_bytes)
        return ciphertext

    def __encode_bits(self) -> str:
        bits = BitArray(bytes=self._encoded_data)
        return str(bits.bin)

    def __str__(self):
        return self._encoded_bits

    def next_bits(self, amount: int) -> str:
        """
        :param amount: the number of bytes to return
        :return: returns the next amount bits and counts up internaly.
        """
        result_arr = self._encoded_bits[self._position_counter:self._position_counter + amount]
        self._position_counter += amount
        return result_arr

    def has_next_bits(self):
        """
        :return: True in case the secret has still bits to offer, False otherwise.
        """
        if self._position_counter >= self.total_payload_length:
            return False
        return True

    def get_all_bits(self):
        """
        :return: a copy of all bits stored in this secret.
        """
        return str(self._encoded_bits)


class NTPCrypto:

    def __init__(self, log: logging.Logger = logging.getLogger("NTPCrypto-logger")):
        self.log = log

    def generate_aes_key_bytes(self, static_key, aes_nonce):
        """
        Generates a 256 bit aes key for the encryption and decryption of a CP1 message, by combining the nonce with
        the static key.
        :param aes_nonce:
        :param static_key:
        :return: the key in bytes
        """

        assert len(aes_nonce) == 64
        assert len(static_key) == 192

        combined_bits = static_key + aes_nonce
        self.log.debug("Generating aes key with bits: " + str(combined_bits))

        result_bytes = BitArray(bin=combined_bits).bytes
        self.log.debug("Generating aes key with bytes: " + str(result_bytes) + " and length: " + str(len(result_bytes)))

        return result_bytes
