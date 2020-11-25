import logging

from cp1_package import CP1Package
from ntp_crypto import NTPCrypto


class CP1ClientSession:

    def __init__(self, static_key_bits, init_pck: CP1Package,
                 log: logging.Logger = logging.getLogger('CP1ClientSession-logger')):
        """
        A data container which stores session data of one CP1 Session from client perspective.
        :param static_key_bits: The static key to decrypt a received message.
        :param init_pck: The first package send to the client which holds the nonce for the aes key.
        :param log:
        """
        self.log = log
        self.crypto_tools = NTPCrypto()
        self._decryption_key_bytes = self.crypto_tools.generate_aes_key_bytes(static_key_bits,
                                                                              init_pck.aes_nonce_bits())
        self.secret_received_in_bits = ''

    def add_next_pck(self, cp1_pck: CP1Package):
        """
        Handles the next NTP package, extracts the payload and adds it to the session storage.
        :param cp1_pck:
        :return:
        """
        self.secret_received_in_bits += cp1_pck.extract_payload()

    def is_complete(self):
        """
        Checks whether the 128 bit payload of this session is fully received or not.
        :return:
        """
        return len(self.secret_received_in_bits) >= 128

    def get_decryption_key_bytes(self):
        return self._decryption_key_bytes
