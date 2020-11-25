import logging

from bitstring import BitArray
from scapy.layers.ntp import NTP

from cp1_helper import _PROTOCOL_VERSION, generate_address_hash, generate_version_hash
from cp1_package import CP1Package
from ntp_crypto import NTPSecret, NTPCrypto
from ntp_raw import NTPField
from ntp_utils import init_ntp_pck


class CP1Session:
    """
    A data container which stores session data of one CP1 Session data exchange.
    """

    def __init__(self):
        self.aes_nonce = None
        self.init_pck_field = NTPField.TRANSMIT_TIMESTAMP
        self.secret_to_send: NTPSecret = None
        self.secret_received = ''
        self.log = logging.getLogger('default-logger')
        self.complete_key_in_bytes = None
        self.crypto_tools = NTPCrypto()

    def add_secret_to_send(self, plaintext, static_key):
        """
        Adds a plaintext and a static key which are stored as an NTPSecret.
        :param plaintext:
        :param static_key:
        :return:
        """
        combined_key = self.crypto_tools.generate_aes_key_bytes(static_key, self.aes_nonce)
        self.complete_key_in_bytes = combined_key
        payload_bytes = BitArray(bin=plaintext).bytes
        self.log.debug('Plaintext to encrypt in bits: ' + str(plaintext))
        self.log.debug('Key used for encryption: ' + str(combined_key))
        self.secret_to_send = NTPSecret(payload_bytes=payload_bytes, key_bytes=combined_key)
        self.log.debug("Encrypted payload to send in bits: " + str(self.secret_to_send.get_all_bits()))

        return self.secret_to_send

    def generate_init_pck(self, address: str) -> NTP:
        """
        Creates a new init package containing the hashed version number and address information.
        Also stores the AES nonce in the session.
        :param address: The address to hash and insert into the package.
        :return: the NTP package filled with address and version information.
        """
        ntp = init_ntp_pck()

        raw_ntp = CP1Package(ntp)
        self.log.debug("Init pck field: " + str(self.init_pck_field))
        self.log.debug(
            'Value of init-package-field before transformation: ' + str(raw_ntp.get_field(self.init_pck_field)))

        self.aes_nonce = raw_ntp.aes_nonce_bits()
        address_hashed = generate_address_hash(raw_ntp.hash_nonce(), address)
        self.log.debug('Address hash: ' + str(address_hashed))
        version_hashed = generate_version_hash(raw_ntp.hash_nonce(), _PROTOCOL_VERSION)

        field_value = raw_ntp.get_field(self.init_pck_field)
        field_value = field_value[:len(field_value) - 8] + address_hashed + version_hashed
        assert len(field_value) == 64
        raw_ntp.set_field(field_value, self.init_pck_field)
        self.log.debug(
            'Value of init-package-field after transformation: ' + str(raw_ntp.get_field(self.init_pck_field)))

        ntp = raw_ntp.ntp()
        return ntp

    def next_pck(self, cp1_pck: CP1Package):
        """
        Handles the next NTP package, extracts the payload and adds it to the session storage.
        :param cp1_pck:
        :return:
        """
        self.secret_received += cp1_pck.extract_payload()

    def is_complete(self):
        """
        Checks whether the 128 bit payload of this session is fully received or not.
        :return:
        """
        return len(self.secret_received) >= 128
