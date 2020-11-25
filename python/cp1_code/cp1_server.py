import logging
from threading import Lock

from scapy.layers.ntp import NTP

from cp1_client_session import CP1ClientSession
from cp1_helper import _PROTOCOL_VERSION, generate_address_hash, generate_version_hash
from cp1_package import CP1Package
from ntp_crypto import decrypt_bits_raw, NTPCrypto
from ntp_raw import NTPField
from scapy_wrapper import ScapyWrapper


class CP1Server:
    """
    Provides functionality for a CP1 client (receive and send hidden messages).
    """

    def __init__(self, cp1_address_bits: str, static_decryption_key_bits: str, sniff_interface: str = 'lo',
                 self_ip_addr: str = None,
                 log: logging.Logger = logging.getLogger('CP1Server-logger')):
        self.log = log
        self._address = cp1_address_bits
        self.static_key_bits = static_decryption_key_bits
        self.init_pck_field = NTPField.TRANSMIT_TIMESTAMP
        self.sniff_interface = sniff_interface
        self.listen_session: CP1ClientSession = None
        self._listen_lock = Lock()
        self._release_listen = False
        self.self_ip_addr = self_ip_addr
        self.scapy_wrapper = ScapyWrapper()
        self.crypto_tools = NTPCrypto()

    def address_and_version_check(self, pck: CP1Package) -> bool:
        """
        Checks whether a pck is meant for this client: Does the address and version number match?
        :param pck: The package to check
        :return: True in case it is meant for this client, False otherwise.
        """
        init_field = pck.get_field(self.init_pck_field)
        init_field = init_field[self.init_pck_field.length() - 8: self.init_pck_field.length()]
        received_address_bits_hashed = init_field[0:6]
        own_address_bits_hashed = generate_address_hash(pck.hash_nonce(), self._address)

        if received_address_bits_hashed != own_address_bits_hashed:
            self.log.debug('The received address hash did not match: ' + received_address_bits_hashed)
            return False

        received_version_bits_hashed = init_field[6:8]
        own_version_bits_hashed = generate_version_hash(pck.hash_nonce(), _PROTOCOL_VERSION)

        if received_version_bits_hashed != own_version_bits_hashed:
            self.log.debug(
                'The received version hash did not match the expected value: ' + str(received_version_bits_hashed))
            return False

        return True

    def listen(self):
        """
        Starts to listen for incoming NTP packages. This action is blocking so far.
        :return:
        """
        # TODO: Move this action to a new thread.
        if self._listen_lock.locked():
            return False
        self._listen_async()
        return True

    def _listen_async(self):
        """
        A synchronized method which waits for matching incoming NTP-packages and handles them accordingly to the
        current Session status (initialized, or non-initialized).
        :return:
        """
        self._listen_lock.acquire()
        try:
            self.log.info(
                "Lock acquired, starting to listen for incoming NTP packages on interface: " + self.sniff_interface)
            while True:

                if self.self_ip_addr is None:
                    pck = self.scapy_wrapper.next_ntp_packet(self.sniff_interface)
                else:
                    pck = self.scapy_wrapper.next_ntp_packet_for_target(self.sniff_interface, self.self_ip_addr)

                self.log.info("NTP-Package received")

                if self._release_listen:  # The listening should be aborted.
                    self._release_listen = False
                    return

                self.handle_incoming_ntp_pck(pck[NTP])

        finally:
            self.log.error("Session cleared after exception.")
            self.listen_session = None
            self._listen_lock.release()

    def handle_incoming_ntp_pck(self, ntp_pck: NTP):
        cp1_pck = CP1Package(ntp_pck)
        self.log.info('Received pck bits: ' + str(cp1_pck._raw))
        if self.listen_session is None:
            if not self.address_and_version_check(cp1_pck):
                self.log.info('Package did not contain matching address or version')
            else:
                self.log.info("Init pck. Creating new session")
                self.listen_session = CP1ClientSession(self.static_key_bits, cp1_pck)
            return

        self.listen_session.add_next_pck(cp1_pck)

        if self.listen_session.is_complete():
            self.log.info("Payload completely received: " + str(self.listen_session.secret_received_in_bits))
            self.log.info("Using key to decrypt: " + str(self.listen_session.get_decryption_key_bytes()))
            decoded_bits = decrypt_bits_raw(
                encrypted_bits=self.listen_session.secret_received_in_bits,
                decryption_key_bytes=self.listen_session.get_decryption_key_bytes())
            self.log.info("DECRYPTED Payload: " + str(decoded_bits))
            self.listen_session = None
