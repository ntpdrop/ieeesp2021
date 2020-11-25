import logging
from threading import Lock

from scapy.layers.inet import IP, UDP
from scapy.packet import Packet
from scapy.sendrecv import send

from cp1_function_code import CP1FunctionCode
from cp1_helper import _PROTOCOL_VERSION, generate_address_hash, generate_version_hash
from cp1_package import CP1Package
from cp1_payload import CP1Payload
from cp1_session import CP1Session
from ntp_mode import NTPMode
from ntp_raw import NTPField
from ntp_utils import init_ntp_client_pck


class CP1Client:
    """
    Provides functionality for a CP1 client (receive and send hidden messages).
    """

    def __init__(self, address: str, static_key: str, sniff_interface: str = 'lo',
                 log=logging.getLogger('CP1Client-Logger')):
        self.address = address
        self.static_key = static_key
        self.init_pck_field = NTPField.TRANSMIT_TIMESTAMP
        self.sniff_interface = sniff_interface
        self.listen_session: CP1Session = None
        self._listen_lock = Lock()
        self._release_listen = False
        self.send_session: CP1Session = None
        self.payload_size = 16  # The number of bits send per payload package (must be a divisor of 128).
        self.log = log

    def address_and_version_check(self, pck: CP1Package) -> bool:
        """
        Checks whether a pck is meant for this client: Does the address and version number match?
        :param pck: The package to check
        :return: True in case it is meant for this client, False otherwise.
        """
        init_field = pck.get_field(self.init_pck_field)
        init_field = init_field[self.init_pck_field.length() - 8: self.init_pck_field.length()]
        received_address_bits_hashed = init_field[0:6]
        own_address_bits_hashed = generate_address_hash(pck.hash_nonce(), self.address)

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

    def send_init_pck(self, ip_address, cp1_address):
        """
        Sends an init-package to the desired ip-address and files in the desired cp1-address.
        :param ip_address:
        :param cp1_address:
        :return:
        """
        self.send_session = CP1Session()
        ntp_pck = self.send_session.generate_init_pck(cp1_address)
        # ntp_pck.show()
        pck_to_send = IP(dst=ip_address) / UDP() / ntp_pck
        send(pck_to_send)
        self.log.debug("Init package successfully send to " + str(ip_address))
        return pck_to_send

    def add_secret_payload(self, payload, static_key):
        assert self.send_session is not None
        payload_with_function_code = CP1Payload(CP1FunctionCode.MSG_ONE, payload)
        self.log.debug("Complete payload created: " + str(payload_with_function_code.complete_payload))
        self.send_session.add_secret_to_send(payload_with_function_code.complete_payload, static_key)

    def has_next_pck(self):
        if self.send_session is None:
            return False

        if self.send_session.secret_to_send is None:
            return False

        return self.send_session.secret_to_send.has_next_bits()

    def send_next_pck(self, ip_address, ntp_mode: NTPMode = NTPMode.CLIENT) -> Packet:
        """
        Sends the next chunk of payload bits to the destination.
        :param ip_address:
        :param ntp_mode: the mode of the ntp package to send.
        :return: the bits just send.
        """
        next_bits_to_send = self.send_session.secret_to_send.next_bits(self.payload_size)
        self.log.debug("Next payload bits to send: " + str(next_bits_to_send))

        ntp_pck = CP1Package(ntp_pck=init_ntp_client_pck())
        ntp_pck.add_payload(next_bits_to_send)
        ntp_pck.set_mode(NTPMode.to_bit_string(ntp_mode))

        pck_to_send = IP(dst=ip_address) / UDP() / ntp_pck.ntp()
        send(pck_to_send)

        self.log.debug("Payload package successfully send to " + str(ip_address))

        if not self.send_session.secret_to_send.has_next_bits():
            self.log.debug("Sending complete. Terminating sending session.")

        return pck_to_send
