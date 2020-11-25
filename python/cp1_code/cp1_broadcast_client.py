import logging

from scapy.layers.inet import IP, UDP
from scapy.packet import Packet
from scapy.sendrecv import send

from cp1_client import CP1Client
from cp1_package import CP1Package
from cp1_session import CP1Session
from ntp_mode import NTPMode
from ntp_utils import init_ntp_client_pck


class CP1BroadcastClient(CP1Client):
    """
    OBSOLETE
    """

    def __init__(self, address: str, static_key: str, sniff_interface: str = 'lo',
                 log=logging.getLogger('CP1Client-Logger')):
        super().__init__(address, static_key, sniff_interface, log)


    def send_init_pck(self, ip_address, cp1_address):
        """
        Sends an init-package to the desired ip-address and files in the desired cp1-address.
        :param ip_address:
        :param cp1_address:
        :return:
        """
        self.send_session = CP1Session()
        ntp_pck = self.send_session.generate_init_pck(cp1_address)
        ntp_pck.orig = None
        ntp_pck.recv = None
        ntp_pck.mode = 5
        # ntp_pck.show()
        pck_to_send = IP(dst=ip_address) / UDP() / ntp_pck
        send(pck_to_send)
        self.log.debug("Init package successfully send to " + str(ip_address))
        return pck_to_send

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
        ntp_pck_ntp = ntp_pck.ntp()
        ntp_pck_ntp.orig = None
        ntp_pck_ntp.recv = None
        ntp_pck_ntp.mode = 5
        pck_to_send = IP(dst=ip_address) / UDP() / ntp_pck_ntp
        send(pck_to_send)

        self.log.debug("Payload package successfully send to " + str(ip_address))

        if not self.send_session.secret_to_send.has_next_bits():
            self.log.debug("Sending complete. Terminating sending session.")

        return pck_to_send
