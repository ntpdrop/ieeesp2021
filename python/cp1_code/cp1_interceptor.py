import logging

from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTP
from scapy.packet import Packet
from scapy.sendrecv import send

from cp1_client import CP1Client
from cp1_common_secrets import PAYLOAD_BITS_120, ADDR_2
from cp1_package import CP1Package
from cp1_session import CP1Session
from ntp_crypto import NTPCrypto
from ntp_raw import RawNTP
from ntp_utils import init_ntp_client_pck
from scapy_wrapper import ScapyWrapper


class CP1Interceptor(CP1Client):
    def __init__(self, address: str, static_key: str, sniff_interface: str = 'lo', self_ip_addr='192.168.0.1',
                 payload: str = PAYLOAD_BITS_120, client_address: str = ADDR_2,
                 log=logging.getLogger('CP1Interceptor-Logger')):
        super().__init__(address, static_key, sniff_interface, log)
        self.scapy_wrapper = ScapyWrapper()
        self.crypto_tools = NTPCrypto()
        self.self_ip_addr = self_ip_addr
        self.payload = payload
        self.client_address = client_address

    def listen(self):
        self.log.info(
            "Starting to listen for incoming NTP packages on interface: " + self.sniff_interface)
        while True:
            if self.self_ip_addr is None:
                pck = self.scapy_wrapper.next_ntp_packet(self.sniff_interface)
            else:
                pck = self.scapy_wrapper.next_ntp_packet_for_target(self.sniff_interface, self.self_ip_addr)

            self.log.info("NTP-Package received")

            self.handle_incoming_pck(pck)

    def handle_incoming_pck(self, pck: Packet):
        ntp_pck = pck[NTP]
        cp1_pck = CP1Package(ntp_pck)
        self.log.info('Received pck bits: ' + str(cp1_pck._raw))

        if self.send_session is None:
            self.log.debug("Init new session (1).")
            self.send_session = CP1Session()
            next_pck = self.send_session.generate_init_pck(self.client_address)
            self.add_secret_payload(self.payload, self.static_key)

        else:
            next_bits_to_send = self.send_session.secret_to_send.next_bits(self.payload_size)
            self.log.debug("Next payload bits to send: " + str(next_bits_to_send))
            new_cp1_pck = CP1Package(ntp_pck=init_ntp_client_pck())
            new_cp1_pck.add_payload(next_bits_to_send)
            next_pck = new_cp1_pck.ntp()

        upstream_pck = self.scapy_wrapper.get_upstream_ntp()

        upstream_pck[NTP].mode = 4
        # upstream_pck[NTP].orig = ntp_pck.sent
        upstream_pck[NTP].sent = next_pck[NTP].sent
        upstream_pck[NTP].ref = next_pck[NTP].ref
        upstream_pck[IP].src = pck[IP].dst
        upstream_pck[IP].dst = pck[IP].src
        upstream_pck[UDP].sport = pck[UDP].dport
        upstream_pck[UDP].dport = pck[UDP].sport

        up_raw = RawNTP(upstream_pck[NTP])
        pck_raw = RawNTP(ntp_pck)
        up_raw.set_origin_timestamp(pck_raw.transmit_timestamp())
        upstream_pck[NTP] = up_raw.ntp()

        self.log.debug("Created new CP1 packet to send...")

        upstream_pck.show()
        send(upstream_pck)

        if not self.has_next_pck():
            self.log.debug("Init new session (2).")
            self.send_session = None
