import logging

from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTP
from scapy.packet import Packet

from cp3_common_secrets import CP3_STATIC_KEY, PAYLOAD_RANDOM_64_1, PAYLOAD_RANDOM_64_2
from cp3_handler import CP3Handler
from cp3_package import CP3Package
from log_utils import file_logger
from netfilter_wrapper import NetfilterWrapper


class CP3Interceptor:

    def __init__(self, client_addr: str, server_addr: str, cp3_handler: CP3Handler,
                 log: logging.Logger = logging.getLogger('CP3Interceptor-logger')):
        self.log = log
        self.client_addr = client_addr
        self.server_addr = server_addr
        self.cp3_handler = cp3_handler
        self.sending_status = 1
        self.send_payload = True

    def check_pck(self, packet: Packet) -> bool:
        if not packet:
            return False

        if not packet.haslayer(NTP):
            return False

        if (packet[IP].src != self.client_addr) and (packet[IP].src != self.server_addr):
            self.log.debug('The source IP addr was: ' + str(packet[IP].src))
            return False
        return True

    def handle_pck(self, packet: Packet) -> Packet:

        if packet[IP].src == self.server_addr:
            if not self.send_payload:
                self.log.debug("Sending of payload is deactivated.")
                return packet
            cp3_pck = CP3Package(packet[NTP])
            if self.sending_status == 1:
                cp3_pck.set_cp3_mode_1()
            else:
                cp3_pck.set_cp3_mode_2()
            cp3_pck.add_payload(self.__next_payload())
            self.log.info('CP3 payload added for intercepted package: ' + str(cp3_pck.extract_payload())
                          + " in CP3 mode " + str(cp3_pck.get_cp3_mode()))
            complete_pck = packet[IP] / packet[UDP] / NTP()
            complete_pck[NTP] = cp3_pck.ntp()
            return complete_pck

        elif packet[IP].src == self.client_addr:
            cp3_pck = CP3Package(packet[NTP])
            if not self.cp3_handler.read_incoming_pck(cp3_pck):
                return packet
            ntp_restored = self.cp3_handler.restore_pck(cp3_pck)
            complete_restored = packet[IP] / packet[UDP] / ntp_restored
            complete_restored[NTP] = ntp_restored
            return complete_restored

        else:
            self.log.error('The given packet was not matching the sender/receiver address!')
            return packet

    def __next_payload(self) -> str:
        if self.sending_status == 1:
            self.sending_status = 2
            return PAYLOAD_RANDOM_64_1
        else:
            self.sending_status = 1
            return PAYLOAD_RANDOM_64_2


if __name__ == '__main__':
    logger = file_logger(path='cp3_interceptor.log')
    handler = CP3Handler(CP3_STATIC_KEY, log=logger)
    client_ip = '192.168.100.101'
    server_ip = '192.168.110.1'
    interceptor = CP3Interceptor(client_addr=client_ip, server_addr=server_ip, cp3_handler=handler, log=logger)
    interceptor.send_payload = False
    netfilter_wrapper = NetfilterWrapper(interceptor.check_pck, interceptor.handle_pck)
    netfilter_wrapper.bind()
    netfilter_wrapper.run()
