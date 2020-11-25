import logging

from scapy.layers.inet import UDP, IP

from cp3_common_secrets import CP3_STATIC_KEY
from cp3_handler import CP3Handler
from log_utils import file_logger


class CP3Server(CP3Handler):
    def __init__(self, static_key_bits: str, listen_interface: str, self_ip,
                 log: logging.Logger = logging.getLogger('CP3Server-logger')):
        """
        Provides functionality to answer requests of a CP3 client but does not care about the restoration of NTP
        packages.
        """
        super().__init__(static_key_bits, log)
        self.listen_interface: str = listen_interface
        self.self_ip: str = self_ip

    def listen_for_client_requests(self):
        self.log.debug("Server is listening for incoming NTP packages on interface " + str(self.listen_interface) + " and self IP " + str(self.self_ip))
        while True:
            pck = self.scappy_wrapper.next_ntp_packet_for_target(self.listen_interface, self.self_ip)
            self.log.debug("Captured an incoming NTP package")

            # TODO Check if NTP mode is client mode.
            # TODO Check if this is an CP3 package.
            # TODO Handle incoming package (e.g. extract information)

            answer_pck = self.scappy_wrapper.get_upstream_ntp()

            self.log.debug("Send a request for real time to the pool NTP server.")

            self.scappy_wrapper.restore_ntp_mitm_pck(answer_pck, pck[UDP].sport, pck[IP].dst)

            self.log.debug("Answer send to: " + answer_pck[IP].dst)

            self.scappy_wrapper.send(answer_pck)


if __name__ == '__main__':
    logger = file_logger(path='cp3_server.log')
    server = CP3Server(static_key_bits=CP3_STATIC_KEY,listen_interface='wlp3s0',self_ip='141.44.229.131',log=logger)
    server.listen_for_client_requests()

