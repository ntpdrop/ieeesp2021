import logging
import time

from cp3_common_secrets import PAYLOAD_RANDOM_64_1, PAYLOAD_RANDOM_64_2, CP3_STATIC_KEY
from cp3_handler import CP3Handler


class CP3Client(CP3Handler):
    def __init__(self, send_interval_between_pck_sec: int, send_interval_sec: int, server_ip_addr: str,
                 static_key_bits: str,
                 log: logging.Logger = logging.getLogger('CP3Client-logger')):
        """
        A CP3 client that is able to send packages to a common server in different intervals.
        :param send_interval_between_pck_sec:
        :param send_interval_sec:
        :param server_ip_addr:
        :param static_key_bits:
        :param log:
        """
        super().__init__(static_key_bits, log)
        self.log = log
        self.send_interval_sec = send_interval_sec
        self.send_interval_between_pck_sec = send_interval_between_pck_sec
        self.server_ip_addr = server_ip_addr

    def run(self):
        self.log.debug('Running CP3Client.')
        while True:
            self.send_pck_1(PAYLOAD_RANDOM_64_1, self.server_ip_addr)
            time.sleep(self.send_interval_between_pck_sec)
            self.send_pck_2(PAYLOAD_RANDOM_64_2, self.server_ip_addr)
            time.sleep(self.send_interval_sec)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    server_ip = '192.168.110.1'
    sec_between_pck = 2
    sec_between_msg = 10
    client = CP3Client(2, 10, server_ip, CP3_STATIC_KEY)
    client.run()
