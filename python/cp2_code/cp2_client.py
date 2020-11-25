import logging

from scapy.layers.ntp import NTP
from scapy.packet import Packet
from scapy.sendrecv import sniff

from cp2_common_secret import CP2_ONE_BITS, CP2_ZERO_BITS, CP2_NO_BITS
from log_utils import file_logger
from ntp_utils import bit_to_ascii


class CP2Client:
    """
    Describes a secret client that uses the alteration of the stratum value to read secret information.
    """

    def __init__(self, sniff_interface='lo', server_ip: str = '1.1.1.1',
                 log: logging.Logger = logging.getLogger("CP2Client-logger")):
        self.sniff_interface = sniff_interface
        self.msg_bit_string = ''
        self.no_bits = CP2_NO_BITS
        self.zero_bits = CP2_ZERO_BITS
        self.one_bits = CP2_ONE_BITS
        self.last_stratum = 0
        self.complete_msg = ''
        self.log = log
        self.server_ip = server_ip

    def run(self):
        self.log.info("Starting CP2 client, listening on interface: " + str(self.sniff_interface))
        while True:
            # Wait for the next incoming NTP package
            pck = self.next_ntp_packet()
            ntp_pck = pck[NTP]
            stratum = ntp_pck.stratum
            self.log.info("NTP package with stratum " + str(stratum) + " received.")
            self.handle_stratum(stratum)

    def handle_stratum(self, stratum: int):
        # Case: No change in this stratum, compared with the last, so no action is taken.
        if stratum is self.last_stratum:
            self.log.info("Client no action")
            return

        if stratum == 0:
            self.log.info("Client no action because of stratum 0")
            return

        # Case: No valid bit was send and therefore the current message filling is aborted.
        if stratum in self.no_bits:
            self.log.info("Client status reset.")
            self.__client_reset()
            return

        # Case: We start a new message.
        if self.last_stratum == 0:
            self.last_stratum = stratum
            if stratum in self.zero_bits:
                self.msg_bit_string += '0'
            else:
                self.msg_bit_string += '1'
            self.log.info("New message started.")
            return

        # Case: The stratum value is in the zero bits
        if stratum in self.zero_bits:
            self.last_stratum = stratum
            self.msg_bit_string += '0'

        # Case: The stratum value is in the one bits
        if stratum in self.one_bits:
            self.last_stratum = stratum
            self.msg_bit_string += '1'

        # Case: The bit message is filled.
        if len(self.msg_bit_string) == 8:
            self.log.info("Message received (bin): " + self.msg_bit_string)
            self.log.info("Message received (char): " + str(bit_to_ascii(self.msg_bit_string)))
            self.complete_msg = self.msg_bit_string
            self.__client_reset()
            return

        self.log.debug("Current bit status: " + str(self.msg_bit_string))

    def __client_reset(self):
        self.last_stratum = 0
        self.msg_bit_string = ''
        return

    def next_ntp_packet(self) -> Packet:
        """
        Sniffs for the next incoming ntp package. This method is blocking
        :return: the sniffed package.
        """
        results = sniff(filter='udp and port 123 and src ' + str(self.server_ip), count=1, iface=self.sniff_interface)
        pck = (results[0])
        return pck


if __name__ == '__main__':
    logger = file_logger(path='cp2_client.log')
    sniff_interface = 'enp0s9'
    server_ip = '192.168.100.1'
    client = CP2Client(sniff_interface=sniff_interface,log=logger,server_ip=server_ip)
    client.run()
