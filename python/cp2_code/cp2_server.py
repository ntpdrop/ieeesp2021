import logging

from scapy.layers.inet import IP

from cp2_common_secret import CP2_ZERO_BITS, CP2_ONE_BITS
from log_utils import file_logger
from ntp_utils import ascii_to_bit
from scapy_wrapper import ScapyWrapper


class CP2Server:
    def __init__(self, client_ip: str, sniff_interface: str,
                 stratum_file_path: str = '/etc/stratum_override.txt', num_pck_per_bit=1,
                 log: logging.Logger = logging.getLogger('CP2Server-logging')):
        """
        A CP2 Server that listens for incoming NTP requests and injects the manipulated stratum value to a config
        file on the harddrive
        :param log:
        """
        self.log = log
        self.stratum_file_path = stratum_file_path
        self.num_pck_per_bit = num_pck_per_bit
        self.client_ip = client_ip
        self.scapy_wrapper = ScapyWrapper()
        self.sniff_interface = sniff_interface
        self.payload_to_send = 'Hello World'
        self.payload_pointer = -1
        self.payload_bits = ''
        self.current_pck_num = 0
        self.current_stratum = None
        self.zero_mode = False
        self.init_done = False
        self.init_counter = 0

    def run(self):
        self.log.info("Starting CP2 Server and listening on interface " + str(self.sniff_interface)
                      + " for client requests from " + str(self.client_ip))
        self.payload_bits = ascii_to_bit(self.payload_to_send)
        self.log.info('Sending payload "' + str(self.payload_to_send) + '" decoded as ' + str(self.payload_bits))

        self.set_current_stratum()
        self.inject_next_bit()

        while True:
            next_pck = self.scapy_wrapper.next_ntp_packet(sniff_interface=self.sniff_interface)
            if next_pck[IP].src != self.client_ip:
                self.log.debug('Packet with ip ' + str(next_pck[IP]) + ' was not meant for this server.')
                continue

            if not self.init_done:
                self.init_counter += 1
                if self.init_counter >= 3:
                    self.init_done = True
                    continue

            self.current_pck_num += 1

            if self.current_pck_num >= self.num_pck_per_bit:
                self.current_pck_num = 0
                self.set_current_stratum()
                self.inject_next_bit()
            else:
                self.log.debug('No change in stratum so far...')

    def set_current_stratum(self):
        """
        Sets the current stratum value based on the last bit value. It toggles the current stratum value in case
        the next bit is from the same type. This methods also sets and resets the current payload pointer accordingly.
        :return: the current Stratum value that was just set.
        """

        if self.payload_pointer % 8 == 0 and self.payload_pointer != 0 and not self.zero_mode:
            self.log.debug("One byte transfer complete " +
                           str(self.payload_bits[self.payload_pointer - 8:self.payload_pointer]))
            # self.zero_mode = True
            # self.current_stratum = CP2_NO_BITS[0]
            # return

        # if self.zero_mode:
        #    self.zero_mode = False

        if self.payload_pointer == len(self.payload_bits) - 1:
            self.log.info("Resetting the payload pointer")
            self.payload_pointer = -1
            self.payload_pointer += 1
            current_bit = self.payload_bits[self.payload_pointer]
            if current_bit == '0':
                self.current_stratum = CP2_ZERO_BITS[0]
            else:
                self.current_stratum = CP2_ONE_BITS[0]
            return self.current_stratum

        current_bit = self.payload_bits[self.payload_pointer]
        next_bit = self.payload_bits[self.payload_pointer + 1]
        self.payload_pointer += 1

        if current_bit == '0' and next_bit == '0':
            if self.current_stratum == CP2_ZERO_BITS[0]:
                self.current_stratum = CP2_ZERO_BITS[1]
            else:
                self.current_stratum = CP2_ZERO_BITS[0]
        elif current_bit == '1' and next_bit == '1':
            if self.current_stratum == CP2_ONE_BITS[0]:
                self.current_stratum = CP2_ONE_BITS[1]
            else:
                self.current_stratum = CP2_ZERO_BITS[0]
        elif next_bit == '1':
            self.current_stratum = CP2_ONE_BITS[0]
        else:
            self.current_stratum = CP2_ZERO_BITS[0]

        return self.current_stratum

    def inject_next_bit(self):
        """
        Writes the current stratum value to a file, where it can be read by a manipulated chrony NTP server.
        :return:
        """
        self.log.debug("Injecting next stratum " + str(self.current_stratum) + " for bit: "
                       + str(self.payload_bits[self.payload_pointer]))
        with open(self.stratum_file_path, 'w') as file:
            file.write(str(self.current_stratum))


if __name__ == '__main__':
    logger = file_logger(path='cp2_server.log')
    client_ip = '192.168.110.101'
    sniff_interface = 'enp0s9'
    server = CP2Server(client_ip=client_ip, sniff_interface=sniff_interface, log=logger)
    server.run()
