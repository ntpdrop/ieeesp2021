import logging
import random
from time import sleep

import matplotlib.pyplot as plt
from scapy.layers.ntp import NTP

from cp1_client import CP1Client
from cp1_common_secrets import ADDR_2, STATIC_KEY, ADDR_1, PAYLOAD_BITS_120
from ntp_raw import RawNTP
from ntp_utils import extract_64timestamp_fraction


class CP1DistributionExperiment:
    def __init__(self, n: int, receiver_addr:str, max_sleep: float = 2,
                 log: logging.Logger = logging.getLogger('CP1-Distribution-Experiment-Logger')):
        self.log = log
        self._n = n
        self._max_sleep = max_sleep
        self.receiver_addr = receiver_addr
        self._ref_container = [[0 for i in range(10)] for j in range(9)]
        self._origin_container = [[0 for i in range(10)] for j in range(9)]
        self._rec_container = [[0 for i in range(10)] for j in range(9)]
        self._trans_container = [[0 for i in range(10)] for j in range(9)]

    def run(self):
        self.log.info('# Start CP1 experiment with n=' + str(self._n))
        i = 0
        while i < self._n:
            i += 1
            self.log.info('\n### Iteration: ' + str(i) + '/' + str(self._n))
            #sleep_time = random.uniform(0, self._max_sleep)
            sleep_time = 0
            self.log.info('Delay: ' + str(sleep_time))

            client = CP1Client(address=ADDR_2, static_key=STATIC_KEY, sniff_interface='wlp3s0')

            sleep(sleep_time)
            self.log.info("Send init package to addr: " + str(self.receiver_addr))
            raw_ntp = RawNTP(client.send_init_pck(self.receiver_addr, ADDR_1)[NTP])
            self._process_ntp_result(raw_ntp)

            client.add_secret_payload(PAYLOAD_BITS_120, STATIC_KEY)

            for x in range(8):
                #sleep_time = random.uniform(0, self._max_sleep)
                sleep_time = 0
                self.log.info('Delay: ' + str(sleep_time))
                sleep(sleep_time)
                self.log.info("Send payload package nr. " + str(x+1))
                raw_ntp = RawNTP(client.send_next_pck(self.receiver_addr)[NTP])
                self._process_ntp_result(raw_ntp)

        self._show_results()

    def _show_results(self):
        self.log.info('\n\n# Final report')
        self.log.info('Iterations: ' + str(self._n))
        self.log.info('Test receiver: ' + str(self.receiver_addr))
        self.log.info('Reference timestamp results: ' + str(self._ref_container))
        self.log.info('Origin timestamp results: ' + str(self._origin_container))
        self.log.info('Received timestamp results: ' + str(self._rec_container))
        self.log.info('Transmit timestamp results: ' + str(self._trans_container))
        for i in range(9):
            plt.plot(self._origin_container[i], label='Origin position: ' + str(i + 1))
        plt.legend()
        plt.xlabel('Digit')
        plt.ylabel('Amount')
        plt.show()

        plt.clf()
        for i in range(9):
            plt.plot(self._ref_container[i], label='Reference position: ' + str(i + 1))
        plt.legend()
        plt.xlabel('Digit')
        plt.ylabel('Amount')
        plt.show()

        plt.clf()
        for i in range(9):
            plt.plot(self._trans_container[i], label='Transmit position: ' + str(i + 1))
        plt.legend()
        plt.xlabel('Digit')
        plt.ylabel('Amount')
        plt.show()

        plt.clf()
        for i in range(9):
            plt.plot(self._rec_container[i], label='Received position: ' + str(i + 1))
        plt.legend()
        plt.xlabel('Digit')
        plt.ylabel('Amount')
        plt.show()

    def _process_ntp_result(self, result: RawNTP):
        orig_digits = extract_64timestamp_fraction(result.origin_timestamp())
        trans_digits = extract_64timestamp_fraction(result.transmit_timestamp())
        ref_digits = extract_64timestamp_fraction(result.reference_timestamp())
        rec_digits = extract_64timestamp_fraction(result.receive_timestamp())

        self.log.info('Raw bits: ' + orig_digits + ' ' + trans_digits + ' ' + ref_digits + ' ' + rec_digits)

        for i in range(9):
            origin_n = int(orig_digits[i])
            trans_n = int(trans_digits[i])
            ref_n = int(ref_digits[i])
            rec_n = int(rec_digits[i])
            self.log.debug('Iteration bits ' + str(i) + ': ' + str(origin_n) + ' ' + str(trans_n) + ' ' + str(
                    ref_n) + ' ' + str(rec_n))
            self._origin_container[i][origin_n] += 1
            self._ref_container[i][ref_n] += 1
            self._rec_container[i][rec_n] += 1
            self._trans_container[i][trans_n] += 1


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()
    fh = logging.FileHandler('cp1_experiment_results.log')
    fh.setLevel(logging.INFO)
    logger.addHandler(fh)
    experiment = CP1DistributionExperiment(1112, receiver_addr='192.168.50.102', log=logger)
    experiment.run()
