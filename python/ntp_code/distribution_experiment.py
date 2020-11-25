import logging
from time import sleep

import matplotlib.pyplot as plt
from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTP
from scapy.sendrecv import sr1

from ntp_raw import RawNTP
from ntp_utils import extract_64timestamp_fraction


class DistributionExperiment:
    def __init__(self, n: int, max_sleep: float = 2, server_addr: str = '2.pool.ntp.org', debug: bool = False,
                 log: logging.Logger = logging.getLogger('default_logger')):
        self.log = log
        self._n = n
        self._error_counter_response = 0
        self._error_counter_timeout = 0
        self._max_sleep = max_sleep
        self._server_addr = server_addr
        self._debug = debug
        self._ref_container = [[0 for i in range(10)] for j in range(9)]
        self._origin_container = [[0 for i in range(10)] for j in range(9)]
        self._rec_container = [[0 for i in range(10)] for j in range(9)]
        self._trans_container = [[0 for i in range(10)] for j in range(9)]

    def run(self):
        self.log.info('# Start experiment with n=' + str(self._n))
        i = 0
        while i < self._n:
            i += 1
            self.log.info('\n### Iteration: ' + str(i) + '/' + str(self._n))
            # sleep_time = random.uniform(0, self._max_sleep)
            sleep_time = 0
            self.log.info('Delay: ' + str(sleep_time))
            sleep(sleep_time)
            request = IP(dst=self._server_addr) / UDP() / NTP()
            response = sr1(request, timeout=2)
            if response is None:
                self.log.info('Error: Server not reached within time. Increasing n by 1')
                self._n += 1
                self._error_counter_timeout += 1
                continue

            response[NTP].show()
            raw_ntp = RawNTP(response[NTP])
            self._process_ntp_result(raw_ntp)
        self._show_results()

    def _show_results(self):
        self.log.info('\n\n# Final report')
        self.log.info('Iterations: ' + str(self._n))
        self.log.info('Malformed server responses: ' + str(self._error_counter_response))
        self.log.info('Server timeouts errors: ' + str(self._error_counter_timeout))
        self.log.info('Test server: ' + str(self._server_addr))
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
            try:
                origin_n = int(orig_digits[i])
                trans_n = int(trans_digits[i])
                ref_n = int(ref_digits[i])
                rec_n = int(rec_digits[i])
            except:
                # Sometimes one of the pool servers does not respond with 4 valid timestamp fields.
                # In that case the response is skipped and another round is re-added.
                self.log.info('Experiment FAILED due to invalid server response. Increasing n by 1')
                self._n += 1
                self._error_counter_response += 1
                return
            if self._debug:
                self.log.info('Iteration bits ' + str(i) + ': ' + str(origin_n) + ' ' + str(trans_n) + ' ' + str(
                    ref_n) + ' ' + str(rec_n))
            self._origin_container[i][origin_n] += 1
            self._ref_container[i][ref_n] += 1
            self._rec_container[i][rec_n] += 1
            self._trans_container[i][trans_n] += 1


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()
    fh = logging.FileHandler('experiment_results.log')
    fh.setLevel(logging.INFO)
    logger.addHandler(fh)
    experiment = DistributionExperiment(10000, server_addr='1.pool.ntp.org', debug=True, log=logger)
    experiment.run()
