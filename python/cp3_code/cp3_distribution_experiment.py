from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTP
from scapy.sendrecv import sr1

from log_utils import file_logger
from ntp_raw import RawNTP

if __name__ == '__main__':
    log = file_logger(path='cp3_experiment_results.log', logger_name='CP3-Logger')

    N = 10000
    server_address = '192.168.50.102'
    deviations = 0
    error_counter = 0

    log.info("Starting CP3 distribution experiment with N=" + str(N) + " and server address=" + str(server_address))

    i = 0
    while i < N:
        i += 1
        log.debug("Iteration " + str(i))
        ntp = NTP()
        ntp.orig = None
        request = IP(dst=server_address) / UDP() / ntp
        response = sr1(request, timeout=2)
        if response is None:
            error_counter += 1
            i -= 1
            log.info('Error: Server not reached within time.')
            continue

        log.debug("Response from: " + response[IP].src)
        ntp_raw = RawNTP(response[NTP])
        if (ntp_raw.origin_timestamp()[0:32] != ntp_raw.transmit_timestamp()[0:32]) \
                or (ntp_raw.origin_timestamp()[0:32] != ntp_raw.receive_timestamp()[0:32]):
            deviations += 1
            log.info("Deviation detected")
            log.info("Origin:" + str(ntp_raw.origin_timestamp()))
            log.info("Trasmit:" + str(ntp_raw.transmit_timestamp()))
            log.info("Received:" + str(ntp_raw.receive_timestamp()))

    log.info("Experiment done. Total number of deviations=" + str(deviations)
             + ", number of errors=" + str(error_counter))
