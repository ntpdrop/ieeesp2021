from time import sleep

from cp1_client import CP1Client
from cp1_common_secrets import ADDR_1, STATIC_KEY, ADDR_2, PAYLOAD_BITS_120
from log_utils import file_logger

if __name__ == '__main__':
    # OBSOLETE
    sleep_time_sec_between_packets = 5
    broadcast_address = '192.168.50.255'
    sniff_interface = 'enp0s8'

    logger = file_logger(path='cp1_broadcaster.log')


    client = CP1Client(address=ADDR_2, static_key=STATIC_KEY, sniff_interface='wlp3s0', log=logger)
    input("Press ENTER to send init package")
    client.send_init_pck('192.168.50.255', ADDR_1)

    client.add_secret_payload(PAYLOAD_BITS_120, STATIC_KEY)

    while not client.send_session.is_complete():
        sleep(sleep_time_sec_between_packets)
        client.send_next_pck(broadcast_address)
