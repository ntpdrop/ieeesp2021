from cp1_client import CP1Client
from cp1_common_secrets import ADDR_1, STATIC_KEY, ADDR_2, PAYLOAD_BITS_120
from log_utils import file_logger

if __name__ == '__main__':
    logger = file_logger(path='cp1_sender.log')
    client = CP1Client(address=ADDR_2, static_key=STATIC_KEY, sniff_interface='wlp3s0', log=logger)
    input("Press ENTER to send init package")
    client.send_init_pck('192.168.0.11', ADDR_1)

    client.add_secret_payload(PAYLOAD_BITS_120, STATIC_KEY)

    while not client.send_session.is_complete():
        input("Press ENTER to send next packages")
        client.send_next_pck('192.168.0.11')
