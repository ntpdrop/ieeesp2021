from cp1_common_secrets import ADDR_1, STATIC_KEY
from cp1_server import CP1Server
from log_utils import file_logger

if __name__ == '__main__':
    logger = file_logger(path='cp1_listener.log')
    client = CP1Server(cp1_address_bits=ADDR_1, static_decryption_key_bits=STATIC_KEY, sniff_interface='enp0s3',
                       log=logger)
    client.listen()
