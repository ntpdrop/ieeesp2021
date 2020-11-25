from cp1_common_secrets import ADDR_1, STATIC_KEY
from cp1_interceptor import CP1Interceptor
from log_utils import file_logger

if __name__ == '__main__':
    logger = file_logger(path='cp1_interceptor.log')
    interceptor = CP1Interceptor(address=ADDR_1, static_key=STATIC_KEY, sniff_interface='enp0s9',
                                 self_ip_addr='192.168.110.1',
                                 log=logger)
    interceptor.listen()
