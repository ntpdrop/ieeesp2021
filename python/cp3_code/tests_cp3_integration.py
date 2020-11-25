import logging
import unittest

from cp3_handler import CP3Handler
from test_constants import PAYLOAD_RANDOM_64


class CP3IntegrationTests(unittest.TestCase):

    def test_send_pck_1(self):
        # Arrange
        print("TEST: Send pck 1")
        logging.basicConfig(level=logging.DEBUG)
        client = CP3Handler(static_key_bits='')

        client.send_pck_1(PAYLOAD_RANDOM_64,'192.168.0.90')


if __name__ == '__main__':
    unittest.main()
