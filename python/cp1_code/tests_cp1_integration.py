import unittest

from cp1_client import CP1Client
from test_constants import PAYLOAD_BITS_120, KEY_BITS_192


class CP1IntegrationTests(unittest.TestCase):

    def test_send_init_pck(self):
        # Arrange
        print("TEST: Send init package")

        # Act
        client = CP1Client('111010', 'SecretKey')
        client.send_init_pck("192.168.0.0", "100110")

    def test_send_next_pck_after_init(self):
        # Arrange
        print("TEST: Send next package")
        client = CP1Client('111010', 'SecretKey')
        client.send_init_pck("192.168.0.0", "100110")

        # Act
        client.add_secret_payload(payload=PAYLOAD_BITS_120, static_key=KEY_BITS_192)
        client.send_next_pck('192.168.0.0')


if __name__ == '__main__':
    unittest.main()
