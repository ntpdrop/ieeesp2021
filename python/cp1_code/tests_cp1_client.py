import unittest

from cp1_client import CP1Client
from cp1_session import CP1Session
from test_constants import PAYLOAD_BITS_120, KEY_BITS_192


class CP1ClientTests(unittest.TestCase):

    def test_add_secret_payload_ok_payload_added_to_session(self):
        # Arrange
        client = CP1Client('', '')
        client.send_session = CP1Session()
        client.send_session.generate_init_pck('')

        # Act
        client.add_secret_payload(payload=PAYLOAD_BITS_120, static_key=KEY_BITS_192)

        # Assert
        self.assertEqual(client.send_session.secret_to_send.total_payload_length, 128)


if __name__ == '__main__':
    unittest.main()
