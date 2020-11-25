import unittest

from cp1_client_session import CP1ClientSession
from cp1_package import CP1Package
from ntp_crypto import NTPCrypto
from test_constants import KEY_BITS_192


class CP1ClientSessionTests(unittest.TestCase):

    def test_add_next_pck_successfully_added(self):
        # Arrange
        session = CP1ClientSession(KEY_BITS_192, CP1Package())
        payload_pck = CP1Package()
        payload = '1010101010111011'
        payload_pck.add_payload(payload)

        # Act
        session.add_next_pck(payload_pck)

        # Assert
        self.assertEqual(session.secret_received_in_bits, payload)

    def test_get_decryption_key_bytes(self):
        # Arrange
        cp1_pck = CP1Package()
        session = CP1ClientSession(KEY_BITS_192, cp1_pck)
        comparing_result = NTPCrypto().generate_aes_key_bytes(KEY_BITS_192, cp1_pck.aes_nonce_bits())

        # Act
        result = session.get_decryption_key_bytes()

        # Assert
        self.assertEqual(result, comparing_result)
