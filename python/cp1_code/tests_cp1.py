import unittest

from scapy.layers.ntp import NTPHeader

from cp1_client import CP1Client
from cp1_helper import generate_address_hash, generate_version_hash
from cp1_package import CP1Package
from cp1_session import CP1Session
from ntp_utils import bit_to_long
from test_constants import KEY_BITS_192

_first_32_bit = '00101111111111111110111010000111'
_last_24_bit = '000000000000000000000000'
_last_30_bit = '000000000000000000000000000000'
_last_32_bit = '00000000000000000000000000000000'


class CP1Tests(unittest.TestCase):

    def test_generate_address_hash(self):
        # Arrange
        nonce = '011101011'
        address = '0101'
        expected_hash = '010011'  # complete hex =  4c2e2f7c4b571674aac9f9d780d601d6

        # Act
        result_hash = generate_address_hash(nonce, address)

        # Assert
        self.assertEqual(expected_hash, result_hash)


class CP1ClientTests(unittest.TestCase):
    def test_address_and_version_check_true(self):
        # Arrange
        raw_ntp = CP1Package()
        address = '011011'
        hash_6bit = generate_address_hash(_first_32_bit, address)[:6]
        last_32_bit = _last_24_bit + hash_6bit + generate_version_hash(_first_32_bit, '00')
        raw_ntp.set_transmit_timestamp(_first_32_bit + last_32_bit)
        raw_ntp = CP1Package(raw_ntp.ntp())  # Create a new raw in order to validate, that the transformation works.
        cp1_client = CP1Client(address=address, static_key='')

        # Act
        result = cp1_client.address_and_version_check(raw_ntp)

        # Assert
        self.assertTrue(result)


class CP1PackageTests(unittest.TestCase):
    def test_hash_nonce(self):
        # Arrange
        ntp = NTPHeader()
        time_value = bit_to_long(_first_32_bit + _last_32_bit)
        ntp.sent = time_value
        cp1_pck = CP1Package(ntp)

        # Act
        nonce = cp1_pck.hash_nonce()

        # Assert
        self.assertEqual(_first_32_bit, nonce)

    def test_aes_nonce(self):
        # Arrange
        ntp = NTPHeader()
        ntp.sent = bit_to_long(_first_32_bit + _last_32_bit)
        ntp.ref = ntp.sent
        cp1_pck = CP1Package(ntp)

        # Act
        nonce = cp1_pck.aes_nonce_bits()

        # Assert
        self.assertEqual(_first_32_bit + _first_32_bit, nonce)


class CP1SessionTests(unittest.TestCase):
    def test_generate_init_pck_nonce_is_not_null_after_init(self):
        # Arrange
        session = CP1Session()

        # Act
        session.generate_init_pck(address='111101')

        # Assert
        self.assertIsNotNone(session.aes_nonce)

    def test_generate_init_pck_nonce_address_and_version_are_hashed(self):
        # Arrange
        session = CP1Session()

        # Act
        result = session.generate_init_pck(address='111101')

        # Assert
        self.assertIsNotNone(session.aes_nonce)

    def test_generate_aes_key_key_has_length_32(self):
        # Arrange
        session = CP1Session()
        session.generate_init_pck('1.1.1.1')

        # Act
        # TODO repair
        result_bytes = session.generate_aes_key(KEY_BITS_192)

        # Assert
        self.assertTrue(len(result_bytes) == 32)


if __name__ == '__main__':
    unittest.main()
