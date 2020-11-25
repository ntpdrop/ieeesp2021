import unittest

from ntp_crypto import NTPSecret


class NTPCryptoTests(unittest.TestCase):

    def test_has_next_bits_after_not_empty_returns_true(self):
        # Arrange
        ntp_secret = NTPSecret('Hello', 'Encrypt')
        length = ntp_secret.total_payload_length
        ntp_secret.next_bits(length - 1)

        # Act
        result = ntp_secret.has_next_bits()

        # Assert
        self.assertTrue(result)

    def test_has_next_bits_after_empty_returns_false(self):
        # Arrange
        ntp_secret = NTPSecret('Hello', 'Encrypt')
        length = ntp_secret.total_payload_length
        ntp_secret.next_bits(length)

        # Act
        result = ntp_secret.has_next_bits()

        # Assert
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
