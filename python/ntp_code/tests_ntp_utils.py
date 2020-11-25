import unittest
from ntp_utils import *


class NTPUtilsTests(unittest.TestCase):

    def test_init_ntp_pck_all_fields_are_filled(self):
        # Act
        ntp = init_ntp_pck()

        # Assert
        self.assertIsNotNone(ntp.ref)

    def test_init_ntp_client_pck_sent_transmit_filled_rest_null(self):
        # Act
        ntp = init_ntp_client_pck()

        # Assert
        self.assertIsNotNone(ntp.sent)
        self.assertTrue(ntp.ref == 0)
        self.assertTrue(ntp.recv == 0)
        self.assertTrue(ntp.orig == 0)

    def test_bit_to_ascii_8_bit_transferred_one_char_returned(self):
        # Arrange
        bit_string = '01000111'

        # Act
        result = bit_to_ascii(bit_string)

        # Assert
        self.assertEqual(result, 'G')

    def test_bit_to_ascii_complete_sentence_transferred_correctly_translated(self):
        # Arrange
        bit_string = '0100100001100101011011000110110001101111001000000101011101101111011100100110110001100100'

        # Act
        result = bit_to_ascii(bit_string)

        # Assert
        self.assertEqual(result, 'Hello World')

    def test_ascii_to_bit_one_char_to_8_bit(self):
        # Arrange
        ascii_char = 'G'

        # Act
        result = ascii_to_bit(ascii_char)

        # Assert
        self.assertEqual(result, '01000111')

    def test_ascii_to_bit_one_sentence_to_X_bit(self):
        # Arrange
        ascii_char = 'Hello World'

        # Act
        result = ascii_to_bit(ascii_char)

        # Assert
        self.assertEqual(result, '0100100001100101011011000110110001101111001000000101011101101111011100100110110001100100')


if __name__ == '__main__':
    unittest.main()
