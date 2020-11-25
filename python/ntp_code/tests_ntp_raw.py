import unittest

from scapy.layers.ntp import NTPHeader

from ntp_raw import NTPField, RawNTP

_TEST_BIN_64BIT = '1010111111111111111011101000011100000000000000000000000000000011'


class NTPFieldTests(unittest.TestCase):
    def test_length(self):
        # Act & Assert
        self.assertEqual(NTPField.REFERENCE_TIMESTAMP.length(), 64)
        self.assertEqual(NTPField.ORIGIN_TIMESTAMP.length(), 64)

    def test_ntp(self):
        # Arrange
        ntp_header = NTPHeader()
        ntp_raw = RawNTP(ntp_header)
        ntp_raw.set_transmit_timestamp(_TEST_BIN_64BIT)

        # Act
        result = RawNTP(ntp_raw.ntp())

        # Assert
        self.assertEqual(result.transmit_timestamp(), _TEST_BIN_64BIT)

    def test_set_receive_timestamp(self):
        # Arrange
        ntp_raw = RawNTP()

        # Act
        ntp_raw.set_receive_timestamp(_TEST_BIN_64BIT)

        # Assert
        self.assertEqual(len(ntp_raw._raw), 384)

    def test_set_origin_timestamp(self):
        # Arrange
        ntp_raw = RawNTP()

        # Act
        ntp_raw.set_origin_timestamp(_TEST_BIN_64BIT)

        # Assert
        self.assertEqual(ntp_raw.origin_timestamp(), _TEST_BIN_64BIT)
