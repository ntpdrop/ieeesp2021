import logging
import unittest

from cp1_package import CP1Package
from ntp_raw import NTPField


class CP1PackageTests(unittest.TestCase):

    def test_add_payload_in_default_correctly_added(self):
        # Arrange
        payload = '1000101011010011'
        cp1_package = CP1Package()

        # Act
        cp1_package.add_payload(payload)

        # Assert
        self.assertTrue(cp1_package.transmit_timestamp()[40:56] == payload)

    def test_add_payload_different_field_and_length_correctly_added(self):
        # Arrange
        payload = '10001010100110111111'
        cp1_package = CP1Package()

        # Act
        cp1_package.add_payload(payload, pos=5, field=NTPField.RECEIVE_TIMESTAMP)

        # Assert
        self.assertTrue(cp1_package.receive_timestamp()[5:5 + len(payload)] == payload)

    def test_extract_payload_default_correctlyExtracted(self):
        # Arrange
        logging.basicConfig(level=logging.DEBUG)
        payload = '1000101011010011'
        cp1_package = CP1Package()
        cp1_package.add_payload(payload)

        # Act
        result = cp1_package.extract_payload()

        # Assert
        self.assertEqual(result, payload)


if __name__ == '__main__':
    unittest.main()
