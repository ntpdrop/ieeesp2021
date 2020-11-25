import unittest

from cp2_common_secret import CP2_ZERO_BITS, CP2_ONE_BITS
from cp2_server import CP2Server


class CP2ServerTests(unittest.TestCase):

    def test_set_current_stratum_is_first_0_value_set_accordingly(self):
        # Arrange
        server = CP2Server('', '')
        server.payload_bits = '0'

        # Act
        server.set_current_stratum()

        # Assert
        self.assertEqual(CP2_ZERO_BITS[0], server.current_stratum)

    def test_set_current_stratum_is_first_1_value_set_accordingly(self):
        # Arrange
        server = CP2Server('', '')
        server.payload_bits = '1'

        # Act
        server.set_current_stratum()

        # Assert
        self.assertEqual(CP2_ONE_BITS[0], server.current_stratum)

    def test_set_current_stratum_overflow_value_set_accordingly(self):
        # Arrange
        server = CP2Server('', '')
        server.payload_bits = '011'

        # Act
        server.set_current_stratum()
        server.set_current_stratum()
        server.set_current_stratum()
        server.set_current_stratum()

        # Assert
        self.assertEqual(CP2_ZERO_BITS[0], server.current_stratum)

    def test_set_current_stratum_zero_toogle_set_accordingly(self):
        # Arrange
        server = CP2Server('', '')
        server.payload_bits = '00'

        # Act
        server.set_current_stratum()
        server.set_current_stratum()

        # Assert
        self.assertEqual(CP2_ZERO_BITS[1], server.current_stratum)

    def test_set_current_stratum_one_toogle_set_accordingly(self):
        # Arrange
        server = CP2Server('', '')
        server.payload_bits = '11'

        # Act
        server.set_current_stratum()
        server.set_current_stratum()

        # Assert
        self.assertEqual(CP2_ONE_BITS[1], server.current_stratum)

    def test_set_current_stratum_one_different_set_accordingly(self):
        # Arrange
        server = CP2Server('', '')
        server.payload_bits = '01'

        # Act
        server.set_current_stratum()
        server.set_current_stratum()

        # Assert
        self.assertEqual(CP2_ONE_BITS[0], server.current_stratum)

    def test_set_current_stratum_zero_different_set_accordingly(self):
        # Arrange
        server = CP2Server('', '')
        server.payload_bits = '10'

        # Act
        server.set_current_stratum()
        server.set_current_stratum()

        # Assert
        self.assertEqual(CP2_ZERO_BITS[0], server.current_stratum)


if __name__ == '__main__':
    unittest.main()
