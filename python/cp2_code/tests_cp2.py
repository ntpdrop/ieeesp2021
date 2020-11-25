import unittest

from cp2_client import CP2Client


class CP2Tests(unittest.TestCase):

    def test_post_construction_correctly(self):
        # Arrange
        client = CP2Client()

        # Assert
        self.assertEqual('', client.msg_bit_string)
        self.assertEqual(0, client.last_stratum)

    def test_complete_msg_correctly_filled(self):
        # Arrange
        client = CP2Client()

        # Act
        client.handle_stratum(5)
        client.handle_stratum(6)
        client.handle_stratum(7)
        client.handle_stratum(8)
        client.handle_stratum(10)
        client.handle_stratum(11)
        client.handle_stratum(12)
        client.handle_stratum(13)

        # Assert
        self.assertEqual(client.complete_msg, '00001111')

    def test_msg_reset(self):
        # Arrange
        client = CP2Client()

        # Act
        client.handle_stratum(6)
        client.handle_stratum(11)
        self.assertEqual(client.msg_bit_string, '01')  # Pre-Assert
        client.handle_stratum(1)

        # Assert
        self.assertEqual(client.msg_bit_string, '')
        self.assertEqual(client.last_stratum, 0)

    def test_msg_following_stratum_no_new_bits(self):
        # Arrange
        client = CP2Client()

        # Act
        client.handle_stratum(7)
        client.handle_stratum(7)
        client.handle_stratum(7)
        client.handle_stratum(7)

        # Assert
        self.assertEqual(client.msg_bit_string, '0')
        self.assertEqual(client.last_stratum, 7)


if __name__ == '__main__':
    unittest.main()
