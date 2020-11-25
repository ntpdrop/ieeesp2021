import unittest

from cp1_package import CP1Package
from cp1_session import CP1Session


class CP1SessionTests(unittest.TestCase):

    def test_is_complete_payload_not_complete_false_returned(self):
        # Arrange
        session = CP1Session()
        pck = CP1Package()
        pck.add_payload('1010101010101010')
        session.next_pck(pck)

        # Act
        result = session.is_complete()

        # Assert
        self.assertFalse(result)

    def test_is_complete_payload_is_complete_true_returned(self):
        # Arrange
        session = CP1Session()
        pck = CP1Package()
        pck.add_payload('1010101010101010')
        for x in range(8):
            session.next_pck(pck)

        # Act
        result = session.is_complete()

        # Assert
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
