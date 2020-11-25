import unittest

from cp1_function_code import CP1FunctionCode
from cp1_payload import CP1Payload
from test_constants import PAYLOAD_BITS_120


class CP1PayloadTests(unittest.TestCase):

    def test_payload_correct_init(self):
        # Act
        payload = CP1Payload(CP1FunctionCode.MSG_ONE, PAYLOAD_BITS_120)

        # Assert
        self.assertEqual(len(payload.complete_payload), 128)


if __name__ == '__main__':
    unittest.main()
