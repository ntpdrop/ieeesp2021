import unittest

from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTP

from cp3_interceptor import CP3Interceptor


class CP3InterceptorTests(unittest.TestCase):

    def test_check_pck_pck_is_No_NTP_False_Returned(self):
        # Arrange
        interceptor = CP3Interceptor('','')

        # Act
        result = interceptor.check_pck(IP())

        # Assert
        self.assertFalse(result)

    def test_check_pck_has_no_matching_ip_False_Returned(self):
        # Arrange
        interceptor = CP3Interceptor('3.3.3.3', '4.4.4.4')
        pck = IP(dst='1.1.1.1',src='2.2.2.2') / UDP() / NTP()

        # Act
        result = interceptor.check_pck(pck)

        # Assert
        self.assertFalse(result)

    def test_check_pck_has_matching_ip_True_Returned(self):
        # Arrange
        interceptor = CP3Interceptor('3.3.3.3', '4.4.4.4')
        pck = IP(dst='1.1.1.1', src='3.3.3.3') / UDP() / NTP()

        # Act
        result = interceptor.check_pck(pck)

        # Assert
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()