import unittest
from datetime import datetime

import ntplib
from scapy.layers.ntp import NTP

from cp3_package import CP3Package, CP3Mode
from ntp_utils import init_ntp_pck
from test_constants import ZEROS_64


class CP3PackageTests(unittest.TestCase):

    def test_get_cp3_mode_pck_has_no_specific_year_none_mode_returned(self):
        # Arrange
        pck = CP3Package()
        pck.set_transmit_timestamp(ZEROS_64)

        # Act
        result = pck.get_cp3_mode()

        # Assert
        self.assertEqual(result, CP3Mode.NONE)

    def test_get_cp3_mode_pck_has_year_1995_mode_1_returned(self):
        # Arrange
        ntp_timestamp = ntplib.system_to_ntp_time(datetime.now().replace(year=1995).timestamp())
        ntp_pck = NTP()
        ntp_pck.sent = ntp_timestamp
        pck = CP3Package(ntp_pck=ntp_pck)

        # Act
        result = pck.get_cp3_mode()

        # Assert
        self.assertEqual(result, CP3Mode.PCK_1)

    def test_get_cp3_mode_pck_has_year_2000_mode_2_returned(self):
        # Arrange
        ntp_timestamp = ntplib.system_to_ntp_time(datetime.now().replace(year=2000).timestamp())
        ntp_pck = NTP()
        ntp_pck.sent = ntp_timestamp
        pck = CP3Package(ntp_pck=ntp_pck)

        # Act
        result = pck.get_cp3_mode()

        # Assert
        self.assertEqual(result, CP3Mode.PCK_2)

    def test_get_cp3_mode_pck_is_none_mode_returned(self):
        # Arrange
        pck = CP3Package()

        # Act
        result = pck.get_cp3_mode()

        # Assert
        self.assertEqual(result, CP3Mode.NONE)

    def test_set_cp3_mode_1_correct_datetime_set(self):
        # Arrange
        pck = CP3Package(ntp_pck=init_ntp_pck())

        # Act
        pck.set_cp3_mode_1()

        # Assert
        time = datetime.fromtimestamp(ntplib.ntp_to_system_time(pck.ntp().sent)).year
        self.assertEqual(time, 1995)

    def test_set_cp3_mode_2_correct_datetime_set(self):
        # Arrange
        pck = CP3Package(ntp_pck=init_ntp_pck())

        # Act
        pck.set_cp3_mode_2()

        # Assert
        time = datetime.fromtimestamp(ntplib.ntp_to_system_time(pck.ntp().sent)).year
        self.assertEqual(time, 2000)


if __name__ == '__main__':
    unittest.main()
