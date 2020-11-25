import unittest
from datetime import datetime

import ntplib
from scapy.layers.ntp import NTP

from cp3_handler import CP3Handler
from cp3_package import CP3Package
from ntp_mode import NTPMode
from ntp_raw import RawNTP
from ntp_utils import init_ntp_pck


class CP3HandlerTests(unittest.TestCase):

    def test_restore_pck_client_pck_with_changed_year(self):
        # Arrange
        client = CP3Handler('')
        pck = init_ntp_pck()
        pck.sent = ntplib.system_to_ntp_time(datetime
                                             .fromtimestamp(ntplib.ntp_to_system_time(pck.sent))
                                             .replace(year=2006).timestamp())

        # Act
        result_pck = client.restore_pck(CP3Package(ntp_pck=pck))

        # Assert
        self.assertEqual(result_pck.ref, 0)
        self.assertEqual(result_pck.recv, 0)
        self.assertEqual(result_pck.orig, 0)
        self.assertEqual(datetime.fromtimestamp(ntplib.ntp_to_system_time(result_pck.sent)).year, datetime.now().year)

    def test_restore_pck_server_pck_other_timestamps_filled_with_send(self):
        # Arrange
        client = CP3Handler('')
        pck = CP3Package()
        first_32 = '11111111111111111111000000011111'
        origin_last_32 = '11111111111110011110111111111111'
        received_last_32 = '11111111110111011110111111111111'
        transmit = '1111111111111111111111111111111111111111111111111111111111111111'
        pck.set_origin_timestamp(first_32 + origin_last_32)
        pck.set_receive_timestamp(first_32 + received_last_32)
        pck.set_transmit_timestamp(transmit)
        pck.set_mode(NTPMode.to_bit_string(NTPMode.SERVER))

        # Act
        result_pck = RawNTP(client.restore_pck(pck))

        # Assert
        self.assertNotEqual(result_pck.transmit_timestamp(), transmit)
        self.assertEqual(result_pck.origin_timestamp()[32:64], origin_last_32)
        self.assertEqual(result_pck.receive_timestamp()[32:64], received_last_32)
        self.assertEqual(result_pck.origin_timestamp()[0:32], result_pck.origin_timestamp()[0:32])
        self.assertEqual(result_pck.receive_timestamp()[0:32], result_pck.origin_timestamp()[0:32])
        self.assertEqual(datetime.fromtimestamp(ntplib
                                                .ntp_to_system_time(result_pck.ntp().sent)).year, datetime.now().year)

    def test_handle_incoming_pck_is_not_marked_no_action_performed(self):
        # Arrange
        client = CP3Handler('')
        pck = CP3Package()

        # Act
        client.read_incoming_pck(pck)

        # Assert
        self.assertEqual('', client.msg)

    def test_handle_incoming_pck_is_marked_with_1_msg_added(self):
        # Arrange
        client = CP3Handler('')
        ntp_timestamp = ntplib.system_to_ntp_time(datetime.now().replace(year=1995).timestamp())
        ntp_pck = NTP()
        ntp_pck.sent = ntp_timestamp
        pck = CP3Package(ntp_pck=ntp_pck)
        origin_first_32 = '11111111111110011110111111111111'
        received_first_32 = '11111110111111011110111111111111'
        last_32 = '11111111111111111111111111111111'
        pck.set_origin_timestamp(origin_first_32 + last_32)
        pck.set_receive_timestamp(received_first_32 + last_32)

        # Act
        client.read_incoming_pck(pck)

        # Assert
        self.assertEqual(origin_first_32 + received_first_32, client.msg)


if __name__ == '__main__':
    unittest.main()
