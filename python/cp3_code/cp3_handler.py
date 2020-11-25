import logging
from datetime import datetime

import ntplib
from bitstring import BitArray
from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTP

from cp3_package import CP3Package, CP3Mode
from ntp_crypto import decrypt_bits
from ntp_mode import NTPMode
from scapy_wrapper import ScapyWrapper


class CP3Handler:

    def __init__(self, static_key_bits: str, log: logging.Logger = logging.getLogger('CP3Handler-logger')):
        """
        The core of every CP3 server and client. Provides functions to work with packages and process them.
        :param static_key_bits:
        :param log:
        """
        self.log = log
        self.static_key_bits = static_key_bits
        self.msg: str = ''
        self.scappy_wrapper = ScapyWrapper()

    def read_incoming_pck(self, pck: CP3Package) -> bool:
        mode = pck.get_cp3_mode()
        if mode is CP3Mode.PCK_1:
            self.msg = pck.extract_payload()
            self.log.debug("CP3_Mode_1 package received and payload set: " + self.msg)
            return True
        elif mode is CP3Mode.PCK_2:
            self.msg += pck.extract_payload()
            self.log.debug("CP3_Mode_1 package received and complete payload now: " + self.msg)
            decrypted_bytes = decrypt_bits(self.msg, BitArray(bin=self.static_key_bits).bytes)
            self.log.info("Decrypted payload: " + str(decrypted_bytes))
            return True
        else:
            self.log.debug("Package had no corresponding CP3 mode")
            return False

    def create_cp3_pck(self, payload_bits: str, cp3_mode: CP3Mode, ntp_mode: NTPMode) -> NTP:
        assert len(payload_bits) == 64

        pck = CP3Package()
        pck.add_payload(payload_bits)

        if cp3_mode is CP3Mode.PCK_1:
            pck.set_cp3_mode_1()
        elif cp3_mode is CP3Mode.PCK_2:
            pck.set_cp3_mode_2()
        pck.set_mode(NTPMode.to_bit_string(ntp_mode))

        return pck.ntp()

    def _send_cp3_pck(self, payload_bits: str, ip_addr: str, cp3_mode: CP3Mode, ntp_mode: NTPMode):
        ntp = self.create_cp3_pck(payload_bits, cp3_mode, ntp_mode)
        self.log.debug("Sending of NTP Mode " + str(cp3_mode) + " package with payload: "
                       + payload_bits + " to " + str(ip_addr))
        self.scappy_wrapper.send(IP(dst=ip_addr) / UDP() / ntp)


    def send_pck_1(self, payload_bits: str, ip_addr: str, ntp_mode: NTPMode = NTPMode.CLIENT):
        self._send_cp3_pck(payload_bits, ip_addr, CP3Mode.PCK_1, ntp_mode)

    def send_pck_2(self, payload_bits: str, ip_addr: str, ntp_mode: NTPMode = NTPMode.CLIENT):
        self._send_cp3_pck(payload_bits, ip_addr, CP3Mode.PCK_2, ntp_mode)

    def __restore_ntp_pck(self, ntp: NTP) -> NTP:
        self.log.debug('Send timestamp for reconstruction: ' + str(ntp.sent))
        sent_time_stamp = datetime.fromtimestamp(ntplib.ntp_to_system_time(ntp.sent))
        sent_time_stamp = sent_time_stamp.replace(year=datetime.now().year)
        sent_time_stamp_as_ntp = ntplib.system_to_ntp_time(sent_time_stamp.timestamp())
        ntp.sent = sent_time_stamp_as_ntp
        self.log.debug('Send timestamp after reconstruction: ' + str(ntp.sent))
        pck = CP3Package(ntp)


        if NTPMode.from_bit_string(pck.mode()) is NTPMode.CLIENT:
            self.log.debug("Restored in Client mode")
            ntp.ref = 0
            ntp.orig = 0
            ntp.recv = 0
        if NTPMode.from_bit_string(pck.mode()) is NTPMode.SERVER \
                or NTPMode.from_bit_string(pck.mode()) is NTPMode.BROADCAST_SERVER:
            self.log.debug("Restored in Server mode")
            origin_last_32 = pck.origin_timestamp()[32:64]
            received_last_32 = pck.receive_timestamp()[32:64]
            transmit_first_32 = pck.origin_timestamp()[0:32]

            pck.set_origin_timestamp(transmit_first_32 + origin_last_32)
            pck.set_receive_timestamp(transmit_first_32 + received_last_32)
            ntp = pck.ntp()
        self.log.debug("Reconstruction complete.")
        #ntp.show()
        return ntp

    def restore_pck(self, pck: CP3Package) -> NTP:
        """
        Restores the original values of the given CP3 packages, depending on the NTP mode.
        :param pck:
        :return:
        """
        ntp = pck.ntp()
        return self.__restore_ntp_pck(ntp)
