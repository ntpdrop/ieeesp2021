import logging
from datetime import datetime
from enum import Enum

import ntplib
from scapy.layers.ntp import NTPHeader

from ntp_raw import RawNTP

_PCK_1_YEAR = 1995
_PCK_2_YEAR = 2000


class CP3Mode(Enum):
    """
    In CP3 an NTP package can be marked as a type 1, or 2 package or as nothing. This class represents the different
    types.
    """
    NONE = 0,
    PCK_1 = 1,
    PCK_2 = 2,

    @staticmethod
    def from_year(year: int):
        if year == _PCK_1_YEAR:
            return CP3Mode.PCK_1
        elif year == _PCK_2_YEAR:
            return CP3Mode.PCK_2
        else:
            return CP3Mode.NONE


class CP3Package(RawNTP):

    def __init__(self, ntp_pck: NTPHeader = NTPHeader(), log: logging.Logger = logging.getLogger('CP3Package-Logger')):
        """
            A child of RawNTP which adds functionality in order to extract and insert CP3 specific data into
            and from a NTPRaw package.
        """
        super().__init__(ntp_pck)
        self.log: logging.Logger = log

    def _extract_transmit_year(self) -> int:
        year = datetime.fromtimestamp(ntplib.ntp_to_system_time(self.ntp().sent)).year
        return year

    def get_cp3_mode(self) -> CP3Mode:
        transmit_year = self._extract_transmit_year()
        if transmit_year is None or transmit_year == 0:
            return CP3Mode.NONE
        return CP3Mode.from_year(transmit_year)

    def extract_payload(self) -> str:
        return self.origin_timestamp()[0:32] + self.receive_timestamp()[0:32]

    def add_payload(self,payload_bits):
        self.set_origin_timestamp(payload_bits[0:32]+self.origin_timestamp()[32:64])
        self.set_receive_timestamp(payload_bits[32:64]+self.receive_timestamp()[32:64])

    def set_cp3_mode_1(self):
        self._set_cp3_mode(_PCK_1_YEAR)

    def set_cp3_mode_2(self):
        self._set_cp3_mode(_PCK_2_YEAR)

    def _set_cp3_mode(self,year:int):
        ntp = self.ntp()
        time = ntplib.system_to_ntp_time(datetime.fromtimestamp(ntplib.ntp_to_system_time(ntp.sent))
                                  .replace(year=year).timestamp())
        ntp.sent = time
        raw = RawNTP(ntp)
        self.set_transmit_timestamp(raw.transmit_timestamp())