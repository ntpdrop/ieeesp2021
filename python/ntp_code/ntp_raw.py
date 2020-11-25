import logging
from enum import Enum

from bitstring import BitArray
from scapy.layers.ntp import NTPHeader, NTP


class RawNTP:
    """
    A pure bit representation of NTP packages. Provides methods to access the bit masks of the different NTP fields.
    """

    def __init__(self, ntp_pck: NTP = NTPHeader()):
        self._raw = RawNTP.__pck_to_bits(ntp_pck)
        self._orig = ntp_pck
        self.log = logging.getLogger('default_logger')

    def ntp(self) -> NTP:
        """
        :return: creates a scapy.NTP package from this raw package representation.
        """
        raw = BitArray(bin=self._raw).bytes
        ntp = NTP(raw)
        return ntp

    def __str__(self):
        x = ''
        for i in range(len(self._raw)):
            if i % 8 == 0:
                x += ' '
            x += self._raw[i]
        return 'Raw bits: ' + x

    def li(self):
        x = self._raw[0:2]

        return x

    def set_li(self, value):
        assert len(value) == 2
        self._raw = value + self._raw[2:]

    def vn(self):
        x = self._raw[2:5]

        return x

    def set_vn(self, value):
        assert len(value) == 3
        self._raw = self._raw[0:2] + value + self._raw[5:]

    def mode(self):
        x = self._raw[5:8]
        return x

    def set_mode(self, value):
        assert len(value) == 3
        self._raw = self._raw[0:5] + value + self._raw[8:]

    def stratum(self):
        x = self._raw[8:16]
        return x

    def poll(self):
        x = self._raw[16:24]
        return x

    def precision(self):
        x = self._raw[24:32]
        return x

    def root_delay(self):
        x = self._raw[32:64]
        return x

    def root_dispersion(self):
        x = self._raw[64:96]
        return x

    def reference_id(self):
        x = self._raw[96:128]
        return x

    def reference_timestamp(self):
        x = self._raw[128:192]
        return x

    def set_reference_timestamp(self, value: str):
        assert len(value) == 64
        x_raw = self._raw
        self._raw = self._raw[:128] + value + x_raw[192:]

    def origin_timestamp(self):
        x = self._raw[192:256]
        return x

    def set_origin_timestamp(self, value: str):
        assert len(value) == 64
        x_raw = self._raw
        self._raw = self._raw[:192] + value + x_raw[256:]

    def receive_timestamp(self):
        x = self._raw[256:320]
        return x

    def set_receive_timestamp(self, value: str):
        assert len(value) == 64
        x_raw = self._raw
        self._raw = self._raw[:256] + value + x_raw[320:]

    def transmit_timestamp(self):
        x = self._raw[320:384]
        return x

    def set_transmit_timestamp(self, value: str):
        assert len(value) == 64
        self._raw = self._raw[:320] + value

    def get_field(self, field_name) -> str:
        if field_name is NTPField.LI:
            return self.li()
        elif field_name is NTPField.VN:
            return self.vn()
        elif field_name is NTPField.ORIGIN_TIMESTAMP:
            return self.origin_timestamp()
        elif field_name is NTPField.RECEIVE_TIMESTAMP:
            return self.receive_timestamp()
        elif field_name is NTPField.REFERENCE_TIMESTAMP:
            return self.reference_timestamp()
        elif field_name is NTPField.TRANSMIT_TIMESTAMP:
            return self.transmit_timestamp()
        else:
            raise Exception('Field type ' + str(field_name) + ' not supported')

    def set_field(self, value, field_name):
        if field_name is NTPField.LI:
            self.set_li(value)
        elif field_name is NTPField.VN:
            self.set_vn(value)
        elif field_name is NTPField.RECEIVE_TIMESTAMP:
            self.set_receive_timestamp(value)
        elif field_name is NTPField.TRANSMIT_TIMESTAMP:
            self.set_transmit_timestamp(value)
        else:
            raise Exception('Field type ' + str(field_name) + ' not supported')

    @staticmethod
    def __pck_to_bits(pck) -> str:
        """
        Transforms a scpay package into its bit representation.
        :param pck: the package to transform
        :return: a bit representation of the packages content
        """
        orig_pck_len = len(pck) * 8
        pck = bytes(pck).hex()
        pck = bin(int(pck, 16))[2:]
        pck_len = len(pck)
        for i in range(orig_pck_len - pck_len):
            # Add the leading 0's, which were lost during the int transformation
            pck = '0' + pck
        return pck


class NTPField(Enum):
    """
    A enumeration of all field types (names) in an NTPv4 package.
    """
    LI = 1
    VN = 2
    MODE = 3
    STRATUM = 4
    POLL = 5
    PRECISION = 6
    ROOT_DELAY = 7
    ROOT_DISPERSION = 8
    REFERENCE_ID = 9
    REFERENCE_TIMESTAMP = 10
    ORIGIN_TIMESTAMP = 11
    RECEIVE_TIMESTAMP = 12
    TRANSMIT_TIMESTAMP = 13

    def length(self) -> int:
        """
        :return: the size of the field in bits.
        """
        if self is NTPField.REFERENCE_TIMESTAMP or self is NTPField.ORIGIN_TIMESTAMP \
                or self is NTPField.RECEIVE_TIMESTAMP or self is NTPField.TRANSMIT_TIMESTAMP:
            return 64
        raise ValueError("Not defined/implemented yet!")
