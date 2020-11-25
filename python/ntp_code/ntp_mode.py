from enum import Enum


class NTPMode(Enum):
    """
    An Enum representation of the different ntp protocol modes
    """
    SYMMETRIC_ACTIVE = 1
    SYMMETRIC_PASSIVE = 2
    CLIENT = 3
    SERVER = 4
    BROADCAST_SERVER = 5
    BROADCAST_CLIENT = 6

    @staticmethod
    def to_bit_string(code) -> str:
        if code is NTPMode.CLIENT:
            return "011"
        elif code is NTPMode.SERVER:
            return "100"
        elif code is NTPMode.BROADCAST_SERVER:
            return "101"
        else:
            raise ValueError("No valid enum value supported: " + str(code))

    @staticmethod
    def from_bit_string(bit_string):
        if bit_string == '011':
            return NTPMode.CLIENT
        elif bit_string == '100':
            return NTPMode.SERVER
        elif bit_string == '101':
            return NTPMode.BROADCAST_SERVER
        else:
            raise ValueError("No valid bit string supported: " + str(bit_string))