from enum import Enum


class CP1FunctionCode(Enum):
    """
    Represents a 3-bit function code of a the CP1 protocol.
    """
    RESERVED = 0
    ACK = 1
    ERROR = 2
    MSG_ONE = 3
    MSG_ACK = 4
    KEY_UPDATE = 5
    ADDR_UPDATE = 6
    CARRIER_UPDATE = 7

    @staticmethod
    def to_bit_string(code):
        if code is CP1FunctionCode.MSG_ONE:
            return "011"
        else:
            raise ValueError("No valid enum value supported: " + str(code))
