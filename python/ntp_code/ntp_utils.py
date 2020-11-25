import logging
import time
from decimal import Decimal
import random

from scapy.layers.ntp import NTP, NTPHeader

from ntp_raw import RawNTP

_max_16bit = 65536
_max_32bit = 4294967295
_max_64bit = 18446744073709551616
__log = logging.getLogger()


def bit_to_short(bits: str) -> float:
    """
    Converts a bit string in the format '01' to a float, representing the NTP short format (32bit)
    :param bits:
    :return:
    """
    ints = int(bits, 2)
    result = ints / _max_16bit
    return result


def bit_to_long(bits: str) -> Decimal:
    """
    Converts a bit string in the format '01' to a float, representing the NTP long format (64bit)
    """
    ints = int(bits, 2)
    result = Decimal(ints) / Decimal(_max_32bit)
    return result


def extract_64timestamp_fraction(bits: str) -> str:
    """
    Extracts the fraction digits from a 64bit timestamp.
    :param bits:
    :return:
    """
    assert len(bits) == 64
    bits = bits[32:64]
    # __log.info(bits)
    ints = int(bits, 2)
    result = ints / _max_32bit
    result = int(result * 1000000000)
    result = str(result)
    while len(result) < 9:
        result = '0' + result
    return result


def ntp_time_now() -> float:
    """
    :return: The current system time in milliseconds in NTP format.
    """
    ntp_basetime = 2208988800
    return time.time() + ntp_basetime


def init_ntp_pck(num_of_digits_to_fill_up: int = 12) -> NTP:
    """
    Creates a new NTP package, fills all 4 64 bit timestamps with the current time and fills up the last bits
    with random values, since they are set to 0 by Scapy
    :param num_of_digits_to_fill_up: The amount of digits to fill up.
    :return: The newly created NTP package
    """
    ntp = NTP()
    ntp.ref = ntp_time_now()
    ntp.sent = ntp_time_now()
    ntp.orig = ntp_time_now()
    ntp.recv = ntp_time_now()
    raw_ntp = RawNTP(ntp)

    f_ref = raw_ntp.reference_timestamp()
    f_trans = raw_ntp.transmit_timestamp()
    f_orig = raw_ntp.origin_timestamp()
    f_recv = raw_ntp.receive_timestamp()

    for i in range(num_of_digits_to_fill_up):
        pos = 64 - i
        f_ref = f_ref[:pos - 1] + str(random.randint(0, 1)) + f_ref[pos:]
        f_trans = f_trans[:pos - 1] + str(random.randint(0, 1)) + f_trans[pos:]
        f_orig = f_orig[:pos - 1] + str(random.randint(0, 1)) + f_orig[pos:]
        f_recv = f_recv[:pos - 1] + str(random.randint(0, 1)) + f_recv[pos:]

    assert len(f_ref) == 64
    assert len(f_trans) == 64
    assert len(f_orig) == 64
    assert len(f_recv) == 64

    raw_ntp.set_reference_timestamp(f_ref)
    raw_ntp.set_transmit_timestamp(f_trans)
    raw_ntp.set_origin_timestamp(f_orig)
    raw_ntp.set_receive_timestamp(f_recv)
    ntp = raw_ntp.ntp()
    return ntp


def init_ntp_client_pck(num_of_digits_to_fill_up: int = 12):
    """
    Creates a new NTP package, fills only the transmit 64 bit timestamps with the current time and fills up the last
    bits with random values, since they are set to 0 by Scapy
    :param num_of_digits_to_fill_up: The amount of digits to fill up.
    :return: The newly created NTP package
    """
    ntp = NTP()
    ntp.sent = ntp_time_now()
    ntp.ref = 0
    ntp.orig = 0
    ntp.recv = 0
    raw_ntp = RawNTP(ntp)
    f_trans = raw_ntp.transmit_timestamp()

    for i in range(num_of_digits_to_fill_up):
        pos = 64 - i
        f_trans = f_trans[:pos - 1] + str(random.randint(0, 1)) + f_trans[pos:]

    assert len(f_trans) == 64

    raw_ntp.set_transmit_timestamp(f_trans)
    ntp = raw_ntp.ntp()
    return ntp


def bit_to_ascii(bit_string: str) -> str:
    """
    Converts a given string of bits to a string of ASCII characters.
    :param bit_string: a string of 0s and 1s, dividable by 8.
    :return:
    """
    assert len(bit_string) % 8 == 0

    n = int(bit_string, 2)
    result = n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()
    return result


def ascii_to_bit(ascii_string: str) -> str:
    """
    Converts a given string of ASCII chars to a string of bits.
    :param ascii_string:
    :return:
    """
    result = bin(int.from_bytes(ascii_string.encode(), 'big'))
    result = result[2:] # We don't want this '0b' at the beginning.
    while len(result) % 8 != 0:
        result = '0' + result
    return result
