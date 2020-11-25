import ntplib
from scapy.all import rdpcap
from scapy.layers.ntp import NTP
from datetime import datetime

from ntp_raw import RawNTP
from ntp_utils import extract_64timestamp_fraction


def difference_detector():
    file_path = '/home/shroud/workbench/MasterThesis/results/operating_system_default/2020_08_19_NTPd_2_Filtered.pcap'
    packets = rdpcap(file_path)
    ntp_packets = []
    x = 0
    counter = 0
    for packet in packets:
        counter += 1
        ntp_pck = packet[NTP]
        ntp_pck_raw = RawNTP(ntp_pck)
        if (ntp_pck_raw.transmit_timestamp()[0:32] != ntp_pck_raw.receive_timestamp()[0:32]) \
                or (ntp_pck_raw.origin_timestamp()[0:32] != ntp_pck_raw.receive_timestamp()[0:32]):
            x += 1
            print("Packet with differences detected, nr.: " + str(counter))
        ntp_packets.append(ntp_pck)
    print("Total amount of differences: " + str(x))


def read_transmit_values_raw(file_path):
    packets = rdpcap(file_path)
    bin_values = []
    for packet in packets:
        ntp_pck = packet[NTP]
        ntp_pck_raw = RawNTP(ntp_pck)
        bin_values.append(ntp_pck_raw.transmit_timestamp()[32:64])
    return bin_values


def read_transmit_values(file_path):
    packets = rdpcap(file_path)
    values = []
    for packet in packets:
        ntp_pck = packet[NTP]
        raw_ntp = RawNTP(ntp_pck)
        trans_digits = extract_64timestamp_fraction(raw_ntp.transmit_timestamp())
        values.append(trans_digits)
    return values
