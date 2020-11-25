from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTP
from scapy.packet import Packet
from scapy.sendrecv import sniff, send, sr1


class ScapyWrapper:
    """
    A wrapper class for scapy functionality.
    """

    def next_ntp_packet(self, sniff_interface) -> Packet:
        """
        Sniffs for the next incoming ntp package. This method is blocking
        :return: the sniffed package (with OSI layer 3 and 4 still attached).
        """
        results = sniff(filter='udp and port 123', count=1, iface=sniff_interface)
        pck = (results[0])
        return pck

    def next_ntp_packet_for_target(self, sniff_interface: str, target_ip_addr: str) -> Packet:
        """
        Sniffs for the next incoming ntp package with was send to the specific ip addr. This method is blocking
        :return: the sniffed package (with OSI layer 3 and 4 still attached).
        """
        results = sniff(filter='udp and dst port 123 and dst ' + str(target_ip_addr), count=1, iface=sniff_interface)
        pck = (results[0])
        return pck

    def send(self, pck: Packet):
        """
        Sends the given Scapy Packet without waiting for a response.
        :param pck:
        :return:
        """
        send(pck)

    def get_upstream_ntp(self, server_addr: str = 'pool.ntp.org') -> Packet:
        request = IP(dst=server_addr) / UDP() / NTP()
        response = sr1(request, timeout=2)
        return response

    def restore_ntp_mitm_pck(self, pck: Packet, sport: int, dst_ip: str):
        """
        Prepares a IP()/UDP() packet which was changend by a MITM to be send back to the original sender.
        """
        pck = IP(src=pck[IP].dst, dst=dst_ip) / UDP(dport=sport, sport=123) / pck[NTP]
        return pck
        # pck[UDP].dport = sport
        # pck[UDP].sport = 123
        # pck[IP].src = pck[IP].dst
        # pck[IP].dst = dst_ip
