from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTP
from scapy.packet import Packet
from scapy.sendrecv import sniff, sr1, send

from ntp_utils import ntp_time_now


class NTPInterceptor:
    def intercept_req(self, pck):
        return pck

    def intercept_res(self, pck):
        return pck


class NTPServer:
    """
    A scapy MITM NTP server which can respond to client requests and provide access to interceptors in order to
    implement covert channels.
    """

    def __init__(self, sniff_interface: str = 'wlp4s0', host_ip='localhost', req_interceptor=NTPInterceptor(),
                 res_interceptor=NTPInterceptor()):
        """

        :param sniff_interface:
        :param req_interceptor: a class which is called whenever an NTP package arrives at the server.
        :param res_interceptor: a class which is called whenever a NTP response is send to a client request.
        """
        super().__init__()
        self.sniff_interface = sniff_interface
        self._req_interceptor = req_interceptor
        self._res_interceptor = res_interceptor
        self._host_ip = host_ip
        self.reference_time = ntp_time_now()
        self.debug = False

    def run(self, with_response: bool = True):
        """
        Starts the sniffing for incoming NTP client packages. Note that further packages are not sniffed while
        one package is processed.
        """
        print('Starting server.... listening on interface ' + self.sniff_interface)
        while True:
            pck = self.next_ntp_packet()
            received_time = ntp_time_now()

            if pck[IP].dst != self._host_ip:
                print('This package was not meant for the server...')
                continue

            pck_ntp = pck[NTP]
            if pck_ntp.mode != 3:
                continue

            self._req_interceptor.intercept_req(pck_ntp)

            if not with_response:
                continue

            if self.debug:
                print('Got a NTP client request, creating response.')
            # ntp_resp = self._send_ntp_client_request(ntp=pck_ntp)
            response_from_server_ntp = NTP()  # ntp_resp[NTP]
            response_from_server_ntp.recv = received_time
            response_from_server_ntp.ref = self.reference_time
            # response_from_server_ntp.id = str(pck[IP].dst)
            response_from_server_ntp = self._res_interceptor.intercept_res(response_from_server_ntp)
            response = IP(dst=pck[IP].src, src=pck[IP].dst) / UDP() / response_from_server_ntp

            if self.debug:
                response.show()
            send(response)

    def next_ntp_packet(self) -> Packet:
        """
        Sniffs for the next incoming ntp package. This method is blocking
        :return: the sniffed package.
        """
        results = sniff(filter='udp and port 123', count=1, iface=self.sniff_interface)
        pck = (results[0])
        if self.debug:
            pck.show()
        return pck

    def _send_ntp_client_request(self, dst='pool.ntp.org', ntp=NTP()) -> Packet:
        pck = IP(dst=dst) / UDP() / ntp
        if self.debug:
            pck.show()
        pck = sr1(pck)
        if self.debug:
            pck.show()
        return pck


if __name__ == '__main__':
    class StratumInterceptor(NTPInterceptor):
        def intercept_res(self, pck):
            pck.stratum = 2
            return pck


    interceptor = StratumInterceptor()
    server = NTPServer(res_interceptor=interceptor, host_ip='192.168.0.4')
    server.run()
