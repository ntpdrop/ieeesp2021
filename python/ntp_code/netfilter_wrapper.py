import logging

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP


class NetfilterWrapper:

    def __init__(self, pre_check, handle_pck, log: logging.Logger = logging.getLogger('NetfilterWrapper-Logger')):
        """
        A wrapper for NetfilterQueue functions. Provides some possibilities to bind outside functions to check
        and manipulate incoming functions.
        :param log:
        :param pre_check: A function which should check whether the given Scapy packet is meant for the interceptor.
        this method should return False in case the Packet is not meant for the handler.
        :param handle_pck: A function which can manipulate the given Scapy packet and should return a new one.
        """
        self.log = log
        self.nfqueue: NetfilterQueue = None
        self.pre_check = pre_check
        self.handle_pck = handle_pck

    def bind(self, filter_number: int = 0):
        self.log.info('Bind to Netfilter Queue Nr.: ' + str(filter_number))
        self.nfqueue = NetfilterQueue()
        self.nfqueue.bind(filter_number, self.modify)

    def modify(self, packet):
        pkt = IP(packet.get_payload())
        self.log.debug("Netfilter pkt received.")

        if not self.pre_check(pkt):
            self.log.debug('Pre check failed!')
            packet.accept()
            return

        manipulated_pck = self.handle_pck(pkt)
        packet.set_payload(manipulated_pck.__bytes__())
        packet.accept()

    def run(self):
        self.nfqueue.run()