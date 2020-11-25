import logging

from scapy.layers.ntp import NTPHeader

from ntp_raw import RawNTP, NTPField


class CP1Package(RawNTP):
    """
    A child of RawNTP which adds functionality in order to extract and insert CP1 specific data into
    and from a NTPRaw package
    """

    def __init__(self, ntp_pck: NTPHeader = NTPHeader()):
        super().__init__(ntp_pck)
        self.log = logging.getLogger('default_logger')

    def hash_nonce(self) -> str:
        """
        :return: he 32 bit nonce for the address in binary format.
        """
        second_part = self.transmit_timestamp()[0:32]
        return second_part

    def aes_nonce_bits(self) -> str:
        """
        :return: the 64 bit nonce for the AES-ECB key in binary format.
        """
        second_part_transmit = self.transmit_timestamp()[0:32]
        second_part_reference = self.reference_timestamp()[0:32]
        combined = second_part_transmit + second_part_reference
        return combined

    def add_payload(self, payload, pos: int = 40, field: NTPField = NTPField.TRANSMIT_TIMESTAMP):
        """
        Adds the CP1 payload to the CP1 package in order to send it.
        :param payload:
        :param pos:
        :param field:
        :return:
        """
        field_value = self.get_field(field)
        field_value = field_value[:pos] + payload + field_value[pos + len(payload):]

        assert len(field_value) == 64  # This assertion is only helpful for one of the 4 64 bit timestamps.

        self.set_field(field_value, field)

    def extract_payload(self, pos: int = 40, payload_size: int = 16, field: NTPField = NTPField.TRANSMIT_TIMESTAMP):
        """
        Retrieves the complete payload from this CP1 package.
        :param payload_size:
        :param pos:
        :param field:
        :return:
        """
        field_value = self.get_field(field)[pos:pos + payload_size]

        self.log.debug("Extracted payload: " + str(field_value))

        return field_value
