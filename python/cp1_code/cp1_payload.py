import hashlib
import logging

from bitstring import BitArray

from cp1_function_code import CP1FunctionCode


class CP1Payload:
    __CHECKSUM_LENGTH = 5
    """
    Represents a CP1 payload, a 128 bit field, represented by a function code, a checksum and a payload.
    """

    def __init__(self, function_code: CP1FunctionCode, payload):
        self._function_code = CP1FunctionCode.to_bit_string(function_code)
        self._payload = payload
        self._checksum = self._generate_checksum()
        self.complete_payload = self._function_code + self._checksum + self._payload
        self.log = logging.getLogger('default-logger')
        self.log.debug('Length of complete payload: ' + str(len(self.complete_payload)))

        assert len(self.complete_payload) == 128

    def _generate_checksum(self):
        combined_str = (self._function_code + self._payload).encode('ASCII')
        hash_digest = hashlib.md5(combined_str).digest()
        bin_value = BitArray(bytes=hash_digest).bin
        bin_value = bin_value[0:CP1Payload.__CHECKSUM_LENGTH]
        return bin_value
