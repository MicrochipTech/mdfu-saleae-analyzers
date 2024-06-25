"""
Saleae high level analyzer for MDFU serial transport
"""
from abc import ABC, abstractmethod
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting #pylint: disable=import-error
from mdfu import MdfuCmdPacket, MdfuStatusPacket, MdfuStatusInvalidError, MdfuCmdNotSupportedError

FRAME_START_CODE = 0x56
FRAME_END_CODE = 0x9E
ESCAPE_SEQ_CODE = 0xCC
FRAME_START_ESC_SEQ = bytes([ESCAPE_SEQ_CODE, ~FRAME_START_CODE & 0xff])
FRAME_END_ESC_SEQ = bytes([ESCAPE_SEQ_CODE, ~FRAME_END_CODE & 0xff])
ESCAPE_SEQ_ESC_SEQ = bytes([ESCAPE_SEQ_CODE, ~ESCAPE_SEQ_CODE & 0xff])

class Frame():
    """UART transport frame
    
    frame = <FRAME_START_CODE> <frame payload> <FRAME_END_CODE>
    frame payload =  encode_payload(<packet> + <frame check sequence>)
    """
    def __init__(self, packet):
        """Frame initialization

        :param packet: Data to be sent in the frame
        :type packet: bytes, bytearray
        """
        self.packet = packet

    @staticmethod
    def calculate_checksum(data):
        """Calculate checksum for transport frame

        The checksum is a two's complement addition (integer addition)
        of 16-bit values in little-endian byte oder.

        :param data: Input data for checksum calculation
        :type data: Bytes like object
        :return: 16bit checksum
        :rtype: int
        """
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i + 1] << 8) | data[i]
        return (~checksum) & 0xffff

    @staticmethod
    def decode_payload(data):
        """Decode frame payload

        Replaces escape codes in payload with corresponding data.

        :param data: Raw frame payload
        :type data: bytes, bytearray
        :raises ValueError: If unknown escape sequences are detected.
        :return: Decoded payload
        :rtype: bytearray
        """
        decoded_data = bytearray()
        escape_code = False
        for byte in data:
            if not escape_code:
                if byte == ESCAPE_SEQ_CODE:
                    escape_code = True
                else:
                    decoded_data.append(byte)
            else:
                if byte == (~FRAME_START_CODE & 0xFF):
                    decoded_data.append(FRAME_START_CODE)
                elif byte == (~FRAME_END_CODE & 0xFF):
                    decoded_data.append(FRAME_END_CODE)
                elif byte == (~ESCAPE_SEQ_CODE & 0xFF):
                    decoded_data.append(ESCAPE_SEQ_CODE)
                else:
                    raise ValueError(f"Decoding of escape sequence failed: "
                            f"Got unkown escape sequence 0x{ESCAPE_SEQ_CODE:02x}{byte:02x}")
                escape_code = False
        return decoded_data

    @staticmethod
    def encode_payload(data):
        """Encode frame payload

        Inserts escape sequences for reserved codes.

        :param data: Frame payload
        :type data: bytes, bytearray
        :return: Encoded frame payload
        :rtype: bytearray
        """
        encoded_data = bytearray()
        for byte in data:
            if byte == FRAME_START_CODE:
                encoded_data += FRAME_START_ESC_SEQ
            elif byte == FRAME_END_CODE:
                encoded_data += FRAME_END_ESC_SEQ
            elif byte == ESCAPE_SEQ_CODE:
                encoded_data += ESCAPE_SEQ_ESC_SEQ
            else:
                encoded_data.append(byte)
        return encoded_data

    def to_bytes(self):
        """Convert frame into bytes

        :return: Bytes representation of the frame
        :rtype: bytes
        """
        padded_packet = self.packet + bytes(1) if len(self.packet) % 2 else self.packet
        check_sequence = self.calculate_checksum(padded_packet).to_bytes(2, byteorder="little")
        frame_payload = self.encode_payload(self.packet + check_sequence)
        frame = bytes([FRAME_START_CODE]) + frame_payload + bytes([FRAME_END_CODE])
        return frame

    @classmethod
    def from_bytes(cls, frame):
        """Create a frame from bytes

        :param frame: Frame in bytes
        :type frame: bytes, bytearray
        :return: Frame instance
        :rtype: Frame
        """
        start_code = frame[0]
        end_code = frame[-1]
        if start_code != FRAME_START_CODE:
            raise ValueError(f"Invalid frame start code: {hex(start_code)}")
        if end_code != FRAME_END_CODE:
            raise ValueError(f"Invalid frame end code: {hex(end_code)}")
        payload = cls.decode_payload(frame[1:-1])
        check_sequence = payload[-2:]
        data = payload[0:-2]
        padded_payload = data + bytes(1) if len(data) % 2 else data
        if cls.calculate_checksum(padded_payload + check_sequence):
            raise ValueError("Frame check sequence error")
        return cls(data)

class MdfuSerialFrameDecoder(ABC):
    """MDFU Serial transport frame decoder"""
    def __init__(self):
        """Serial transport frame decoder initialization"""
        self.state = "idle"
        self.buf = bytearray()
        self.frame_start = None
        self.frame_end = None

    def clear_buffers(self):
        """Clear buffer"""
        self.buf = bytearray()

    def update(self, byte, start_time, end_time):
        """Update decoder with new data

        :param byte: New byte to add to the decoder
        :type byte: bytes, bytearray
        :param start_time: Start time of the byte. 
        :type start_time: datetime
        :param end_time: End time of the byte.
        :type end_time: datetime
        :return: None, AnalyzerFrame
        :rtype: None | AnalyzerFrame | list(AnalyzerFrame)
        """
        if "idle" == self.state:
            if FRAME_START_CODE != byte:
                return None
            self.clear_buffers()
            self.state = "decoding"
            self.frame_start = start_time
            self.buf.append(byte)
            return None

        if FRAME_START_CODE == byte:
            self.clear_buffers()
            self.frame_start = start_time
            self.buf.append(byte)
            return None
        if FRAME_END_CODE == byte:
            self.state = "idle"
            self.frame_end = end_time
            self.buf.append(byte)
            return self.decode_frame()

        self.buf.append(byte)
        return None

    @abstractmethod
    def decode_frame(self):
        """Serial transport frame decoding abstract method"""

class MdfuCmdDecoder(MdfuSerialFrameDecoder):
    """MDFU serial transport command decoder
    """
    def decode_frame(self):
        """Decode a serial transport command frame

        :return: Saleae Analyzer frame or None
        :rtype: None or AnalyzerFrame
        """
        try:
            mdfu_serial_frame = Frame.from_bytes(self.buf)
            mdfu_packet = MdfuCmdPacket.from_binary(mdfu_serial_frame.packet)
        except (ValueError, MdfuCmdNotSupportedError):
            return None
        return AnalyzerFrame("mdfu_frame", self.frame_start, self.frame_end, {'labelText': repr(mdfu_packet)})

class MdfuResponseDecoder(MdfuSerialFrameDecoder):
    """MDFU serial transport response decoder
    """
    def decode_frame(self):
        """Decode a serial transport response frame

        :return: Saleae Analyzer frame or None
        :rtype: None or AnalyzerFrame
        """
        try:
            mdfu_serial_frame = Frame.from_bytes(self.buf)
            mdfu_packet = MdfuStatusPacket.from_binary(mdfu_serial_frame.packet)
        except (ValueError, MdfuStatusInvalidError):
            return None
        return AnalyzerFrame("mdfu_frame", self.frame_start, self.frame_end, {'labelText': repr(mdfu_packet)})


class MdfuSerialTransportAnalyzer(HighLevelAnalyzer): #pylint: disable=too-few-public-methods
    """MDFU serial transport analyzer
    """
    trace_setting = ChoicesSetting(choices=('from host', 'to host'))
    result_types = {
        'mdfu_frame': {
            'format': '{{data.labelText}}'
        }
    }

    def __init__(self):
        """Analyzer intitialization"""
        self.decoder = MdfuCmdDecoder() if self.trace_setting == "from host" else MdfuResponseDecoder()

    def decode(self, frame: AnalyzerFrame):
        """Decode analyzer frame

        :param frame: Saleae serial transport frame
        :type frame: AnalyzerFrame
        :return: AnalyzerFrame or list of AnalyzerFrame
        :rtype: AnalyzerFrame or list(AnalyzerFrame)
        """
        if "data" == frame.type:
            return self.decoder.update(frame.data['data'][0], frame.start_time, frame.end_time)
        return None
