"""
Saleae high level analyzer for MDFU SPI transport
"""
from enum import Enum
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting #pylint: disable=import-error
from mdfu import MdfuCmdPacket, MdfuStatusPacket, MdfuProtocolError, verify_checksum, ClientInfo, MdfuCmd, MdfuClientInfoError

# Enable/disable printing to Saleae terminal in debug_print function
DEBUG = True

class FrameType(Enum):
    RESPONSE_LENGTH = ord('L')
    RESPONSE = ord('R')

def debug_print(*args):
    """Print debug messages to Saleae terminal
    :param args: Objects to print on terminal
    :type args: object
    """
    if DEBUG:
        print(*args)

class DecodingError(Exception):
    """Exception for errors during protocol decoding
    """

class ResponseDecoder():
    """MDFU I2C transport response decoder"""
    RSP_FRAME_TYPE_START = 0
    RSP_FRAME_RSP_DATA_START = 1
    RSP_FRAME_RSP_DATA_END = -3
    RSP_FRAME_CRC_START = -2
    RSP_FRAME_CRC_END = -1

    def decode(self, data, time, command=None):
        """Decode MISO transaction data

        :param tx: Buffer containing MISO bytes
        :type tx: bytes, bytearray
        :param time: Timestamps for MISO bytes
        :type time: list[dict(str:datetime)]
        :raises DecodingError: When encountering a decoding error
        :return: List of Saleae analyzer frames containing decoded data
        :rtype: list[AnalyzerFrame]
        """
        return_frames = []
        label_text = "Frame Type Response (R)"
        return_frames.append(AnalyzerFrame('mdfu_frame',
                                                time[self.RSP_FRAME_TYPE_START]["start"],
                                                time[self.RSP_FRAME_TYPE_START]["end"],
                                                {'labelText': label_text}))
        try:
            mdfu_packet_bin = data[self.RSP_FRAME_RSP_DATA_START:self.RSP_FRAME_RSP_DATA_END + 1]
            mdfu_packet = MdfuStatusPacket.from_binary(mdfu_packet_bin)
            label_text = f"{mdfu_packet}"
            try:
                if command is not None:
                    if command == MdfuCmd.GET_CLIENT_INFO.value:
                        client_info = ClientInfo.from_bytes(mdfu_packet.data)
                        debug_print(client_info)
            except MdfuClientInfoError as exc:
                debug_print(exc)
        except MdfuProtocolError as exc:
            debug_print(exc)
            label_text = f"Error decoding MDFU response: {exc}"

        return_frames.append(AnalyzerFrame('mdfu_frame',
                                            time[self.RSP_FRAME_RSP_DATA_START]["start"],
                                            time[self.RSP_FRAME_RSP_DATA_END]["end"],
                                            {'labelText': label_text}))

        if verify_checksum(mdfu_packet_bin, int.from_bytes(data[self.RSP_FRAME_CRC_START:], byteorder="little")):
            label_text = "CRC (Valid)"
        else:
            label_text = "CRC (Invalid)"
        return_frames.append(AnalyzerFrame('mdfu_frame',
                                            time[self.RSP_FRAME_CRC_START]["start"],
                                            time[self.RSP_FRAME_CRC_END]["end"],
                                            {'labelText': label_text}))

        return return_frames

class ResponseLengthDecoder():
    """MDFU I2C transport response length decoder"""
    RSP_FRAME_TYPE_START = 0
    RSP_FRAME_RSP_LENGTH_START = 1
    RSP_FRAME_RSP_LENGTH_END = 2
    RSP_FRAME_CRC_START = -2
    RSP_FRAME_CRC_END = -1
    RSP_FRAME_TYPE_LENGTH = ord("L")

    def decode(self, data, time):
        """Decode I2C transaction data

        :param data: I2C data
        :type data: bytes, bytearray
        :param time: Timestamps for I2C data
        :type time: list[dict(str:datetime)]
        :return: List of Saleae analyzer frames containing decoded data
        :rtype: list[AnalyzerFrame]
        """
        return_frames = []
        # If we a valid response type we have a valid response length
        if self.RSP_FRAME_TYPE_LENGTH == data[0]:
            rsp_length_bin = data[self.RSP_FRAME_RSP_LENGTH_START:self.RSP_FRAME_RSP_LENGTH_END + 1]
            rsp_length = int.from_bytes(rsp_length_bin, byteorder="little")
            crc_valid = verify_checksum(rsp_length_bin, int.from_bytes(data[self.RSP_FRAME_CRC_START:], byteorder="little"))

            label_text = "Frame Type Response Length (L)"
            return_frames.append(AnalyzerFrame('mdfu_frame',
                                                    time[self.RSP_FRAME_TYPE_START]["start"],
                                                    time[self.RSP_FRAME_TYPE_START]["end"],
                                                    {'labelText': label_text}))
            if crc_valid:
                label_text = f"Response Length: ({rsp_length} bytes)"
                return_frames.append(AnalyzerFrame('mdfu_frame',
                                                    time[self.RSP_FRAME_RSP_LENGTH_START]["start"],
                                                    time[self.RSP_FRAME_RSP_LENGTH_END]["end"],
                                                    {'labelText': label_text}))
                label_text = "CRC (Valid)"
                return_frames.append(AnalyzerFrame('mdfu_frame',
                                        time[self.RSP_FRAME_CRC_START]["start"],
                                        time[self.RSP_FRAME_CRC_END]["end"],
                                        {'labelText': label_text}))
            else:
                label_text = "Respone Length (Invalid due to CRC error)"
                return_frames.append(AnalyzerFrame('mdfu_frame',
                                                    time[self.RSP_FRAME_RSP_LENGTH_START]["start"],
                                                    time[self.RSP_FRAME_RSP_LENGTH_END]["end"],
                                                    {'labelText': label_text}))
                label_text = "CRC (Invalid)"
                return_frames.append(AnalyzerFrame('mdfu_frame',
                                                    time[self.RSP_FRAME_CRC_START]["start"],
                                                    time[self.RSP_FRAME_CRC_END]["end"],
                                                    {'labelText': label_text}))
        else:
            label_text = "Response not ready"
            return_frames.append([AnalyzerFrame('mdfu_frame',
                                                time[self.RSP_FRAME_RSP_LENGTH_START]["start"],
                                                time[self.RSP_FRAME_CRC_END]["end"],
                                                {'labelText': label_text})])
        return return_frames

class CmdDecoder():
    """MDFU I2C transport command decoder
    """
    FRAME_CRC_START = -2
    FRAME_CRC_END = -1
    FRAME_CRC_LEN = 2

    def __init__(self):
        self.command = None

    def decode(self, data, time):
        """Decode MDFU command I2C transport frame

        :param data: I2C data
        :type data: bytes, bytearray
        :param time: Timestamps for I2C bytes
        :type time: list[dict(str:datetime)]
        :return: List of Saleae analyzer frames containing decoded data
        :rtype: list[AnalyzerFrame]
        """
        return_frames = []
        data_size = len(data) - self.FRAME_CRC_LEN
        mdfu_packet_bin = data[:self.FRAME_CRC_START]

        crc_valid = verify_checksum(mdfu_packet_bin, int.from_bytes(data[self.FRAME_CRC_START:], byteorder="little"))
        if crc_valid:
            try:
                mdfu_packet = MdfuCmdPacket.from_binary(mdfu_packet_bin)
                self.command = mdfu_packet.command
                label_text = f"{mdfu_packet}"
            except (MdfuProtocolError, ValueError) as exc:
                self.command = None
                debug_print(exc)
                label_text = f"Invalid MDFU packet ({data_size} bytes)"

            return_frames.append(AnalyzerFrame('mdfu_frame',
                                            time[0]["start"],
                                            time[-3]["end"],
                                            {'labelText': label_text}))
            label_text = "CRC (Valid)"
            return_frames.append(AnalyzerFrame('mdfu_frame',
                                    time[self.FRAME_CRC_START]["start"],
                                    time[self.FRAME_CRC_END]["end"],
                                    {'labelText': label_text}))
        else:
            label_text = "Invalid MDFU packet due to CRC error"
            return_frames.append(AnalyzerFrame('mdfu_frame',
                                time[0]["start"],
                                time[-3]["end"],
                                {'labelText': label_text}))
            label_text = "CRC (Invalid)"
            return_frames.append(AnalyzerFrame('mdfu_frame',
                                            time[self.FRAME_CRC_START]["start"],
                                            time[self.FRAME_CRC_END]["end"],
                                            {'labelText': label_text}))
        return return_frames

class MdfuI2cTransportAnalyzer(HighLevelAnalyzer):
    """High level analyzer"""
    debug_setting = ChoicesSetting(choices=('On', 'Off'))
    result_types = {
        'mdfu_frame': {
            'format': '{{data.labelText}}'
        }
    }

    def __init__(self):
        """High level analyzer initialization"""
        self.response_decoder = ResponseDecoder()
        self.response_length_decoder = ResponseLengthDecoder()
        self.command_decoder = CmdDecoder()
        self.buf = bytearray()
        self.time = []
        self.read = False
        self.address_ack = False
        self.address_start = None
        self.address_end = None
        self.address = None
        self.state = "command"
        global DEBUG
        DEBUG = bool(self.debug_setting == "On")

    def reset_buffers(self):
        """Reset buffers
        This should be done for each I2C transaction
        """
        self.buf.clear()
        self.time = []

    def store_data(self, frame: AnalyzerFrame):
        """Store I2C data in buffer

        Stores I2C data bytes and their timestamps in internal buffers.


        :param frame: Saleae frame that has result type (frame.type="data")
        :type frame: AnalyzerFrame
        """
        self.time.append({"start": frame.start_time, "end": frame.end_time})
        self.buf.extend(frame.data["data"])

    def create_client_frame(self):
        label_text = f"Client (0x{self.address:02x}) - {self.state}"
        return AnalyzerFrame('mdfu_frame',
                                        self.address_start,
                                        self.address_end,
                                        {'labelText': label_text})

    def decode(self, frame: AnalyzerFrame):
        """Decode I2C traffic"""

        if "stop" == frame.type:
            frames = []
            if not self.address_ack:
                return AnalyzerFrame('mdfu_frame',
                                           self.address_start,
                                           self.address_end,
                                           {'labelText': "Client busy"})
            # Check if its an I2C read or a write operation
            if self.read:
                if FrameType.RESPONSE_LENGTH.value == self.buf[0]:
                    frames.append(self.create_client_frame())
                    frames.extend(self.response_length_decoder.decode(self.buf, self.time))
                    self.state = "response"
                elif FrameType.RESPONSE.value == self.buf[0]:
                    frames.append(self.create_client_frame())
                    frames.extend(self.response_decoder.decode(self.buf, self.time, command=self.command_decoder.command))
                    self.state = "command"
                else:
                    # If its neither a response or response length frame the client is busy
                    label_text = "Response not ready"
                    frames.append(AnalyzerFrame('mdfu_frame',
                                                self.time[0]["start"],
                                                self.time[-1]["end"],
                                                {'labelText': label_text}))
            else:
                frames.append(self.create_client_frame())
                frames.extend(self.command_decoder.decode(self.buf, self.time))
                self.state = "response length"
            return frames

        if "address" == frame.type:
            self.address = frame.data["address"][0] # 7 bit-address
            self.read = frame.data["read"]
            self.address_ack = frame.data["ack"]
            self.address_start = frame.start_time
            self.address_end = frame.end_time

        if "start" == frame.type:
            self.reset_buffers()
            return None

        if "data" == frame.type:
            self.store_data(frame)
            return None

        return None
