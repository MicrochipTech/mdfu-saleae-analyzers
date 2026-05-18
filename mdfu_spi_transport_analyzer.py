# Copyright 2024 Microchip Technology Incorporated
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Saleae high level analyzer for MDFU SPI transport
"""
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting #pylint: disable=import-error
from mdfu import MdfuCmdPacket, MdfuStatusPacket, MdfuProtocolError, verify_checksum, MdfuCmd, MdfuStatus,\
    ClientInfo, MdfuClientInfoError

# Enable/disable printing to Saleae terminal in debug_print function
DEBUG = False

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

class Decoder():
    """Common SPI transport decoder class"""
    WRITE = 0x11
    READ = 0x55
    def __init__(self, trace="mosi"):
        """Command decoder initialization

        :param trace: Configuration to decode either MISO or MOSI, 
        valid values are "mosi" and "miso", defaults to "mosi"
        :type trace: str, optional
        """
        if trace not in ("miso", "mosi"):
            raise ValueError(f"{trace} is not a valid setting. Allowed values are miso and mosi")
        self.trace = trace

    def decode(self, tx, rx, time):
        """Decode MOSI/MOSI transaction data based on trace settings

        :param tx: Buffer containing MOSI bytes
        :type tx: bytes, bytearray
        :param rx: Buffer containing MISO bytes
        :type rx: bytes, bytearray
        :param time: Timestamps for MOSI/MOSI bytes
        :type time: list[dict(str:datetime)]
        :raises DecodingError: When encountering a decoding error
        :return: List of Saleae analyzer frames containing decoded data
        :rtype: list[AnalyzerFrame]
        """
        if self.trace == "mosi":
            return self.decode_tx(tx, time)
        if self.trace == "miso":
            return self.decode_rx(rx, time)
        return []

    def decode_tx(self, tx, time):
        """Override in subclass to decode MOSI transaction data.

        :raises NotImplementedError: Always — subclasses must implement this method.
        """
        raise NotImplementedError("Subclasses must implement decode_tx")

    def decode_rx(self, rx, time):
        """Override in subclass to decode MISO transaction data.

        :raises NotImplementedError: Always — subclasses must implement this method.
        """
        raise NotImplementedError("Subclasses must implement decode_rx")

class ResponseDecoder(Decoder):
    """MDFU SPI transport response decoder"""
    FRAME_READ_PREFIX_START = 0
    FRAME_DUMMY_BYTES_START = 1
    FRAME_DUMMY_BYTES_END = -1

    RSP_FRAME_DUMMY_BYTE_START = 0
    RSP_FRAME_PREFIX_START = 1
    RSP_FRAME_PREFIX_END = 3
    RSP_FRAME_RSP_DATA_START = 4
    RSP_FRAME_RSP_DATA_END = -3
    RSP_FRAME_CRC_START = -2
    RSP_FRAME_CRC_END = -1
    RSP_FRAME_PREFIX = bytes("RSP", encoding="ascii")

    def decode_tx(self, tx, time):
        """Decode MOSI transaction data

        :param tx: Buffer containing MOSI bytes
        :type tx: bytes, bytearray
        :param time: Timestamps for MOSI bytes
        :type time: list[dict(str:datetime)]
        :raises DecodingError: When encountering a decoding error
        :return: List of Saleae analyzer frames containing decoded data
        :rtype: list[AnalyzerFrame]
        """
        return_frames = []
        if tx[self.FRAME_READ_PREFIX_START] != self.READ:
            raise DecodingError(f"Expected READ ({hex(self.READ)}) byte at start of frame " +
                                "but got {tx[self.FRAME_READ_PREFIX_START]}")
        label_text = "READ"
        return_frames.append(AnalyzerFrame('mdfu_transport',
                                           time[self.FRAME_READ_PREFIX_START]["start"],
                                           time[self.FRAME_READ_PREFIX_START]["end"],
                                           {'type': label_text}))

        label_text = "DUMMY BYTES"
        return_frames.append(AnalyzerFrame('mdfu_transport',
                                           time[self.FRAME_DUMMY_BYTES_START]["start"],
                                           time[self.FRAME_DUMMY_BYTES_END]["end"],
                                           {'type': label_text}))
        return return_frames

    def decode_rx(self, rx, time):
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
        response_frame_prefix = rx[self.RSP_FRAME_PREFIX_START: self.RSP_FRAME_PREFIX_END + 1]
        if response_frame_prefix != self.RSP_FRAME_PREFIX:
            label_text = "DUMMY BYTE"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                               time[self.RSP_FRAME_DUMMY_BYTE_START]["start"],
                                               time[self.RSP_FRAME_DUMMY_BYTE_START]["end"],
                                               {'type': label_text}))
            label_text = f"Transport error: Invalid response frame prefix {response_frame_prefix}" +\
                        f" expected {self.RSP_FRAME_PREFIX}"
            return_frames.append(AnalyzerFrame('mdfu_error',
                                               time[self.RSP_FRAME_PREFIX_START]["start"],
                                               time[self.RSP_FRAME_CRC_END]["end"],
                                               {'type': label_text}))
        else:
            label_text = "DUMMY BYTE"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                               time[self.RSP_FRAME_DUMMY_BYTE_START]["start"],
                                               time[self.RSP_FRAME_DUMMY_BYTE_START]["end"],
                                               {'type': label_text}))
            label_text = "PREFIX (RSP)"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                               time[self.RSP_FRAME_PREFIX_START]["start"],
                                               time[self.RSP_FRAME_PREFIX_END]["end"],
                                               {'type': label_text}))

            mdfu_packet_bin = rx[self.RSP_FRAME_RSP_DATA_START:self.RSP_FRAME_RSP_DATA_END + 1]
            try:
                mdfu_packet = MdfuStatusPacket.from_binary(mdfu_packet_bin)
                # Client info command has always sequence number 0
                if mdfu_packet.sequence_number == 0:
                    client_info = ClientInfo.from_bytes(mdfu_packet.data)
                    print(client_info)
                return_frames.append(AnalyzerFrame('mdfu_prot_response',
                                    time[self.RSP_FRAME_RSP_DATA_START]["start"],
                                    time[self.RSP_FRAME_RSP_DATA_END]["end"],
                                    {'sequence_number': str(mdfu_packet.sequence_number),
                                     'resend': mdfu_packet.resend,
                                     'status': MdfuStatus(mdfu_packet.status).name,
                                     'data': mdfu_packet.data}))
            except MdfuProtocolError as exc:
                label_text = f"Protocol error: {exc}"
                return_frames.append(AnalyzerFrame('mdfu_error',
                                                time[self.RSP_FRAME_RSP_DATA_START]["start"],
                                                time[self.RSP_FRAME_RSP_DATA_END]["end"],
                                                {'error': label_text}))

            if verify_checksum(mdfu_packet_bin, int.from_bytes(rx[self.RSP_FRAME_CRC_START:], byteorder="little")):
                label_text = "CRC (Valid)"
            else:
                label_text = "CRC (Invalid)"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                                time[self.RSP_FRAME_CRC_START]["start"],
                                                time[self.RSP_FRAME_CRC_END]["end"],
                                                {'type': label_text}))

        return return_frames

class ResponseStatusDecoder(Decoder):
    """MDFU SPI transport response status decoder"""
    FRAME_READ_PREFIX_START = 0
    FRAME_DUMMY_BYTES_START = 1
    FRAME_DUMMY_BYTES_END = 7

    RSP_FRAME_DUMMY_BYTE_START = 0
    RSP_FRAME_PREFIX_START = 1
    RSP_FRAME_PREFIX_END = 3
    RSP_FRAME_RSP_LENGTH_START = 4
    RSP_FRAME_RSP_LENGTH_END = 5
    RSP_FRAME_CRC_START = 6
    RSP_FRAME_CRC_END = 7

    FRAME_SIZE = 8
    RSP_FRAME_PREFIX = bytes("LEN", encoding="ascii")

    def decode_tx(self, tx, time):
        """Decode MOSI transaction data

        :param tx: Buffer containing MOSI bytes
        :type tx: bytes, bytearray
        :param time: Timestamps for MOSI bytes
        :type time: list[dict(str:datetime)]
        :raises DecodingError: When encountering a decoding error
        :return: List of Saleae analyzer frames containing decoded data
        :rtype: list[AnalyzerFrame]
        """
        return_frames = []
        if tx[self.FRAME_READ_PREFIX_START] != self.READ:
            raise DecodingError(f"Expected READ ({hex(self.READ)}) byte at start of frame " +
                                "but got {tx[self.FRAME_READ_PREFIX_START]}")
        if len(tx) > self.FRAME_SIZE:
            raise DecodingError(f"Response status frame size should be {self.FRAME_SIZE} bytes but got {len(tx)}")
        label_text = "READ"
        return_frames.append(AnalyzerFrame('mdfu_transport',
                                           time[self.FRAME_READ_PREFIX_START]["start"],
                                           time[self.FRAME_READ_PREFIX_START]["end"],
                                           {'type': label_text}))

        label_text = "DUMMY BYTES"
        return_frames.append(AnalyzerFrame('mdfu_transport',
                                           time[self.FRAME_DUMMY_BYTES_START]["start"],
                                           time[self.FRAME_DUMMY_BYTES_END]["end"],
                                           {'type': label_text}))
        return return_frames

    def decode_rx(self, rx, time):
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
        if rx[self.RSP_FRAME_PREFIX_START: self.RSP_FRAME_PREFIX_END + 1] != self.RSP_FRAME_PREFIX:
            label_text = "DUMMY BYTE"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                               time[self.RSP_FRAME_DUMMY_BYTE_START]["start"],
                                               time[self.RSP_FRAME_DUMMY_BYTE_START]["end"],
                                               {'type': label_text}))
            label_text = "PREFIX (invalid)"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                               time[self.RSP_FRAME_PREFIX_START]["start"],
                                               time[self.RSP_FRAME_PREFIX_END]["end"],
                                               {'type': label_text}))
            label_text = "Invalid data"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                               time[self.RSP_FRAME_RSP_LENGTH_START]["start"],
                                               time[self.RSP_FRAME_CRC_END]["end"],
                                               {'type': label_text}))
        else:
            label_text = "DUMMY BYTE"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                               time[self.RSP_FRAME_DUMMY_BYTE_START]["start"],
                                               time[self.RSP_FRAME_DUMMY_BYTE_START]["end"],
                                               {'type': label_text}))
            label_text = "PREFIX (LEN)"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                               time[self.RSP_FRAME_PREFIX_START]["start"],
                                               time[self.RSP_FRAME_PREFIX_END]["end"],
                                               {'type': label_text}))

            rsp_length_bin = rx[self.RSP_FRAME_RSP_LENGTH_START:self.RSP_FRAME_RSP_LENGTH_END + 1]
            rsp_length = int.from_bytes(rsp_length_bin, byteorder="little")
            label_text = f"RESPONSE LENGTH: ({rsp_length} bytes)"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                               time[self.RSP_FRAME_RSP_LENGTH_START]["start"],
                                               time[self.RSP_FRAME_RSP_LENGTH_END]["end"],
                                               {'type': label_text}))

            if verify_checksum(rsp_length_bin, int.from_bytes(rx[self.RSP_FRAME_CRC_START:], byteorder="little")):
                label_text = "CRC (Valid)"
            else:
                label_text = "CRC (Invalid)"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                               time[self.RSP_FRAME_CRC_START]["start"],
                                               time[self.RSP_FRAME_CRC_END]["end"],
                                               {'type': label_text}))

        return return_frames

class CmdDecoder(Decoder):
    """MDFU SPI transport command decoder
    """
    FRAME_WRITE_PREFIX_START = 0
    FRAME_PAYLOAD_START = 1
    FRAME_PAYLOAD_END = -3
    FRAME_CRC_START = -2
    FRAME_CRC_END = -1

    FRAME_WRITE_PREFIX_LEN = 1
    FRAME_CRC_LEN = 2

    RSP_FRAME_DUMMY_BYTES_START = 0
    RSP_FRAME_DUMMY_BYTES_END = -1

    def decode_rx(self, rx, time):#pylint: disable=unused-argument
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

        label_text = "DUMMY BYTES"
        return_frames.append(AnalyzerFrame('mdfu_transport',
                                           time[self.RSP_FRAME_DUMMY_BYTES_START]["start"],
                                           time[self.RSP_FRAME_DUMMY_BYTES_END]["end"],
                                           {'type': label_text}))
        return return_frames

    def decode_tx(self, tx, time):
        """Decode MOSI transaction data

        :param tx: Buffer containing MOSI bytes
        :type tx: bytes, bytearray
        :param time: Timestamps for MOSI bytes
        :type time: list[dict(str:datetime)]
        :raises DecodingError: When encountering a decoding error
        :return: List of Saleae analyzer frames containing decoded data
        :rtype: list[AnalyzerFrame]
        """
        return_frames = []
        if tx[self.FRAME_WRITE_PREFIX_START] != self.WRITE:
            raise DecodingError(f"Expected WRITE {hex(self.WRITE)} byte at start of frame " +
                                "but got {tx[self.FRAME_WRITE_PREFIX_START]}")

        label_text = "WRITE"
        return_frames.append(AnalyzerFrame('mdfu_transport',
                                           time[self.FRAME_WRITE_PREFIX_START]["start"],
                                           time[self.FRAME_WRITE_PREFIX_START]["end"],
                                           {'type': label_text}))

        data_size = len(tx) - self.FRAME_WRITE_PREFIX_LEN - self.FRAME_CRC_LEN
        mdfu_packet_bin = tx[self.FRAME_PAYLOAD_START:self.FRAME_PAYLOAD_END + 1]

        try:
            mdfu_packet = MdfuCmdPacket.from_binary(mdfu_packet_bin)
            return_frames.append(AnalyzerFrame('mdfu_prot_command',
                                    time[self.FRAME_PAYLOAD_START]["start"],
                                    time[self.FRAME_PAYLOAD_END]["end"],
                                    {
                                        'command': MdfuCmd(mdfu_packet.command).name,
                                        'sequence_number': str(mdfu_packet.sequence_number),
                                        'sync': mdfu_packet.sync,
                                        'data': mdfu_packet.data
                                    }))
        except MdfuProtocolError as exc:
            msg = f"Protocol error: {exc}"
            return_frames.append(AnalyzerFrame('mdfu_error',
                        time[self.FRAME_PAYLOAD_START]["start"],
                        time[self.FRAME_PAYLOAD_END]["end"],
                        {'error': msg}))

        if verify_checksum(mdfu_packet_bin, int.from_bytes(tx[self.FRAME_CRC_START:], byteorder="little")):
            label_text = "CRC (Valid)"
        else:
            label_text = "CRC (Invalid)"
        return_frames.append(AnalyzerFrame('mdfu_transport',
                                           time[self.FRAME_CRC_START]["start"],
                                           time[self.FRAME_CRC_END]["end"],
                                           {'type': label_text}))
        return return_frames

class InvalidFrameDecoder(Decoder):
    """MDFU SPI transport response status decoder"""
    FRAME_PREFIX_START = 0
    FRAME_DUMMY_BYTES_START = 1
    FRAME_DUMMY_BYTES_END = 7

    RSP_FRAME_DUMMY_BYTE_START = 0
    RSP_FRAME_PREFIX_START = 1
    RSP_FRAME_PREFIX_END = 3
    RSP_FRAME_RSP_LENGTH_START = 4
    RSP_FRAME_RSP_LENGTH_END = 5
    RSP_FRAME_CRC_START = 6
    RSP_FRAME_CRC_END = 7

    FRAME_SIZE = 8
    RSP_FRAME_PREFIX = bytes("LEN", encoding="ascii")

    def decode_tx(self, tx, time):
        """Decode MOSI transaction data

        :param tx: Buffer containing MOSI bytes
        :type tx: bytes, bytearray
        :param time: Timestamps for MOSI bytes
        :type time: list[dict(str:datetime)]
        :raises DecodingError: When encountering a decoding error
        :return: List of Saleae analyzer frames containing decoded data
        :rtype: list[AnalyzerFrame]
        """
        return_frames = []
        label_text = "READ"
        return_frames.append(AnalyzerFrame('mdfu_transport',
            time[self.FRAME_PREFIX_START]["start"],
            time[self.FRAME_PREFIX_START]["end"],
            {'type': label_text}))

        label_text = "DUMMY BYTES"
        return_frames.append(AnalyzerFrame('mdfu_transport',
                                           time[self.FRAME_DUMMY_BYTES_START]["start"],
                                           time[-1]["end"],
                                           {'type': label_text}))
        return return_frames

    def decode_rx(self, rx, time):
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
        if rx[self.RSP_FRAME_PREFIX_START: self.RSP_FRAME_PREFIX_END + 1] != self.RSP_FRAME_PREFIX:
            label_text = "DUMMY BYTE"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                               time[self.RSP_FRAME_DUMMY_BYTE_START]["start"],
                                               time[self.RSP_FRAME_DUMMY_BYTE_START]["end"],
                                               {'type': label_text}))
            label_text = "PREFIX (invalid)"
            return_frames.append(AnalyzerFrame('mdfu_transport_error',
                                               time[self.RSP_FRAME_PREFIX_START]["start"],
                                               time[self.RSP_FRAME_PREFIX_END]["end"],
                                               {'type': 'PREFIX', 'error': label_text}))
            label_text = "DATA (invalid)"
            return_frames.append(AnalyzerFrame('mdfu_transport_error',
                                               time[self.RSP_FRAME_RSP_LENGTH_START]["start"],
                                               time[-1]["end"],
                                               {'type': 'DATA', 'error': label_text}))

        return return_frames

# High level analyzers must subclass the HighLevelAnalyzer class.
class MdfuSpiTransportAnalyzer(HighLevelAnalyzer):
    """High level analyzer"""
    trace_setting = ChoicesSetting(choices=('mosi', 'miso'))
    # Result types are split into three categories
    # 1) MDFU protocol (commands and responses)
    # 2) MDFU transport (all transport related types)
    # 3) MDFU error (both, transport and protocol errors)
    result_types = {
        'mdfu_prot_response': {
            'format': (
                'MDFU Response - '
                'Sequence Number: {{data.sequence_number}}, '
                'Resend: {{data.resend}}, '
                'Status: {{data.status}}, '
                'Data: {{data.data}}'
            )
        },

        'mdfu_prot_command': {
            'format': (
                'MDFU Command - '
                'Command: {{data.command}}, '
                'Sequence Number {{data.sequence_number}}, '
                'Sync: {{data.sync}}, '
                'Data: {{data.data}}'
            )
        },

        'mdfu_error': {
            'format': '{{data.error}}'
        },

        'mdfu_transport_error': {
            'format': '{{data.error}}'
        },

        'mdfu_transport': {
            'format': '{{data.type}}'
        }
    }
    WRITE = 0x11
    READ = 0x55

    def __init__(self):
        """High level analyzer initialization"""
        self.spi_cs = False
        self.response_decoder = ResponseDecoder(trace=self.trace_setting)
        self.response_status_decoder = ResponseStatusDecoder(trace=self.trace_setting)
        self.command_decoder = CmdDecoder(trace=self.trace_setting)
        self.invalid_frame_decoder = InvalidFrameDecoder(trace=self.trace_setting)
        self.txbuf = bytearray()
        self.rxbuf = bytearray()
        self.time = []
        self.state = "cmd"

    def reset_buffers(self):
        """Reset buffers
        This should be done for each SPI transaction
        """
        self.txbuf.clear()
        self.rxbuf.clear()
        self.time = []

    def store_data(self, frame: AnalyzerFrame):
        """Store SPI data in buffer

        Stores miso/mosi bytes and start/stop timestamps in internal buffers.


        :param frame: Saleae frame that has result type (frame.type="result")
        :type frame: AnalyzerFrame
        """
        self.time.append({"start": frame.start_time, "end": frame.end_time})
        self.rxbuf.extend(frame.data["miso"])
        self.txbuf.extend(frame.data["mosi"])

    def decode(self, frame: AnalyzerFrame):
        """Decode SPI traffic"""

        if frame.type == "disable":
            self.spi_cs = False
            return_frames = None
            try:
                if self.WRITE == self.txbuf[0]:
                    debug_print("Decoding command")
                    self.state = "len"
                    return self.command_decoder.decode(self.txbuf, self.rxbuf, self.time)

                elif self.READ == self.txbuf[0]:
                    prefix = self.rxbuf[1:4]
                    if ResponseDecoder.RSP_FRAME_PREFIX == prefix:
                        debug_print("Decoding response")
                        self.state = "cmd"
                        return_frames = self.response_decoder.decode(self.txbuf, self.rxbuf, self.time)
                    elif ResponseStatusDecoder.RSP_FRAME_PREFIX == prefix:
                        debug_print("Decoding response status")
                        self.state ="rsp"
                        return_frames = self.response_status_decoder.decode(self.txbuf, self.rxbuf, self.time)
                    else:
                        # Unless we are in the poll for the response length
                        # we must consider this case as an error
                        if self.state != "len":
                            return_frames = self.invalid_frame_decoder.decode(self.txbuf, self.rxbuf, self.time)
                        else:
                            return_frames = self.response_status_decoder.decode(self.txbuf, self.rxbuf, self.time)

            except DecodingError as exc:
                # Let's skip this frame, print the error and try the next one
                print(f"Error decoding frame: {exc}")

            return return_frames

        if frame.type == "enable":
            self.spi_cs = True
            self.reset_buffers()
            return None

        if frame.type == "result" and self.spi_cs:
            self.store_data(frame)
            return None

        return None
