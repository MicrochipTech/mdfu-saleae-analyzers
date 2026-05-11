# Copyright 2026 Microchip Technology Incorporated
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
from enum import Enum
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting #pylint: disable=import-error
from mdfu import MdfuCmdPacket, MdfuStatusPacket, MdfuProtocolError, \
                verify_checksum, ClientInfo, MdfuCmd, MdfuClientInfoError, \
                MdfuStatus

# Enable/disable printing to Saleae terminal in debug_print function
DEBUG = True

class FrameType(Enum):
    """MDFU I2C frame type codes"""
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

class ResponseDecoder(): #pylint: disable=too-few-public-methods
    """MDFU I2C transport response decoder"""
    RSP_FRAME_TYPE_START = 0
    RSP_FRAME_RSP_DATA_START = 1
    RSP_FRAME_RSP_DATA_END = -3
    RSP_FRAME_CRC_START = -2
    RSP_FRAME_CRC_END = -1
    # 1 byte frame type, 2 bytes CRC, at least 2 bytes of payload
    MINIMUM_RESPONSE_FRAME_LENGTH = 5

    def decode(self, data, time, command=None):
        """Decode MDFU I2C transport response

        :param data: I2C read transaction data
        :type data: bytearray
        :param time: Timestamps for I2C data bytes
        :type time: list[dict(str:datetime)]
        :return: Tuple of Saleae analyzer frames for transport and MDFU layers (Transport Frames, MDFU Frames)
        :rtype: tuple(list[AnalyzerFrame], list[AnalyzerFrame])
        """
        transport_frames = []
        mdfu_frames = []

        # Verify that response length is reasonable
        if len(data) < self.MINIMUM_RESPONSE_FRAME_LENGTH:
            transport_frames.append(AnalyzerFrame('mdfu_error',
                                            time[self.RSP_FRAME_TYPE_START]["start"],
                                            time[-1]["end"],
                                            {'error': 'Error Decoding Response (Invalid Length)'}))
            return transport_frames, None

        label_text = "Frame Type Response (R)"
        transport_frames.append(AnalyzerFrame('mdfu_transport',
                                            time[self.RSP_FRAME_TYPE_START]["start"],
                                            time[self.RSP_FRAME_TYPE_START]["end"],
                                            {'type': label_text}))
        # Transport payload = MDFU response packet
        mdfu_packet_bin = data[self.RSP_FRAME_RSP_DATA_START:self.RSP_FRAME_RSP_DATA_END + 1]

        if verify_checksum(mdfu_packet_bin, int.from_bytes(data[self.RSP_FRAME_CRC_START:], byteorder="little")):
            # Decode MDFU response packet from transport payload
            try:
                mdfu_packet = MdfuStatusPacket.from_binary(mdfu_packet_bin)
                mdfu_frames.append(AnalyzerFrame('mdfu_prot_response',
                    time[self.RSP_FRAME_RSP_DATA_START]["start"],
                    time[self.RSP_FRAME_RSP_DATA_END]["end"],
                    {'sequence_number': str(mdfu_packet.sequence_number),
                        'resend': mdfu_packet.resend,
                        'status': MdfuStatus(mdfu_packet.status).name,
                        'data': mdfu_packet.data}
                        ))
                try:
                    if command is not None:
                        if command == MdfuCmd.GET_CLIENT_INFO.value:
                            client_info = ClientInfo.from_bytes(mdfu_packet.data)
                            print(client_info)

                except MdfuClientInfoError as exc:
                    debug_print(exc)
            except MdfuProtocolError as exc:
                mdfu_frames.append(AnalyzerFrame('mdfu_error',
                    time[self.RSP_FRAME_RSP_DATA_START]["start"],
                    time[self.RSP_FRAME_RSP_DATA_END]["end"],
                    {'error': str(exc)}
                ))

            # I2C transport payload frame
            transport_frames.append(AnalyzerFrame('mdfu_transport',
                                    time[self.RSP_FRAME_RSP_DATA_START]["start"],
                                    time[self.RSP_FRAME_RSP_DATA_END]["end"],
                                    {'type': 'Payload'}))

            # I2C transport CRC frame
            label_text = "CRC (Valid)"
            transport_frames.append(AnalyzerFrame('mdfu_transport',
                                                time[self.RSP_FRAME_CRC_START]["start"],
                                                time[self.RSP_FRAME_CRC_END]["end"],
                                                {'type': label_text}))
        else:
            # I2C transport payload frame
            transport_frames.append(AnalyzerFrame('mdfu_transport',
                                    time[self.RSP_FRAME_RSP_DATA_START]["start"],
                                    time[self.RSP_FRAME_RSP_DATA_END]["end"],
                                    {'type': 'Payload'}))

            # MDFU protocol frame
            mdfu_frames.append(AnalyzerFrame('mdfu_error',
                                    time[self.RSP_FRAME_RSP_DATA_START]["start"],
                                    time[self.RSP_FRAME_RSP_DATA_END]["end"],
                                    {'error': "Transport error (invalid CRC)"}))
            label_text = "CRC (Invalid)"
            # I2C transport CRC frame
            transport_frames.append(AnalyzerFrame('mdfu_error',
                                                time[self.RSP_FRAME_CRC_START]["start"],
                                                time[self.RSP_FRAME_CRC_END]["end"],
                                                {'error': label_text}))

        return transport_frames, mdfu_frames

class ResponseLengthDecoder(): #pylint: disable=too-few-public-methods
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
        # If we have a valid response type we have a valid response length
        if self.RSP_FRAME_TYPE_LENGTH == data[0]:
            rsp_length_bin = data[self.RSP_FRAME_RSP_LENGTH_START:self.RSP_FRAME_RSP_LENGTH_END + 1]
            rsp_length = int.from_bytes(rsp_length_bin, byteorder="little")
            crc_valid = verify_checksum(rsp_length_bin,
                                        int.from_bytes(data[self.RSP_FRAME_CRC_START:], byteorder="little"))

            label_text = "Response Length (L)"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                                time[self.RSP_FRAME_TYPE_START]["start"],
                                                time[self.RSP_FRAME_TYPE_START]["end"],
                                                {'type': label_text}))
            if crc_valid:
                label_response_length_text = f"Response Length: ({rsp_length} bytes)"
                return_frames.append(AnalyzerFrame('mdfu_transport',
                        time[self.RSP_FRAME_RSP_LENGTH_START]["start"],
                        time[self.RSP_FRAME_RSP_LENGTH_END]["end"],
                        {'type': label_response_length_text}))
                return_frames.append(AnalyzerFrame('mdfu_transport',
                        time[self.RSP_FRAME_CRC_START]["start"],
                        time[self.RSP_FRAME_CRC_END]["end"],
                        {'type': 'CRC (Valid)'}))
            else:
                label_response_length_text = "Response Length (Invalid due to CRC error)"
                return_frames.append(AnalyzerFrame('mdfu_transport',
                        time[self.RSP_FRAME_RSP_LENGTH_START]["start"],
                        time[self.RSP_FRAME_RSP_LENGTH_END]["end"],
                        {'type': label_response_length_text}))
                return_frames.append(AnalyzerFrame('mdfu_error',
                        time[self.RSP_FRAME_CRC_START]["start"],
                        time[self.RSP_FRAME_CRC_END]["end"],
                        {'type': 'CRC (Invalid)'}))
        else:
            label_text = "Response not ready"
            return_frames.append(AnalyzerFrame('mdfu_transport',
                                                time[self.RSP_FRAME_RSP_LENGTH_START]["start"],
                                                time[self.RSP_FRAME_CRC_END]["end"],
                                                {'type': label_text}))
        return return_frames

class CmdDecoder(): #pylint: disable=too-few-public-methods
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
        transport_frames = []
        mdfu_frames = []
        data_size = len(data) - self.FRAME_CRC_LEN
        mdfu_packet_bin = data[:self.FRAME_CRC_START]

        crc_valid = verify_checksum(mdfu_packet_bin, int.from_bytes(data[self.FRAME_CRC_START:], byteorder="little"))

        if crc_valid:
            try:
                mdfu_packet = MdfuCmdPacket.from_binary(mdfu_packet_bin)
                self.command = mdfu_packet.command
                label_text = f"{mdfu_packet}"
                # MDFU protocol layer frame
                mdfu_frames.append(AnalyzerFrame('mdfu_prot_command',
                                    time[0]["start"],
                                    time[-3]["end"],
                                    {
                                        'command': MdfuCmd(mdfu_packet.command).name,
                                        'sequence_number': str(mdfu_packet.sequence_number),
                                        'sync': mdfu_packet.sync,
                                        'data': mdfu_packet.data
                                    }
                                    ))

            except (MdfuProtocolError, ValueError) as exc:
                self.command = None
                # MDFU protocol layer frame
                mdfu_frames.append(AnalyzerFrame('mdfu_error',
                                        time[0]["start"],
                                        time[-3]["end"],
                                        {'error': "MDFU Packet Decoding Error: - " + str(exc)}))
            # I2C transport payload frame
            transport_frames.append(AnalyzerFrame('mdfu_transport',
                                            time[0]["start"],
                                            time[-3]["end"],
                                            {
                                                'type': "PAYLOAD",
                                                'data': mdfu_packet_bin
                                                }
                                            ))
            # I2C transport CRC frame
            label_text = "CRC (Valid)"
            transport_frames.append(AnalyzerFrame('mdfu_transport',
                                    time[self.FRAME_CRC_START]["start"],
                                    time[self.FRAME_CRC_END]["end"],
                                    {'type': label_text}))
        else:
            # I2C transport invalid payload frame
            label_text = "Invalid MDFU packet due to CRC error on transport"
            transport_frames.append(AnalyzerFrame('mdfu_error',
                                time[0]["start"],
                                time[-3]["end"],
                                {'error': label_text}))
            # MDFU protocol layer invalid frame
            mdfu_frames.append(AnalyzerFrame('mdfu_error',
                                time[0]["start"],
                                time[-1]["end"],
                                {'error': label_text}))
            # I2C transport invalid CRC frame
            label_text = "CRC (Invalid)"
            transport_frames.append(AnalyzerFrame('mdfu_transport',
                                            time[self.FRAME_CRC_START]["start"],
                                            time[self.FRAME_CRC_END]["end"],
                                            {'type': label_text}))

        return transport_frames, mdfu_frames

class MdfuI2cTransportAnalyzer(HighLevelAnalyzer): #pylint: disable=too-many-instance-attributes
    """High level analyzer"""
    debug_setting = ChoicesSetting(choices=('Off', 'On'))
    protocol_layer_setting = ChoicesSetting(choices=('MDFU Layer', 'I2C Transport Layer'))
    # Result types are split into three categories
    # 1) MDFU protocol (commands and responses)
    # 2) MDFU transport (all transport related types)
    # 3) MDFU error (both, transport and protocol errors)
    result_types = {
        'mdfu_prot_response': {
            'format': (
                'Sequence Number: {{data.sequence_number}}, '
                'Resend: {{data.resend}}, '
                'Status: {{data.status}}, '
                'Data: {{data.data}}'
            )
        },

        'mdfu_prot_command': {
            'format': (
                'Command: {{data.command}}, '
                'Sequence Number {{data.sequence_number}}, '
                'Sync: {{data.sync}}, '
                'Data: {{data.data}}'
            )
        },

        'mdfu_error': {
            'format': 'ERROR: {{error}}'
        },

        'mdfu_transport': {
            'format': '{{data.type}}'
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
        self.protocol_layer = "mdfu" if (self.protocol_layer_setting == 'MDFU Layer') else "transport"

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
        """Create a frame for the I2C client address"""
        label_text = f"Client (0x{self.address:02x}) - {self.state}"
        return AnalyzerFrame('mdfu_transport',
                                        self.address_start,
                                        self.address_end,
                                        {'type': label_text})

    def decode(self, frame: AnalyzerFrame):
        """Decode I2C traffic"""

        if "stop" == frame.type:
            transport_frames = []
            mdfu_frames = []
            if not self.address_ack:
                if self.protocol_layer == "mdfu":
                    return None
                return AnalyzerFrame('mdfu_transport',
                                        self.address_start,
                                        self.address_end,
                                        {'type': "Client busy"})
            # Check if its an I2C read or a write operation
            if self.read:
                if FrameType.RESPONSE_LENGTH.value == self.buf[0]:
                    transport_frames.append(self.create_client_frame())
                    transport = self.response_length_decoder.decode(self.buf, self.time)
                    transport_frames.extend(transport)
                    self.state = "Response"
                elif FrameType.RESPONSE.value == self.buf[0]:
                    transport_frames.append(self.create_client_frame())
                    transport, mdfu = self.response_decoder.decode(self.buf,
                                                self.time,
                                                command=self.command_decoder.command)
                    transport_frames.extend(transport)
                    mdfu_frames.extend(mdfu)
                    self.state = "Command"
                else:
                    # If its neither a response or response length frame the client is busy
                    label_text = "Response not ready"
                    transport_frames.append(AnalyzerFrame('mdfu_transport',
                                                self.time[0]["start"],
                                                self.time[-1]["end"],
                                                {'type': label_text}))
            else:
                transport_frames.append(self.create_client_frame())
                transport, mdfu = self.command_decoder.decode(self.buf, self.time)
                transport_frames.extend(transport)
                mdfu_frames.extend(mdfu)
                self.state = "Response Length"
            if self.protocol_layer == "mdfu":
                return mdfu_frames
            return transport_frames

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
