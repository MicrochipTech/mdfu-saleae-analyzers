"""MDFU protocol"""
from enum import Enum

class EnumDescription(int, Enum):
    """Subclass of Enum to support descriptions for Enum members
    
    Example:

    class MyEnum(EnumDescription):
        VAR1 = (0, "Description of VAR1")
        VAR2 = (1, "Desctiption of VAR2")

    MyEnum.VAR1.description
    MyEnum.VAR1.value
    MyEnum.VAR1.name

    Instantiation of MyEnum can be done with its value.
    y = MyEnum(0)
    y.description
    y.value
    y.name
    """
    def __new__(cls, value, description=None):
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj._description_ = description
        return obj

    @property
    def description(self):
        """Enum description property"""
        return self._description_

class MdfuStatus(Enum):
    """MDFU status codes
    """
    SUCCESS = 1
    NOT_SUPPORTED = 2
    NOT_AUTHORIZED = 3
    PACKET_TRANSPORT_FAILURE = 4
    ABORT_FILE_TRANSFER = 5

class MdfuCmd(Enum):
    """MDFU command codes
    """
    GET_CLIENT_INFO = 1
    START_TRANSFER = 2
    WRITE_CHUNK = 3
    GET_IMAGE_STATE = 4
    END_TRANSFER = 5

class ClientInfoType(Enum):
    """MDFU data types for GetClientInfo command response"""
    PROTOCOL_VERSION = 1
    BUFFER_INFO = 2
    COMMAND_TIMEOUTS = 3

class ImageState(Enum):
    """MDFU firmware image states for GetImageState command response"""
    VALID = 1
    INVALID = 2

class FileTransferAbortCause(EnumDescription):
    """Error codes and description for file transfer abort causes"""
    GENERIC_CLIENT_ERROR = (0, "Generic problem encountered by client")
    INVALID_FILE = (1, "Generic problem with the update file")
    INVALID_CLIENT_DEVICE_ID = (2, "The update file is not compatible with the client device ID")
    ADDRESS_ERROR = (3, "An invalid address is present in the update file")
    ERASE_ERROR = (4, "Client memory did not properly erase")
    WRITE_ERROR = (5, "Client memory did not properly write")
    READ_ERROR = (6, "Client memory did not properly read")
    APPLICATION_VERSION_ERROR = (7, "Client did not allow changing to the application version " \
    "in the update file")

class TransportFailureCause(EnumDescription):
    """Transport error causes"""
    INVALID_CHECKSUM = (0, "Invalid checksum detected")
    PACKET_TOO_LARGE = (1, "Packet was too large")

class MdfuProtocolError(Exception):
    """Generic MDFU exception
    """

class MdfuCmdNotSupportedError(MdfuProtocolError):
    """MDFU exception if command is not supported on client
    """

class MdfuClientInfoError(MdfuProtocolError):
    """MDFU exception if client informatino is invalid
    """
class MdfuStatusInvalidError(MdfuProtocolError):
    """MDFU exception for an invalid MDFU packet status
    """

# pylint: disable-next=too-few-public-methods
class MdfuPacket():
    """MDFU packet class
    """

class MdfuCmdPacket(MdfuPacket):
    """MDFU command packet
    """
    def __init__(self, sequence_number: int, command: int, data: bytes, sync=False):
        """MDFU command packet initialization

        :param sequence_number: Sequence number for this packet, valid numbers are from 0 to 31
        :type sequence_number: int
        :param command: Command to execute
        :type command: int
        :param data: Packet data
        :type data: bytes
        :param sync: Whether or not this packet should initiate a synchronization of
        the sequence number, defaults to False
        :type sync: bool, optional
        """
        self.sync = sync
        self.command = command
        self.data = data
        if sequence_number > 31 or sequence_number < 0:
            raise ValueError("Valid values for MDFU packet sequence number are 0...31", sequence_number)
        self.sequence_number = sequence_number
        cmd_values = set(item.value for item in MdfuCmd)
        if command not in cmd_values:
            raise MdfuCmdNotSupportedError(f"{hex(command)} is not a valid MDFU command")


    def __repr__(self) -> str:
        return f"""\
Command:         {MdfuCmd(self.command).name} ({hex(self.command)})
Sequence Number: {self.sequence_number}
Sync:            {self.sync}
Data:            {"0x" + self.data.hex() if len(self.data) else ""}
"""

    @staticmethod
    def decode_packet(packet: bytes) -> tuple:
        """ Decode a MDFU packet

        :param packet: MDFU packet
        :type packet: Bytes
        :return: Fields of the packet (Sequence number, command, data, sync)
        :rtype: Tuple(Int, Int, Bytes, Bool)
        """
        sequence_field = packet[0]
        sequence_number = sequence_field & 0x1f
        sync = bool(sequence_field & 0x80)
        command = int.from_bytes(packet[1:2], byteorder="little")
        data = packet[2:]
        return sequence_number, command, data, sync

    @classmethod
    def from_binary(cls, packet: bytes):
        """Create MDFU command packet from binary data.

        :param packet: MDFU packet in binary form
        :type packet: Bytes like object
        :return: Command packet object
        :rtype: MdfuCmdPacket
        """
        sequence_number, command, data, sync = cls.decode_packet(packet)
        pack = cls(sequence_number, command, data, sync=sync)
        return pack

    def to_binary(self):
        """Create binary MDFU packet

        :return: MDFU packet in binary form
        :rtype: Bytes
        """
        sequence_field = self.sequence_number | ((1 << 7) if self.sync else 0x00)
        packet =  sequence_field.to_bytes(1, byteorder="little") \
            + self.command.to_bytes(1, byteorder="little") \
            + self.data
        return packet

class MdfuStatusPacket(MdfuPacket):
    """MDFU status packet
    """
    def __init__(self, sequence_number, status, data=bytes(), resend=False):
        """MDFU packet initialization

        :param sequence_number: Sequence number for the packet, valid numbers are from 0 to 31
        :type sequence_number: Int
        :param status: Status code
        :type status: Int
        :param data: Data, defaults to bytes()
        :type data: Bytes like object, optional
        :param resend: Resend flag for the packet, defaults to False
        :type resend: bool, optional
        """
        if sequence_number > 31 or sequence_number < 0:
            raise ValueError("Valid values for MDFU packet sequence number are 0...31")
        self.sequence_number = sequence_number

        status_values = set(item.value for item in MdfuStatus)
        if status not in status_values:
            raise MdfuStatusInvalidError(f"{hex(status)} is not a valid MDFU status")
        self.status = status
        self.resend = resend
        self.data = data

    def __repr__(self) -> str:
        return f"""\
Sequence Number: {self.sequence_number}
Status:          {MdfuStatus(self.status).name} ({hex(self.status)})
Resend:          {self.resend}
Data:            {"0x" + self.data.hex() if len(self.data) else ""}
"""
    @staticmethod
    def decode_packet(packet):
        """Decode a status packet

        :param packet: Packet
        :type packet: Bytes like object
        :return: packet sequence number (int), status (int), data (bytes), resend (bool)
        :rtype: tuple(int, int, bytes, bool)
        """
        sequence_field = packet[0]
        sequence_number = sequence_field & 0x1f
        resend = bool(sequence_field & 0x40)
        status = int.from_bytes(packet[1:2], byteorder="little")
        data = packet[2:]
        return sequence_number, status, data, resend

    @classmethod
    def from_binary(cls, packet):
        """Create MDFU status packet from binary data.

        :param packet: MDFU packet in binary form
        :type packet: Bytes like object
        :return: Status packet object
        :rtype: MdfuStatusPacket
        """
        sequence_number, status, data, resend = cls.decode_packet(packet)
        pack = cls(sequence_number, status, data, resend=resend)
        return pack

    def to_binary(self):
        """Create binary MDFU packet

        :return: MDFU packet in binary form
        :rtype: Bytes
        """
        sequence_field = self.sequence_number | ((1 << 6) if self.resend else 0x00)
        packet =  sequence_field.to_bytes(1, byteorder="little") \
            + self.status.to_bytes(1, byteorder="little") \
            + self.data
        return packet

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

def verify_checksum(data, checksum):
    """Verify transport layer checksum.

    Pads data if needed, calculates checksum and then compares this
    to the user provided checksum.

    :param data: Input data for checksum calculation
    :type data: bytes like object
    :param checksum: Checksum to verify against
    :type checksum: int
    :return: True if checksum is valid and False if not
    :rtype: bool
    """
    if len(data) % 2:
        calculated_checksum = calculate_checksum(data + bytes(1))
    else:
        calculated_checksum = calculate_checksum(data)

    if checksum != calculated_checksum:
        return False
    return True
