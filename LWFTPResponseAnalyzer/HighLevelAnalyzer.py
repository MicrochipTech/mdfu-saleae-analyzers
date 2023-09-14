# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

import BidirectionalLookupTableIntsMapToStrings as blt
import FileTransferCommandsAndResponses as CandR

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    # my_string_setting = StringSetting()
    # my_number_setting = NumberSetting(min_value=0, max_value=100)
    # my_choices_setting = ChoicesSetting(choices=('A', 'B'))

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'lwftp_analyzer_frame': {
            'format': '{{data.labelText}}'
        }
    }  
    # result_types = {
    #     'mytype': {
    #         'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
    #     }
    # }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        ''' 
        self.CmdAnalyzer = CommandAnalzyer()
        print(" ---------- Starting Command Analzyer -----------")
        # print("Settings:", self.my_string_setting,
        #       self.my_number_setting, self.my_choices_setting)

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        newByte = frame.data['data'][0] 
        self.CmdAnalyzer.ProcessIncomingByte(newByte, frame.start_time, frame.end_time)

        if self.CmdAnalyzer.IsFrameLabelReady():
            print("Analyzer Frame Ready")
            frameLabelText = self.CmdAnalyzer.GetFrameLabel()
            startTime = self.CmdAnalyzer.GetFrameStartTime()
            endTime   = self.CmdAnalyzer.GetFrameEndTime()
            self.CmdAnalyzer.ClearFrameLabel()
            # frameLabel = {
            #     'mytype': {
            #         'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
            #     }
            # }
            frameLabelFormatType = 'lwftp_analyzer_frame' 
            frameLabelData = {'labelText': frameLabelText}
            if self.CmdAnalyzer.IsPacketComplete():
                self.CmdAnalyzer.ClearPacket()
            return AnalyzerFrame(frameLabelFormatType, startTime, endTime, frameLabelData)
        

        
        
        # else: 
        #     # Return the data frame itself
        #     return AnalyzerFrame('mytype', frame.start_time, frame.end_time, {
        #         'input_type': frame.type
        #     })

class CommandAnalzyer:
    def __init__(self): 
        self.CandR = CandR.CommandsAndResponses()
        self.buffer              = bytearray(0)
        self.packetSizeByteArray = bytearray(0)
        self.packetSize          = 0
        self.numDataBytes        = 0

        self.checksumByteArray   = bytearray(0)
        self.checksum16          = 0

        self.rxIndex = 0
        self.rxField = "Guard"

        self.startLabelTime = 0
        self.endLabelTime   = 0
        self.isLabelReady     = False
        self.frameLabel = ""
        self.isPacketcomplete = False

    def ClearPacket(self):
        self.buffer              = bytearray(0)
        self.packetSizeByteArray = bytearray(0)
        self.packetSize          = 0
        self.numDataBytes        = 0

        self.checksumByteArray   = bytearray(0)
        self.checksum16          = 0

        self.rxIndex = 0
        self.rxField = "Guard"

        self.startLabelTime = 0
        self.endLabelTime   = 0
        self.isLabelReady     = False
        self.frameLabel = ""
        self.isPacketcomplete = False

    def IsPacketComplete(self):
        if self.isPacketcomplete:
            return True
        else:
            return False

    def ProcessIncomingByte(self, newByte, byteStartTime, byteEndTime):

        guardBytes = [0x50, 0x48, 0x43, 0x4D]
        numGuardBytes = len(guardBytes)
        numPacketSizeFieldBytes = 2
        sequenceNumberIndex = numGuardBytes + numPacketSizeFieldBytes
        commandIndex = sequenceNumberIndex + 1
        numDataBytes = self.packetSize - 4
        dataEndIndex = commandIndex + numDataBytes

        if self.rxField == "Guard":

            if newByte == guardBytes[self.rxIndex]:  
                if self.rxIndex == 0:
                    self.startLabelTime = byteStartTime
                    print("Guard StartTime: " + str(byteStartTime))
                
                if self.rxIndex == 3:
                    self.endLabelTime = byteEndTime
                    self.frameLabel = "Guard:Match"
                    self.isLabelReady = True
                    self.rxIndex = 0
                    self.rxField = "PacketSize"
                    print("Guard EndTime: " + str(byteEndTime))
                    
                else:
                    self.rxIndex = self.rxIndex + 1
            else:
                print("Invalid Guard")
                self.rxIndex = 0
        
        elif self.rxField == "PacketSize":
            print("PacketSize")
            self.buffer.append(newByte)
            self.packetSizeByteArray.append(newByte)

            if self.rxIndex == 0:
                self.startLabelTime = byteStartTime
                print("PacketSize StartTime: " + str(byteStartTime))
            
            if self.rxIndex == 1:
                self.packetSize = int.from_bytes(self.packetSizeByteArray, byteorder='little')
                self.numDataBytes = self.packetSize - 4
                self.endLabelTime = byteEndTime
                littleEndianBytes = self.packetSizeByteArray
                littleEndianBytes.reverse()
                self.frameLabel = "PktSize:0x" + littleEndianBytes.hex() + ":" +  str(self.packetSize)
                self.isLabelReady = True
                self.rxIndex = 0
                self.rxField = "Sequence"
                print("PacketSize EndTime: " + str(byteEndTime))
                
            else:
                self.rxIndex = self.rxIndex + 1

        elif self.rxField == "Sequence":
            self.buffer.append(newByte)
            print("Sequence")

            self.startLabelTime = byteStartTime
            self.endLabelTime = byteEndTime
            if newByte & 0b10000000: 
                self.frameLabel = "Seq:" + str(newByte & 0b00011111) + ":Sync"
            else:
                self.frameLabel = "Seq:" + str(newByte & 0b00011111)
            print("PacketSize StartTime: " + str(byteStartTime))
            print("PacketSize EndTime: " + str(byteEndTime))
            self.isLabelReady = True
            self.rxField = "Status"
            self.rxIndex = 0
            
        
        elif self.rxField == "Status":
            self.buffer.append(newByte)
            print("Status")
            self.startLabelTime = byteStartTime
            self.endLabelTime = byteEndTime
            self.frameLabel = self.CandR.responses.GetString(newByte)
            print("PacketSize StartTime: " + str(byteStartTime))
            print("PacketSize EndTime: " + str(byteEndTime))
            self.isLabelReady = True

            if self.numDataBytes > 0:
                
                self.rxField = "Data"
                self.rxIndex = 0
            else:
                self.rxField = "Integrity"
                self.rxIndex = 0
        
        elif self.rxField == "Data":

            self.buffer.append(newByte)

            print("Data") 
            self.packetSizeByteArray.append(newByte)

            if self.rxIndex == 0:
                self.startLabelTime = byteStartTime
                print("PacketSize StartTime: " + str(byteStartTime))
            
            if self.rxIndex == (self.numDataBytes - 1):
                self.packetSize = int.from_bytes(self.packetSizeByteArray, byteorder='little')
                self.numDataBytes = self.packetSize - 4
                self.endLabelTime = byteEndTime 
                self.frameLabel = "Data Payload"
                self.isLabelReady = True
                self.rxIndex = 0
                self.rxField = "Integrity"
                print("PacketSize EndTime: " + str(byteEndTime))
                
            else:
                self.rxIndex = self.rxIndex + 1
 
        
        elif self.rxField == "Integrity": 
            print("Integrity")
            self.checksumByteArray.append(newByte)

            if self.rxIndex == 0:
                self.startLabelTime = byteStartTime
                print("PacketSize StartTime: " + str(byteStartTime))
            
            if self.rxIndex == 1:
                self.checksum16 = int.from_bytes(self.checksumByteArray, byteorder='little')
                calcChecksum = checksum16(self.buffer)
                if calcChecksum == self.checksum16:
                    self.frameLabel   = "Checksum:Valid"
                else:
                    self.frameLabel = "Checksum:Invalid"

                self.endLabelTime = byteEndTime
                self.isLabelReady = True
                self.rxIndex = 0
                self.rxField = "Guard"
                print("PacketSize EndTime: " + str(byteEndTime))
                self.isPacketcomplete = True
                
            else:
                self.rxIndex = self.rxIndex + 1

    def IsFrameLabelReady(self):
        if self.isLabelReady:
            return True
        else:
            return False

    def GetFrameStartTime(self):
        return self.startLabelTime
    def GetFrameEndTime(self):
        return self.endLabelTime
    def GetFrameLabel(self):
        return self.frameLabel
    def ClearFrameLabel(self):
        self.isLabelReady = False
        self.startLabelTime = 0
        self.endLabelTime = 0
        self.frameLabel = ''


        # if self.rxIndex < numGuardBytes:
            
        # elif (self.rxIndex < (numGuardBytes + numPacketSizeFieldBytes)):
        #     print("Size Bytes")
        #     print(str(newByte))
        #     self.packetSizeByteArray.append(newByte)
        #     self.rxIndex = self.rxIndex + 1
        #     if (self.rxIndex == (numGuardBytes + numPacketSizeFieldBytes)):
        #         self.packetSize = int.from_bytes(self.packetSizeByteArray, byteorder='little')
        #         print(self.packetSize)
        # elif (self.rxIndex == sequenceNumberIndex):
        #     print("Sequence Number")
        #     print(str(newByte))
        #     self.rxIndex = self.rxIndex + 1
        # elif (self.rxIndex == commandIndex):
        #     print("Command Code")
        #     print(str(newByte))
        #     self.rxIndex = self.rxIndex + 1
        #     if (numDataBytes == 0):
        #         print("No Data")
        # elif (self.rxIndex <= dataEndIndex):
        #     print("Data")
        #     print(str(newByte))
        #     self.rxIndex = self.rxIndex + 1
        # elif(self.rxIndex < numGuardBytes + 2 + self.packetSize): 
        #     print("Integrity Check")
        #     print(str(newByte))
        #     self.rxIndex = self.rxIndex + 1


        # self.buffer.append(newByte)


def checksum16(byteArray):

    localByteArray = byteArray[:] 

    numBytes = len(localByteArray)
    if (numBytes % 2) == 1:
        localByteArray.append(0)
        numBytes = len(localByteArray)
  
    checksum = 0 
      
    for i in range(0, int(numBytes/2)):
        startInd = i*2
        endInd   = startInd + 2 
        curr16bits = int.from_bytes(localByteArray[startInd:endInd], byteorder='little')  
        checksum = checksum + curr16bits
        if checksum > 65535:
            checksum = checksum - 65536
 
    return checksum