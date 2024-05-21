# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

import BidirectionalLookupTableIntsMapToStrings as blt
import FileTransferCommandsAndResponses as CandR

CMD_READY_MASK = 0x01
RSP_READY_MASK = 0x02
RSP_LEN_MASK   = 0x80
def GetStatusLabel(statusValue):
    label = '' 
    if statusValue & CMD_READY_MASK:
        label += "CMD_READY "
    if statusValue & RSP_READY_MASK:
        label += "RSP_RDY"
        
        if statusValue & RSP_LEN_MASK:
            label += ": Response Field"
        else:
            label += ": Length Field" 

    if not (statusValue & (CMD_READY_MASK| RSP_READY_MASK)):
        label = "Client Busy"

    return label

class Frame:
    def __init__(self, startTime, endTime, label, data):
        self.startTime = startTime
        self.endTime   = endTime
        self.label     = label
        self.data      = data

    def UpdateLabel(self, label):
        self.label = label

    def SetStartTime(self, startTime):
        self.startTime = startTime

    def SetEndTime(self, endTime):
        self.endTime = endTime

    def GetAnalyzerFrame(self):
        frameLabelFormatType = 'mdfu_frame' 
        frameLabelData = {'labelText': self.label} 
        return AnalyzerFrame(frameLabelFormatType, self.startTime, self.endTime, frameLabelData)

def GetTimeStringFromGraphTimeDelta(graphTimeDelta):
    timeSeconds = graphTimeDelta.__float__() 
    if timeSeconds > 1:
        timeString = '{:.1f}'.format(timeSeconds) + ' s'
    elif timeSeconds > 0.001:
        timeString = '{:.1f}'.format(timeSeconds*1000) + ' ms' 
    elif timeSeconds > 0.000001:
        timeString = '{:.1f}'.format(timeSeconds*1000000) + ' us' 
    elif timeSeconds > 0.000000001:
        timeString = '{:.1f}'.format(timeSeconds*1000000000) + ' ns' 
    else:
        timeString = str(timeSeconds) + " s"
    # print(str(timeString))
    return timeString

class ClockStretch:
    def __init__(self, startTime=0, endTime=0.1):
        self.startTime = startTime
        self.endTime   = endTime
        self.label     = '' 

    def UpdateLabel(self, label):
        self.label = label

    def SetStartTime(self, startTime):
        self.startTime = startTime

    def SetEndTime(self, endTime):
        self.endTime = endTime

    def GetCSTime(self):
        cs_time = self.endTime - self.startTime
        return cs_time.__float__()
    
    def GetAnalyzerFrame(self):
        frameLabelFormatType = 'mdfu_frame' 
        # self.label = "CS:"
        cs_time = self.endTime - self.startTime
        timeString = GetTimeStringFromGraphTimeDelta(cs_time)
        self.label = timeString
        frameLabelData = {'labelText': self.label} 
        return AnalyzerFrame(frameLabelFormatType, self.startTime, self.endTime, frameLabelData)



# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    # my_string_setting = StringSetting()
    # my_number_setting = NumberSetting(min_value=0, max_value=100)
    # my_choices_setting = ChoicesSetting(choices=('A', 'B'))
    
    decode_selection = ChoicesSetting(choices=('Protocol', 'All Clock Stretching', 'Clock Stretching Violations'))
    status_byte = ChoicesSetting(choices=('No Status Byte', 'Status Byte'))
    max_clock_stretch_time_seconds = NumberSetting(min_value=0.035)
    # decode_clock_streching = ChoicesSetting(choices=('No', 'Show All Clock Stretching', 'Only Show Violations')) 

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'mdfu_frame': {
            'format': '{{data.labelText}}'
        },
        'test_frame': {
            'format': '{{data.labelText}}'
        }
    }  

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        ''' 
        self.max_cs_time = self.max_clock_stretch_time_seconds
        self.openFrame = False
        self.rawFrames = []
        self.Analyzer = CommandAnalzyer()
        self.responseField = "length"
        self.type = 'cmd'
        self.currentClockStretch = ClockStretch()
        self.clockStretchFrames = []

        if self.status_byte == 'Status Byte':
            self.isStatusByteImplemented = True
        else:
            self.isStatusByteImplemented = False
        print(" ---------- Starting Analzyer -----------")

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        if frame.type == 'address': 
            if frame.data['ack']:
                self.openFrame = True
                self.rawFrames = []
                self.clockStretchFrames = []
                self.currentClockStretch.SetStartTime(frame.end_time)
                if frame.data['read']:
                    print("Start - Read")
                    if self.responseField == "length":
                        self.type = 'length'
                        self.Analyzer = ResponseLengthAnalzyer(self.isStatusByteImplemented)
                        frameLabelFormatType = 'mdfu_frame' 
                        frameLabelData = {'labelText': 'R Length'}
                        if self.decode_selection == "Protocol":  
                            return AnalyzerFrame(frameLabelFormatType, frame.start_time, frame.end_time, frameLabelData) 
                    elif self.responseField == "response":
                        self.type = 'response'
                        self.Analyzer = ResponseAnalzyer(self.isStatusByteImplemented)
                        frameLabelFormatType = 'mdfu_frame' 
                        frameLabelData = {'labelText': 'Response'}
                        self.responseField = "length"
                        if self.decode_selection == "Protocol":  
                            return AnalyzerFrame(frameLabelFormatType, frame.start_time, frame.end_time, frameLabelData) 
                        
                        
                else:
                    print("Start - Write") 
                    self.type = 'cmd'
                    self.Analyzer = CommandAnalzyer() 
                    frameLabelFormatType = 'mdfu_frame' 
                    frameLabelData = {'labelText': 'Command'}
                    self.responseField = "length" 
                    if self.decode_selection == "Protocol":  
                        return AnalyzerFrame(frameLabelFormatType, frame.start_time, frame.end_time, frameLabelData) 
            else:
                self.openFrame = False
                cs_time = frame.end_time - frame.start_time
                timeString = GetTimeStringFromGraphTimeDelta(cs_time) 
                frameLabelFormatType = 'mdfu_frame' 
                frameLabelData = {'labelText': timeString}
                return AnalyzerFrame(frameLabelFormatType, frame.start_time, frame.end_time, frameLabelData) 
        elif frame.type == "stop":
            if self.openFrame:
                
                self.currentClockStretch.SetEndTime(frame.start_time)
                if self.decode_selection == "All Clock Stretching":
                    self.clockStretchFrames.append(self.currentClockStretch.GetAnalyzerFrame())
                elif self.decode_selection == "Clock Stretching Violations":
                    cs_time = self.currentClockStretch.GetCSTime()
                    if cs_time >= self.max_cs_time:
                        self.clockStretchFrames.append(self.currentClockStretch.GetAnalyzerFrame())

                self.openFrame = False
                self.Analyzer.SetEndOfFrame()

                print("Stop")
                # frameList = []
                # if self.type == 'response':
                print(self.responseField)
                if self.isStatusByteImplemented:
                    advanceThreshold = 2
                else:
                    advanceThreshold = 1
                frameList = self.Analyzer.GetFrameList()
                if len(frameList) > advanceThreshold:
                    if self.type == "cmd":
                        self.responseField = "length"
                    elif self.responseField == "length":
                        self.responseField = "response"

                self.Analyzer.ClearPacket()
                
                if self.decode_selection == "Protocol":  
                    return frameList
                else: 
                    return self.clockStretchFrames 
 
        elif frame.type == "data":
            # print("Data")
            self.currentClockStretch.SetEndTime(frame.start_time)
            if self.decode_selection == "All Clock Stretching":
                self.clockStretchFrames.append(self.currentClockStretch.GetAnalyzerFrame())
            elif self.decode_selection == "Clock Stretching Violations":
                cs_time = self.currentClockStretch.GetCSTime()
                if cs_time >= self.max_cs_time:
                    self.clockStretchFrames.append(self.currentClockStretch.GetAnalyzerFrame())

            self.currentClockStretch.SetStartTime(frame.end_time)
            print(frame.data['data']) 
            newByte = frame.data['data'][0] 
            self.Analyzer.ProcessIncomingByte(newByte, frame.start_time, frame.end_time)
            
class CommandAnalzyer:
    def __init__(self): 
        # self.frames = []
        self.rawFrames = []
        self.labelFrames = []
        self.escapeByte = 0
        self.isEscapeByte = False
        self.CandR = CandR.CommandsAndResponses() 
        self.isPacketcomplete = False
        self.numBytesReceived = 0
        self.numEscapeCharsReceived = 0
        self.cmdString = ''
        self.seq = ''
        
        self.packetNumber = 0

    def ClearPacket(self):
        self.rawFrames = []
        self.labelFrames = []
        self.escapeByte = 0
        self.isEscapeByte = False 
        self.isPacketcomplete = False

    def IsPacketComplete(self):
        if self.isPacketcomplete:
            return True
        else:
            return False

    def ProcessIncomingByte(self, newByte, byteStartTime, byteEndTime):

        

        self.rawFrames.append(Frame(byteStartTime, byteEndTime, "---S:" + str(self.packetNumber), newByte))
        self.numBytesReceived += 1

    def SetEndOfFrame(self): 
        self.UpdateFrameLables()
        self.isPacketcomplete = True
        self.packetNumber += 1
        self.isEscapeByte = False 
    
    def GetFrameList(self):
        frameList = []
        for frame in self.labelFrames:
            frameList.append(frame.GetAnalyzerFrame())

        return frameList
        
    def UpdateFrameLables(self): 

        # Too few bytes for a valid frame
        if len(self.rawFrames) < 4:
            self.labelFrames.append(Frame(self.rawFrames[0], self.rawFrames[-1],"Invalid Frame: Too Few Bytes"), 0)
        else: 
            
            bytesToChecksum = bytearray(0)


            seqFrame = self.rawFrames[0]
            seqByte = seqFrame.data 
            if seqByte & 0b10000000: 
                label = "Seq:" + str(seqByte & 0b00011111) + ":Sync"
            else:
                label = "Seq:" + str(seqByte & 0b00011111)
            self.seq = label
            seqFrame.UpdateLabel(label) 
            self.labelFrames.append(seqFrame)
            bytesToChecksum.append(seqFrame.data)

            cmdFrame = self.rawFrames[1]
            cmdFrame.UpdateLabel("Cmd") 
            cmdByte = cmdFrame.data
            label = self.CandR.cmds.GetString(cmdByte)
            self.cmdString = label
            cmdFrame.UpdateLabel("Cmd:" + label) 
            self.labelFrames.append(cmdFrame)
            bytesToChecksum.append(cmdFrame.data)

            numDataBytes = len(self.rawFrames) - 4
            if numDataBytes > 0:
                startIndex = 2 
                startTime = self.rawFrames[2].startTime
                endTime   = self.rawFrames[-3].endTime
                if cmdByte == self.CandR.cmds.GetValue("WriteChunk"):
                    dataFrame = Frame(startTime, endTime, str(numDataBytes) + " Bytes From File", 0) 
                else: 
                    dataFrame = Frame(startTime, endTime, "Data Payload", 0) 
                self.labelFrames.append(dataFrame)
                for i in range(0, numDataBytes):
                    byteFrame = self.rawFrames[i+startIndex]
                    bytesToChecksum.append(byteFrame.data)
                    # byteFrame.UpdateLabel()
                    # self.labelFrames.append(byteFrame)
                
            csumStartTime = self.rawFrames[-2].startTime
            csumEndTime   = self.rawFrames[-1].endTime
            msgChecksum = (self.rawFrames[-1].data * 256) + self.rawFrames[-2].data 
            calcChecksum = checksum16(bytesToChecksum) 
            if msgChecksum == calcChecksum:
                label = "Checksum Valid"
            else:
                label = "Invalid Checksum!"
                print("Invalid Checksum!!")
            csumFrame = Frame(csumStartTime, csumEndTime,label, msgChecksum)
            self.labelFrames.append(csumFrame)


    # def IsFrameLabelReady(self):
    #     if self.isLabelReady:
    #         return True
    #     else:
    #         return False

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
 
    return ((~checksum) & 0xFFFF)


class ResponseLengthAnalzyer:
    def __init__(self, isStatusByteImplemented): 
        # self.frames = []
        self.rawFrames = []
        self.labelFrames = [] 
        self.CandR = CandR.CommandsAndResponses() 
        self.isPacketcomplete = False
        self.numBytesReceived = 0
        self.numEscapeCharsReceived = 0
        self.packetNumber = 0
        self.isStatusByteImplemented = isStatusByteImplemented
        # self.inferResponsePayloadMeanings = inferResponsePayloadMeanings

    def ClearPacket(self):
        self.rawFrames = []
        self.labelFrames = []  
        self.isPacketcomplete = False

    def IsPacketComplete(self):
        if self.isPacketcomplete:
            return True
        else:
            return False

    def ProcessIncomingByte(self, newByte, byteStartTime, byteEndTime):

         
        self.rawFrames.append(Frame(byteStartTime, byteEndTime, "0x{:02X}".format(newByte), newByte))  
        self.numBytesReceived += 1
  

    def SetEndOfFrame(self):  
        self.UpdateFrameLables()
        self.isPacketcomplete = True
        self.packetNumber += 1 
 
    
    def GetFrameList(self):
        frameList = []
        for frame in self.labelFrames:
            frameList.append(frame.GetAnalyzerFrame())

        return frameList
        
    def UpdateFrameLables(self): 

        # Too few bytes for a valid frame
        
        if self.isStatusByteImplemented:
            minFrameSize = 5
        else:
            minFrameSize = 4
        if self.isStatusByteImplemented and (len(self.rawFrames) == 1):
            statusFrame = self.rawFrames[0]
            label = GetStatusLabel(statusFrame.data)
            statusFrame.UpdateLabel(label)
            self.labelFrames.append(statusFrame)
        elif len(self.rawFrames) < minFrameSize:
        
            self.labelFrames.append(Frame(self.rawFrames[0].startTime, self.rawFrames[-1].endTime,"Invalid Frame: Too Few Bytes", 0))
        else: 
            
            index = 0
            if self.isStatusByteImplemented:
                statusFrame = self.rawFrames[index]
                label = GetStatusLabel(statusFrame.data)
                statusFrame.UpdateLabel(label)
                self.labelFrames.append(statusFrame)
                index += 1

            bytesToChecksum = bytearray(0)
 
            lengthLow  = self.rawFrames[index]
            lengthHigh = self.rawFrames[index+1]
            bytesToChecksum.append(lengthLow.data) 
            bytesToChecksum.append(lengthHigh.data) 
            length = lengthLow.data + lengthHigh.data * 256
            lengthLabel = "Length: " + str(length)
            lengthFrame = Frame(lengthLow.startTime, lengthHigh.endTime,lengthLabel, length)
            self.labelFrames.append(lengthFrame)
            index += 2
            # numDataBytesProcessed += 2 
  
 
            csumStartTime = self.rawFrames[-2].startTime
            csumEndTime   = self.rawFrames[-1].endTime
            msgChecksum = (self.rawFrames[-1].data * 256) + self.rawFrames[-2].data 
            calcChecksum = checksum16(bytesToChecksum) 
            if msgChecksum == calcChecksum:
                label = "Checksum Valid"
            else:
                label = "Invalid Checksum!"
                print("Invalid Checksum!!")
            csumFrame = Frame(csumStartTime, csumEndTime,label, msgChecksum)
            self.labelFrames.append(csumFrame)
 

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




class ResponseAnalzyer:
    def __init__(self, isStatusByteImplemented): 
        # self.frames = []
        self.rawFrames = []
        self.labelFrames = []
        self.escapeByte = 0
        self.isEscapeByte = False
        self.CandR = CandR.CommandsAndResponses() 
        self.isPacketcomplete = False
        self.numBytesReceived = 0
        self.numEscapeCharsReceived = 0
        self.packetNumber = 0
        
        self.isStatusByteImplemented = isStatusByteImplemented
        # self.inferResponsePayloadMeanings = inferResponsePayloadMeanings

    def ClearPacket(self):
        self.rawFrames = []
        self.labelFrames = []
        self.escapeByte = 0
        self.isEscapeByte = False 
        self.isPacketcomplete = False

    def IsPacketComplete(self):
        if self.isPacketcomplete:
            return True
        else:
            return False

    def ProcessIncomingByte(self, newByte, byteStartTime, byteEndTime):

         
        self.rawFrames.append(Frame(byteStartTime, byteEndTime, "0x{:02X}".format(newByte), newByte))   
        self.numBytesReceived += 1
  
    def SetEndOfFrame(self): 
        self.UpdateFrameLables()
        self.isPacketcomplete = True
        self.packetNumber += 1 
 
    def GetFrameList(self):
        frameList = []
        for frame in self.labelFrames:
            frameList.append(frame.GetAnalyzerFrame())

        return frameList
        
    def UpdateFrameLables(self): 

        if self.isStatusByteImplemented:
            minFrameSize = 5
        else:
            minFrameSize = 4

        # Too few bytes for a valid frame
        if self.isStatusByteImplemented and (len(self.rawFrames) == 1):
            statusFrame = self.rawFrames[0]
            label = GetStatusLabel(statusFrame.data)
            statusFrame.UpdateLabel(label)
            self.labelFrames.append(statusFrame)
        elif len(self.rawFrames) < minFrameSize:
        
            self.labelFrames.append(Frame(self.rawFrames[0].startTime, self.rawFrames[-1].endTime,"Invalid Frame: Too Few Bytes", 0))
        else: 
            index = 0
            if self.isStatusByteImplemented:
                statusFrame = self.rawFrames[0]
                label = GetStatusLabel(statusFrame.data)
                statusFrame.UpdateLabel(label)
                self.labelFrames.append(statusFrame)
                index += 1
            
            bytesToChecksum = bytearray(0)
 

            seqFrame = self.rawFrames[index]
            index += 1
            seqByte = seqFrame.data 
            if seqByte & 0b01000000: 
                label = "Seq:" + str(seqByte & 0b00011111) + ":Resend"
            else:
                label = "Seq:" + str(seqByte & 0b00011111) + ":ACK"
            seqFrame.UpdateLabel(label) 
            self.labelFrames.append(seqFrame)
            bytesToChecksum.append(seqFrame.data)

            responseFrame = self.rawFrames[index] 
            index += 1
            responseStatus = responseFrame.data
            try:
                responseStatusStr = self.CandR.responses.GetString(responseStatus)
                label = responseStatusStr
            except:
                label = "MissingResponseCode"
            responseFrame.UpdateLabel(label) 
            self.labelFrames.append(responseFrame)
            bytesToChecksum.append(responseFrame.data)

            
            if self.isStatusByteImplemented:
                numDataBytes = len(self.rawFrames) - 5
            else:
                numDataBytes = len(self.rawFrames) - 4

            self.inferResponsePayloadMeanings = True

            if responseStatus == self.CandR.responses.GetValue("SUCCESS"):
                if self.inferResponsePayloadMeanings and numDataBytes > 1: 
                    startIndex = index
                    # index = startIndex

                    numDataBytesProcessed = 0

                    while (numDataBytesProcessed < numDataBytes):
                        
                        startTime = self.rawFrames[index].startTime
                        type = self.rawFrames[index].data
                        index += 1
                        numDataBytesProcessed += 1
                        length = self.rawFrames[index].data
                        index += 1
                        numDataBytesProcessed += 1
                        data = []
                        for i in range(0, length):
                            data.append(self.rawFrames[index].data)
                            endTime   = self.rawFrames[index].endTime  
                            index += 1
                            numDataBytesProcessed += 1


                        label = "T:" + "0x{:02X}".format(type) + "=" + self.CandR.paramTypes.GetString(type)
                        label += " L:" + str(length)
                        dataLabel = CreateResponseDataLabel(type, data)
                        label += " V:" + dataLabel
                        dataFrame = Frame(startTime, endTime, label , 0) 
                        self.labelFrames.append(dataFrame)


                    for i in range(0, numDataBytes):
                        byteFrame = self.rawFrames[i+startIndex]
                        bytesToChecksum.append(byteFrame.data)
                elif self.inferResponsePayloadMeanings and numDataBytes == 1:
                    startIndex = 2
                    startTime = self.rawFrames[startIndex].startTime
                    endTime   = self.rawFrames[startIndex].endTime 

                    data = self.rawFrames[startIndex].data
                    if data == 1:
                        label = "IMAGE_VALID"
                    elif data == 2:
                        label = "IMAGE_INVALID"
                    else:
                        label = "UnknownState"
                    dataFrame = Frame(startTime, endTime, label , 0) 
                    self.labelFrames.append(dataFrame)
                    for i in range(0, numDataBytes):
                        byteFrame = self.rawFrames[i+startIndex]
                        bytesToChecksum.append(byteFrame.data)
                elif numDataBytes > 0:
                    startIndex = 2 
                    startTime = self.rawFrames[2].startTime
                    endTime   = self.rawFrames[-3].endTime 
                    dataFrame = Frame(startTime, endTime, "Data Payload", 0) 
                    self.labelFrames.append(dataFrame)
                    for i in range(0, numDataBytes):
                        byteFrame = self.rawFrames[i+startIndex]
                        bytesToChecksum.append(byteFrame.data) 
            else:

                if numDataBytes > 0:
                    startIndex = 2 
                    startTime = self.rawFrames[2].startTime
                    endTime   = self.rawFrames[-3].endTime 
                    dataFrame = Frame(startTime, endTime, "Error Data Payload: Todo add decoding", 0) 
                    self.labelFrames.append(dataFrame)
                    for i in range(0, numDataBytes):
                        byteFrame = self.rawFrames[i+startIndex]
                        bytesToChecksum.append(byteFrame.data)

 
            csumStartTime = self.rawFrames[-2].startTime
            csumEndTime   = self.rawFrames[-1].endTime
            msgChecksum = (self.rawFrames[-1].data * 256) + self.rawFrames[-2].data 
            calcChecksum = checksum16(bytesToChecksum) 
            if msgChecksum == calcChecksum:
                label = "Checksum Valid"
            else:
                label = "Invalid Checksum!"
                print("Invalid Checksum!!")
            csumFrame = Frame(csumStartTime, csumEndTime,label, msgChecksum)
            self.labelFrames.append(csumFrame)
 

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


# paramTypes = {1:"M-DFUVersion",
#               2:"ClientBufferInfo",
#               3:"CmdTimeouts"}
def CreateResponseDataLabel(type, data):

    if CandR.cmdAResp.paramTypes.GetString(type) == "M-DFUVersion":
        if len(data) > 4 or len(data) < 3:
            dataLabel = "Invalid Parameter"
        else:
            dataLabel  = "Major:" + "0x{:02X}".format(data[0])
            dataLabel += ",Minor:" + "0x{:02X}".format(data[1])
            dataLabel += ",Patch:" + "0x{:02X}".format(data[2])
            if len(data) == 4:
                dataLabel += ",PreRelease:" + + "0x{:02X}".format(data[3])
    elif CandR.cmdAResp.paramTypes.GetString(type) == "ClientBufferInfo":
        if len(data) == 3:
            maxPacketDataLength = data[0] + data[1]*256
            dataLabel = "MaxPacketDataLength=0x{:04X}=".format(maxPacketDataLength)  + str(maxPacketDataLength)
            numCmdBuffers = data[2]
            dataLabel += ", NumCmdBuffers=" + str(numCmdBuffers)
        else: 
            dataLabel = "Invalid Parameter"
    elif CandR.cmdAResp.paramTypes.GetString(type) == "CmdTimeouts":
        numDataBytes = len(data)
        numBytesProcessed = 0
        dataLabel = ''
        while(numBytesProcessed < numDataBytes):
            cmdCode = data[numBytesProcessed]
            numBytesProcessed += 1
            timeout = data[numBytesProcessed] + data[numBytesProcessed+1]*256
            numBytesProcessed += 2
            if cmdCode == 0:
                dataLabel += "DefaultCmdTimeout="
            else:
                dataLabel = CandR.cmdAResp.cmds.GetString(cmdCode) + "Timeout="
            dataLabel += "0x{:04X}".format(timeout) + "=" + str(timeout*0.1) + "s,"
    else:
        dataLabel = "Invalid Parameter Type"
    return dataLabel

