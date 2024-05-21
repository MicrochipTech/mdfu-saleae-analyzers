import BidirectionalLookupTableIntsMapToStrings as blt
import math as math

uninitializedCommandCode = 0
cmdCodes = {1:"GetClientInfo",
            2:"StartTransfer",
            3:"WriteChunk", 
            4:"GetImageState",
            5:"EndTransfer"}

cmdResponseCodes = {0:"Reserved0",
                    1:"SUCCESS",
                    2:"CMD_NOT_SUPPORTED",
                    3:"Reserved3",
                    4:"TRANSPORT_FAILURE",
                    5:"ABORT_FILE_TRANSFER"} 

writeStatusList = {1:"WRITESUCCESS",
                   2:"ADDRESSMISALIGNED",
                   3:"INVALIDWRITELENGTH",
                   4:"PAGEERASEERROR",
                   5:"WRITEERROR",
                   6:"ADDRESSOUTOFRANGE"}

imageStates = {1:"fileValid",
               2:"fileInvalid"}


paramTypes = {1:"M-DFUVersion",
              2:"ClientBufferInfo",
              3:"CmdTimeouts"}

class CommandsAndResponses():

    def __init__(self):
        self.cmds        = blt.BidirectionalLookupTableIntsMapToStrings("Command Codes", cmdCodes)
        self.responses   = blt.BidirectionalLookupTableIntsMapToStrings("command response codes", cmdResponseCodes)
        self.imageStates = blt.BidirectionalLookupTableIntsMapToStrings("Image States", imageStates)
        self.writeStatus = blt.BidirectionalLookupTableIntsMapToStrings("Write Status", writeStatusList) 
        self.paramTypes  = blt.BidirectionalLookupTableIntsMapToStrings("Parameter Types", paramTypes) 

cmdAResp = CommandsAndResponses()


#  ------- Generic Command And Response Classes --------------------------------------

class Command:

    def __init__(self, cmdCode, dataByteArray):
        self.cmdCode = cmdCode
        self.data = dataByteArray
        self.dataLength = len(self.data)
        self.byteArray  = BuildCommandByteArray(self.cmdCode, self.data)

    def GetByteArray(self):
        return self.byteArray

class Response: 
    def __init__(self): 
        self.status      = 0 
        self.data        = bytearray(0)
        self.dataLength  = 0 
        self.byteArray   = 0

    def SetResponsePayload(self, payloadByteArray):
        self.byteArray = payloadByteArray
        self.status = payloadByteArray[0]
        self.data   = payloadByteArray[1:]

        if self.status != cmdAResp.responses.GetValue("CMDSUCCESS"):
            raise ValueError("Command Failed to Execute with Status: " + cmdAResp.responses.GetString(self.status))


# ------- Specific Command Response Pair Classes / Logic ----------------------------------

class TargetBufferInfo:
    def __init__(self):
        self.cmd      = Command(cmdAResp.cmds.GetValue("GetClientInfo"), dataByteArray=bytearray(0)) 
        self.response = Response()  

    def GetBlockTransferSize(self): 
        blockTransferSize = int.from_bytes(self.response.data[0:2], 'little')
        return blockTransferSize
        
class StartTransfer:
    def __init__(self):
        self.cmd      = Command(cmdAResp.cmds.GetValue("StartTransfer"), dataByteArray=bytearray(0)) 
        self.response = Response()
      
class WriteChunk:
    def __init__(self, fileChunkByteArray):
        self.cmd      = Command(cmdAResp.cmds.GetValue("WriteChunk"), dataByteArray=fileChunkByteArray) 
        self.response = Response()
           
class GetImageState:
    def __init__(self):
        self.cmd      = Command(cmdAResp.cmds.GetValue("GetImageState"), dataByteArray=bytearray(0)) 
        self.response = Response()
           
class EndTransfer:
    def __init__(self):
        self.cmd      = Command(cmdAResp.cmds.GetValue("EndTransfer"), dataByteArray=bytearray(0)) 
        self.response = Response()
            

def BuildCommandByteArray(cmdCode, dataByteArray):
    cmdByteArray = bytearray(0) 
    cmdByteArray.append(cmdCode)
    cmdByteArray.extend(dataByteArray) 
    return cmdByteArray 


# def PrintCommandInfo(cmd, logInterface):
#     logInterface.LogLine("", logLevel=1)
#     # logInterface.LogLine("CMD - " + cmdAResp.cmds.GetString(cmd.cmdCode), logLevel=1)
#     # logInterface.LogLine(" - Command Code: " + str(cmd.cmdCode) + " = " + cmdAResp.cmds.GetString(cmd.cmdCode), logLevel=3)
#     logInterface.LogLine(" - Data Length: " + str(cmd.dataLength), logLevel=3)
#     # logInterface.LogLine(str(self.data))
#     if cmd.dataLength > 0:
#         logInterface.LogLine(" - Data: ", logLevel=2)
#         PrintByteArray(cmd.data, 16, "     ", logInterface) 
#     else:
#         logInterface.LogLine(" - Data: No Data In Frame", logLevel=3)


# def PrintByteArray(byteArray, numBytesPerLine, indentString, logInterface):

#     byteNumInLine = 0 
#     currByteNum = 0
#     incompleteLine = True
#     numBytes = len(byteArray)

#     if len(byteArray) > 0:
#         numCharsForBytenum = int(math.log10(len(byteArray))) + 1 
#         formatStr = '{0:' + str(numCharsForBytenum) + '}'

#         lineStr = ''
#         for byte in byteArray:

#             incompleteLine = True

#             if byteNumInLine == 0:
#                 lastByteInLine = currByteNum + numBytesPerLine - 1
#                 if lastByteInLine > numBytes:
#                     lastByteInLine = numBytes - 1
#                 if (byteNumInLine == 0) and (currByteNum == (numBytes - 1)):
#                     lineStr += indentString + formatStr.format(currByteNum) + "   " + " "*numCharsForBytenum + ": "
#                 else:
#                     lineStr += indentString + formatStr.format(currByteNum) + " - " + formatStr.format(lastByteInLine) + ": "  
            
#             lineStr += bytearray([byte]).hex()

#             currByteNum += 1
#             byteNumInLine += 1
#             if byteNumInLine == numBytesPerLine:
#                 byteNumInLine = 0
#                 logInterface.LogLine(lineStr, logLevel=2)
#                 lineStr = ''
#                 incompleteLine = False
#             elif currByteNum != len(byteArray):
#                 lineStr += ','

#         if incompleteLine:
#             logInterface.LogLine(lineStr, logLevel=2)

#     else: 
#         logInterface.LogLine(indentString + "Data Field is Empty", logLevel=2)
        
     

