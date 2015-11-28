# Author: Michael Molho
#
# Description:
#   [MS-EVEN] Interface implementation
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/CoreSecurity/impacket/tree/master/impacket/testcases/SMB_RPC
#
#   Some calls have helper functions, which makes it even easier to use.
#   They are located at the end of this file. 
#   Helper functions start with "h"<name of the call>.
#   There are test cases for them too. 
#


# MS Documentation: https://msdn.microsoft.com/en-us/library/cc231253.aspx

from binascii import unhexlify

from impacket.dcerpc.v5.ndr import NDRCALL, NDR, NDRSTRUCT, NDRUNION, NDRPOINTER, NDRUniConformantArray, \
    NDRUniConformantVaryingArray, NDRArray, NDRENUM
from impacket.dcerpc.v5.dtypes import NULL, WSTR, PWCHAR, WCHAR, RPC_UNICODE_STRING, ULONG, USHORT, UCHAR, LARGE_INTEGER, RPC_SID, LONG, STR, \
    LPBYTE, SECURITY_INFORMATION, PRPC_SID, PRPC_UNICODE_STRING, LPWSTR
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import nt_errors, LOG
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum
from impacket.structure import Structure
from impacket.dcerpc.v5.samr import RPC_STRING
import struct

MSRPC_UUID_EVENTLOG   = uuidtup_to_bin(('82273FDC-E32A-18C3-3F78-827929DC23EA', '0.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if nt_errors.ERROR_MESSAGES.has_key(key):
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1] 
            return 'EVENTLOG SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'EVENTLOG SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################

class EVENTLOG_OPENUNKNOWN(NDRSTRUCT):
   structure = (
       ('Unknown0', USHORT),
       ('Unknown1', USHORT),
   ) 

class PEVENTLOG_OPENUNKNOWN(NDRPOINTER):
    referent = (
        ('Data', EVENTLOG_OPENUNKNOWN),
    )

# 2.2.6 IELF_HANDLE
class IELF_HANDLE(NDR):
    structure =  (
        ('Data','20s=""'),
    )

class EVENTLOG_READ_BUFFER( NDRArray ):
    item = 'c'

    structure = (
        ('Len', '<L'),
        ('Data', '*Len'), 
    )


################################################################################
# RPC CALLS
################################################################################

class EventLogOpenEventLogW(NDRCALL):
    opnum = 7
    structure = (
        ('Unused', PEVENTLOG_OPENUNKNOWN),
        ('ModuleName', RPC_UNICODE_STRING),
        ('RegModuleName', RPC_UNICODE_STRING),
        ('MajorVersion', ULONG),
        ('MinorVersion', ULONG),
    )

class EventLogOpenEventLogWResponse(NDRCALL):
    structure = (
        ('LogHandle', IELF_HANDLE),
        ('ErrorCode', ULONG),
    )

class EventLogNumberOfRecords(NDRCALL):
    opnum = 4
    structure = (
        ('LogHandle', IELF_HANDLE),
    )

class EventLogNumberOfRecordsResponse(NDRCALL):
    structure = (
        ('NumberOfRecors', ULONG),
        ('ErrorCode', ULONG),
    )

class EventLogReadEventLog(NDRCALL):
    opnum = 10
    structure = (
        ('LogHandle', IELF_HANDLE),
        ('ReadFlags', ULONG),
        ('RecordOffset', ULONG),
        ('BytesToRead', ULONG),
    ) 

class EventLogReadEventLogResponse(NDRCALL):
    structure = (
        ('Buffer', EVENTLOG_READ_BUFFER),
        ('BytesRead', ULONG),
        ('ReadSize', ULONG),
    )


OPNUMS = {
 7 :  (EventLogOpenEventLogW, EventLogOpenEventLogWResponse),
 4 :  (EventLogNumberOfRecords, EventLogNumberOfRecordsResponse),
 10 : (EventLogReadEventLog, EventLogReadEventLogResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################

def hEventLogOpenEventLogW(dce, sourceName):
    request = EventLogOpenEventLogW()
    request['Unused']['Unknown0'] = 67
    request['Unused']['Unknown1'] = 0
    request['ModuleName'] = sourceName
    request['RegModuleName'] = ''
    request['MajorVersion'] = 1
    request['MinorVersion'] = 1
    return dce.request(request)

def hEventLogNumberOfRecords(dce, logHandle):
    request = EventLogNumberOfRecords()
    request['LogHandle'] = logHandle
    return dce.request(request)

def hEventLogReadEventLog(dce, logHandle):
    request = EventLogReadEventLog()
    request['LogHandle'] = logHandle
    request['ReadFlags'] = 0x00000001 | 0x00000008
    request['BytesToRead'] = 1000
    return dce.request(request)
    
