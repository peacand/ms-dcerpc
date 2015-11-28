#!/usr/bin/python

import sys
import string
import time
import logging
from impacket.examples import logger 
from impacket import smb, version, smb3, nt_errors, version
from impacket.nt_errors import STATUS_MORE_ENTRIES 
from impacket.dcerpc.v5 import samr, transport, srvs, lsat, lsad, eventlog
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.ndr import NDR
from impacket.smbconnection import *
import argparse
import ntpath
import cmd
import os
import struct

basehdr = ( 
    'Size',
    'Reserved',
    'RecordNumber',
    'TimeGenerated',
    'TimeWritten',
    'EventId',
    'EventType',
    'NumberStrings',
    'EventCategory',
    'ReservedFlags',
    'ClosingRecordNumber',
    'StringsOffset',
    'SidLen',
    'SidOffset',
    'DataLen',
    'DataOffset'
)

BASEHDR_SIZE = 4*6+4*2+6*4
STR_TERMINATOR = '\x00\x00\x00'

def dump(event):
    maxlen = 0
    for key in event:
        if len(key) > maxlen:
            maxlen = len(key)
    for key in event:
        if hasattr(event[key], '__iter__'):
            print key + ':'
            for i in event[key]:
                print '  ' + str(i)
        else:
            print key.ljust(maxlen+1) + ': ' + str(event[key])
            pass
    return ''


def load_data(model, data):
    res = {}
    i = 0
    if len(model) != len(data):
        return None
    while i < len(model):
        res[model[i]] = data[i]
        i += 1
    return res

def read_string(data):
    end = data.find(STR_TERMINATOR)
    if end >= 0:
        return data[:end]
    else:
        return ''

def parse_events(data, readlen):
    raw = ''.join(data)
    events = []
    soFar = 0
    size = struct.unpack('<L', raw[soFar:soFar+4])[0]
    while size > 0:
        entry = {}
        fullevent = raw[soFar:soFar + size]
        hdr = struct.unpack('<LLLLLLHHHHLLLLLL', fullevent[:BASEHDR_SIZE])
        entry = load_data(basehdr, hdr)
        sourceName = read_string(fullevent[BASEHDR_SIZE:])
        computerName = read_string(fullevent[BASEHDR_SIZE + len(sourceName) + len(STR_TERMINATOR):])
        entry['SourceName'] = sourceName
        entry['ComputerName'] = computerName
        # read all strings
        i = 0
        soFarStrings = 0
        entry['Strings'] = []
        while i < entry['NumberStrings']:
            entry['Strings'].append( read_string(fullevent[entry['StringsOffset']+soFarStrings:]).decode('iso-8859-1').encode('utf-8') )
            soFarStrings += len(entry['Strings'][i]) + len(STR_TERMINATOR)
            i += 1
        entry['Data'] = fullevent[entry['DataOffset']:entry['DataOffset']+entry['DataLen']]
        events.append(entry)
        soFar += size
        size = struct.unpack('<L', raw[soFar:soFar+4])[0] 
    return events



rpctransport = transport.DCERPCTransportFactory('ncacn_np:' + sys.argv[1] + '[\pipe\eventlog]')
rpctransport.set_credentials(sys.argv[2], sys.argv[3], sys.argv[4], '', '')
rpctransport.set_dport(445)

dce = rpctransport.get_dce_rpc()
dce.connect()                     
dce.bind(eventlog.MSRPC_UUID_EVENTLOG)

resp = eventlog.hEventLogOpenEventLogW(dce, sys.argv[5])
logHandle = resp['LogHandle']

resp = eventlog.hEventLogNumberOfRecords(dce, logHandle)
print "\n[*] " + str(resp['NumberOfRecors']) + " \"" + sys.argv[5] + "\" Windows Events were found ! Reading first 1000 bytes ...\n\n"

for i in xrange(1):
    resp = eventlog.hEventLogReadEventLog(dce, logHandle)
    data = resp['Buffer']
    logs = parse_events(data, resp['BytesRead'])
    for log in logs:
        print "\n### New Event ###\n"
        dump(log)
