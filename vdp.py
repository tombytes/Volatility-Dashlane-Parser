#Thomas Moore
#7 May 2018
#Version 1.0

import volatility.win32 as win32
import volatility.debug as debug
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.plugins.taskmods as taskmods
import volatility.plugins.filescan as filescan
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address
import volatility.commands as commands
import volatility.obj as obj
import volatility.poolscan as poolscan
import re
import struct
import os
import urllib
import openpyxl

class vdp(commands.Command):

    def calculate(self):
        '''
        addr_space = utils.load_as(self._config) # this is the loaded memory image
        for proc in tasks.pslist(addr_space):
            yield proc # this builds the "data" object (see below)
        '''
        #addr_space = utils.load_as(self._config) ### not necessary, and prevents profile issues
        FindGenPW = b'\x3C\x4B\x57\x47\x65\x6E\x65\x72\x61\x74\x65\x64\x50\x61\x73\x73\x77\x6F\x72\x64\x3E\x3C\x4B\x57\x44\x61\x74\x61\x49\x74\x65\x6D\x20\x6B\x65\x79\x3D\x22\x41\x75\x74\x68\x49\x64\x22'
        #'<KWGeneratedPassword><KWDataItem key="AuthId"'
        infile = urllib.unquote((self._config.location).split('///')[1])
        with open(infile, "rb") as fi:
 
            for match in re.finditer(FindGenPW,fi.read()):
                fi.seek(match.start())
                Offset = str(fi.tell())
                Auth=struct.unpack('55x38s', fi.read (93))
                AuthId= str(Auth[0])
                keep = b''
                keep2= b''
                keep3= b''
                keep4= b''
                keep5= b''
                while True:
                    b=fi.read(1)
                    if b == b'\x5b':
                        while True:
                            b=fi.read(1)
                            if b != b'\x5d':
                                keep += b
                                Domain = str(keep[6:40])
                            else:
                                break
                        break
                while True:    
                    b=fi.read(1)
                    if b == b'\x5b':
                        while True:
                            b=fi.read(1)
                            if b != b'\x5d':
                                keep2 += b
                                GenDate = (keep2[6:20])
                            else:
                                break
                        break
                while True:
                    b=fi.read(1)
                    if b == b'\x5b':
                        while True:
                            b=fi.read(1)
                            if b != b'\x5d':
                                keep3 += b
                                Id = str(keep3[6:50])
                            else:
                                break
                        break
                while True:
                    b=fi.read(1)
                    if b == b'\x5b':
                        while True:
                            b=fi.read(1)
                            if b != b'\x5d':
                                keep4 += b
                                LastBackTime=(str(keep4[6:20]))
                            else:
                                break
                        break
                while True:
                    b=fi.read(1)
                    if b == b'\x5b':
                        while True:
                            b=fi.read(1)
                            if b != b'\x5d':
                                keep5 += b
                                GenPass = (str(keep5[6:40]))
                            else:
                                break
                        break
				
                info = [Offset,AuthId,Domain,GenDate,Id,LastBackTime,GenPass]
                yield info

    def render_text(self, outfd, data): # text output
        """This method formats output to the terminal.
        :param
            outfd | <file>
            data | <generator>
        """
        for info in data:
            #outfd.write("Domain: {0}\nGenDate: {1}\nId: {2}\nLastBackupTime: {3}\nGenPass: {4}\n".format(info[0], info[1], info[2], info[3], info[4]))
            outfd.write("Offset: {0}\nAuthId: {1}\nDomain: {2}\nGenerated date: {3}\nId: {4}\nLast Backup Time: {5}\nPassword: {6}\n\n".format(info[0], info[1], info[2], info[3], info[4], info[5], info[6]))

    def render_csv(self, outfd, data): # CSV output
        """This method formats output to the terminal.
        :param
            outfd | <file>
            data | <generator>
        """
        for info in data:
            outfd.write("{0},{1},{2},{3},{4},{5},{6}\n".format(info[0], info[1], info[2], info[3], info[4], info[5], info[6]))




    #THIS IS VOLATILITY'S NEW UNIFIED OUTPUT THEY WANT DEVELOPERS TO USE:
            #CURRENTLY RESULTS IN ERROR: 
            #ERROR   : volatility.debug    : 'tuple' object is not callable


    # def unified_output(self, data):
    #     """This standardizes the output formatting"""
        
    #     ## make sure the number of columns (4) and their data types match
    #     ## what calculate() and generator() yields 

    #     return TreeGrid([("Offset", str),
    #                     ("AuthId", str),
    #                     ("Domain", str),
    #                     ("Generated Date", str)
    #                     ("Id", str)
    #                     ("Password", str)],
    #                     self.generator(data))

    # def generator(self, data):
    #     """This yields data according to the unified output format"""

    #     ## the variables "unpacked" here must match what calculate() yields 
    #     for Offset, AuthId, Domain, GenDate, Id, LastBackTime, GenPass in data:

    #         ## make sure to wrap each variable according to its data type 
    #         yield (0, [str(Offset), str(AuthId), str(Domain), str(GenDate), str(Id), str(LastBackTime), str(GenPass)])

            #CURRENTLY RESULTS IN ERROR: 
            #ERROR   : volatility.debug    : 'tuple' object is not callable