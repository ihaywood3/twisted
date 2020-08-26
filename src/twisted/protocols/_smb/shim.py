# -*- test-case-name: twisted.protocols._smb.tests -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
"""
the shim objects sit between core.py functions and the user-defined
objects (IPipe/IPrinter/IFile etc. This is to prevent user-defined objects
from having to implement a lot of standard "boilerplate" functionality
.
The shim objects play the role of "filesystem driver" in Windows.
"""

from twisted.protocols._smb import base, types
from twisted.logger import Logger
from twisted.internet.defer import succeed

log = Logger()



class PipeShim:
    def __init__(self, pipe):
        self.__pipe = pipe
        self.ctime = base.wiggleTime()
        self.wtime = self.ctime
        self.atime = self.ctime

    def read(self, offset, length):
        data = self.__pipe.dataAvailable(length)
        if len(data) == 0:
            raise base.SMBError('pipe empty', types.NTStatus.PIPE_EMPTY)
        self.atime = base.wiggleTime()
        return succeed(data)

    def write(self, offset, data):
        self.__pipe.dataReceived(data)
        self.wtime = base.wiggleTime()
        self.atime = self.wtime
        return succeed(len(data))

    def pipeTranscieve(self, data):
        self.__pipe.dataReceived(data)
        self.wtime = base.wiggleTime()
        self.atime = self.wtime
        data = self.__pipe.dataAvailable()
        return succeed(data)

    def flush(self):
        self.wtime = base.wiggleTime()
        self.atime = self.wtime
        return succeed(None)

    def close(self):
        return succeed(None)

    def getFileStandardInformation(self):
        # for pipes entirely "canned" data will suffice
        return types.FileStandardInformation(alloc_size=types.CLUSTER_SIZE,
                                             end_of_file=0,
                                             delete_pending=1,
                                             links=1)

    def getFileNetworkOpenInformation(self):
        return types.FileNetworkOpenInformation(
            alloc_size=types.CLUSTER_SIZE,
            end_of_file=0,
            ctime=base.unixToNTTime(self.ctime),
            mtime=base.unixToNTTime(self.ctime),
            wtime=base.unixToNTTime(self.wtime),
            atime=base.unixToNTTime(self.atime),
            attributes=types.FILE_ATTRIBUTE_NORMAL)
