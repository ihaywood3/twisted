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


import time

from twisted.protocols._smb import base, types
from twisted.protocols._smb.ismb import (ISMBServer, IFilesystem, IPipe, IIPC,
                                         IPrinter, NoSuchShare)

from twisted.internet import protocol
from twisted.logger import Logger
from twisted.internet.defer import maybeDeferred, succeed

log = Logger()


class PipeShim:

    def __init__(self, pipe):
        self.__pipe = pipe
        self.ctime = time.time()
        self.wtime = self.ctime
        self.atime = self.ctime
        
    def read(self, offset, length):
        data = self.__pipe.dataAvailable(length)
        if len(data) == 0:
            raise base.SMBError('pipe empty', types.NTStatus.PIPE_EMPTY)
        self.atime = time.time()
        return succeed(data)
        
    def write(self, offset, data):
        self.__pipe.dataReceived(data)
        self.wtime = time.time()
        self.atime = self.wtime
        return succeed(len(data))

    def flush(self):
        self.wtime = time.time()
        self.atime = self.wtime
        return succeed(None)
        
    def close(self):
        return succeed(None)
        
    def getFileStandardInformation(self):
        # for pipes "canned" data will suffice
        return types.FileStandardInformation(
           alloc_size=types.CLUSTER_SIZE, 
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























