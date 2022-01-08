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

import os.path
import stat

from twisted.protocols._smb import base, smbtypes
from twisted.logger import Logger
from twisted.internet.defer import succeed

log = Logger()


class IPCShim:
    def __init__(self, ipc):
        self.__ipc = ipc

    def open(self, path, **_kwargs):
        driver = PipeShim(self.__ipc.open(path))
        return (driver, smbtypes.CreateAction.Opened)


class PipeShim:
    def __init__(self, pipe):
        self.__pipe = pipe
        self.ctime = base.wiggleTime()
        self.wtime = self.ctime
        self.atime = self.ctime

    def read(self, offset, length):
        data = self.__pipe.dataAvailable(length)
        if len(data) == 0:
            raise base.SMBError("pipe empty", smbtypes.NTStatus.PIPE_EMPTY)
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
        return smbtypes.FileStandardInformation(
            alloc_size=smbtypes.CLUSTER_SIZE, end_of_file=0, delete_pending=1, links=1
        )

    def getFileNetworkOpenInformation(self):
        return smbtypes.FileNetworkOpenInformation(
            alloc_size=smbtypes.CLUSTER_SIZE,
            end_of_file=0,
            ctime=base.unixToNTTime(self.ctime),
            mtime=base.unixToNTTime(self.ctime),
            wtime=base.unixToNTTime(self.wtime),
            atime=base.unixToNTTime(self.atime),
            attributes=smbtypes.FILE_ATTRIBUTE_NORMAL,
        )


class FilesystemShim:
    def __init__(self, vfs):
        self.__vfs = vfs

    def open(self, path, **kwargs):
        flags = 0
        if kwargs["disposition"] == smbtypes.CreateDisposition.Supersede:
            flags |= os.O_CREAT | os.O_TRUNC
            def_action = smbtypes.CreateAction.Superseded
        elif kwargs["disposition"] == smbtypes.CreateDisposition.Open:
            def_action = smbtypes.CreateAction.Opened
        elif kwargs["disposition"] == smbtypes.CreateDisposition.Create:
            flags |= os.O_CREAT | os.O_EXCL
            def_action = smbtypes.CreateAction.Created
        elif kwargs["disposition"] == smbtypes.CreateDisposition.OpenIf:
            flags |= os.O_CREAT
            def_action = smbtypes.CreateAction.Opened
        elif kwargs["disposition"] == smbtypes.CreateDisposition.Overwrite:
            flags |= os.O_TRUNC
            def_action = smbtypes.CreateAction.Overwritten
        elif kwargs["disposition"] == smbtypes.CreateDisposition.OverwriteIf:
            flags |= os.O_CREAT | os.O_TRUNC
            def_action = smbtypes.CreateAction.Overwritten

        def cb_addshim(fd, action, attrs):
            driver = FileShim(fd, path)
            if attrs:
                driver.setInitialAttrs(attrs)
            return (driver, action)

        def eb_addshim(failure):
            failure.trap(FileNotFoundError)
            raise base.SMBError("file not found", smbtypes.NTStatus.NO_SUCH_FILE)

        def cb_file(attrs, action):
            d = self.__vfs.openFile(path, flags)
            d.addCallback(cb_addshim, action, attrs)
            d.addErrback(eb_addshim)
            return d

        def eb_file(failure):
            log.failure("eb_file", failure)
            failure.trap(FileNotFoundError)
            d = self.__vfs.openFile(path, flags)
            d.addCallback(cb_addshim, smbtypes.CreateAction.Created, None)
            d.addErrback(eb_addshim)
            return d

        if def_action == smbtypes.CreateAction.Created:
            return cb_file(None, def_action)
        else:
            d2 = self.__vfs.getAttrs(path)
            d2.addCallback(cb_file, def_action)
            d2.addErrback(eb_file)
            return d2


class FileShim:
    def __init__(self, fd, path):
        self.__fd = fd
        self.init_attr = None
        self.path = path
        self.is_dir = False
        self.delete_pending = 0

    def setInitialAttrs(self, attrs):
        self.init_attr = attrs

    def read(self, offset, length):
        return self.__fd.readChunk(offset, length)

    def write(self, offset, data):
        return self.__fd.writeChunk(offset, data)

    def flush(self):
        return self.__fd.flush()

    def close(self):
        return self.__fd.close()

    def getFileStandardInformation(self):
        def cb_attr(a):
            return smbtypes.FileStandardInformation(
                alloc_size=a.get("ext_blksize", smbtypes.CLUSTER_SIZE),
                end_of_file=a["size"],
                delete_pending=self.delete_pending,
                links=a.get("ext_nlinks", 1),
            )

        d = self.__fd.getAttrs()
        d.addCallback(cb_attr)
        return d

    def _a2attrib(self, a):
        """
        create NT file attributes masks
        """
        attributes = 0
        if os.path.basename(self.path).startswith("."):
            attributes |= smbtypes.FILE_ATTRIBUTE_HIDDEN
        if a["permissions"] & stat.S_IWUSR == 0:
            attributes |= smbtypes.FILE_ATTRIBUTE_READONLY
        if stat.S_ISDIR(a["permissions"]):
            attributes |= smbtypes.FILE_ATTRIBUTE_DIRECTORY
            self.is_dir = True
        if attributes == 0:
            attributes = smbtypes.FILE_ATTRIBUTE_NORMAL
        return attributes

    def getFileNetworkOpenInformation(self):
        def cb_fnoi(a):
            return smbtypes.FileNetworkOpenInformation(
                alloc_size=a.get("ext_blksize", smbtypes.CLUSTER_SIZE),
                end_of_file=a["size"],
                ctime=base.unixToNTTime(a.get("ext_birthtime", a["mtime"])),
                mtime=base.unixToNTTime(a.get("ext_ctime", a["mtime"])),
                wtime=base.unixToNTTime(a["mtime"]),
                atime=base.unixToNTTime(a["atime"]),
                attributes=self._a2attrib(a),
            )

        if self.init_attr:
            r = cb_fnoi(self.init_attr)
            self.init_attr = None
            return succeed(r)
        else:
            d = self.__fd.getAttrs()
            d.addCallback(cb_fnoi)
            return d

    def getFileBasicInformation(self):
        def cb_fbi(a):
            return smbtypes.FileBasicInformation(
                ctime=base.unixToNTTime(a.get("ext_birthtime", a["mtime"])),
                mtime=base.unixToNTTime(a.get("ext_ctime", a["mtime"])),
                wtime=base.unixToNTTime(a["mtime"]),
                atime=base.unixToNTTime(a["atime"]),
                attributes=self._a2attrib(a),
            )

        d = self.__fd.getAttrs()
        d.addCallback(cb_fbi)
        return d

    def getFileAllInformation(self):
        def cb_fai(a):
            access_flags = 0
            if a["permissions"] & stat.S_IWUSR:
                access_flags |= (
                    smbtypes.FILE_WRITE_DATA
                    | smbtypes.DELETE
                    | smbtypes.FILE_APPEND_DATA
                )
                if stat.S_ISDIR(a["permissions"]):
                    access_flags |= smbtypes.FILE_DELETE_CHILD
            if a["permissions"] & stat.S_IRUSR:
                access_flags |= smbtypes.FILE_READ_DATA
            if a["permissions"] & stat.S_IEXEC:
                access_flags |= smbtypes.FILE_EXECUTE
            return smbtypes.FileAllInformation(
                # FileStandardInformation
                alloc_size=a.get("ext_blksize", smbtypes.CLUSTER_SIZE),
                end_of_file=a["size"],
                delete_pending=self.delete_pending,
                links=a.get("ext_nlinks", 1),
                # FileBasicInformation
                ctime=base.unixToNTTime(a.get("ext_birthtime", a["mtime"])),
                mtime=base.unixToNTTime(a.get("ext_ctime", a["mtime"])),
                wtime=base.unixToNTTime(a["mtime"]),
                atime=base.unixToNTTime(a["atime"]),
                attributes=self._a2attrib(a),
                # FileAccessInformation
                access_flags=access_flags,
                # FileNamesInformation
                file_name=os.path.basename(self.path),
            )

        d = self.__fd.getAttrs()
        d.addCallback(cb_fai)
        return d
