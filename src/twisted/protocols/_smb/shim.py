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

import fnmatch
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
        return (driver, smbtypes.CreateAction.Opened, {})


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

        if kwargs["options"] & smbtypes.FILE_OPEN_REPARSE_POINT:
            log.warn("client attempting to open '{path}' as reparse point", path=path)
            # raise base.SMBError(
            #    "not a reparse point", smbtypes.NTStatus.NOT_A_REPARSE_POINT
            # )

        def add_ctx(driver, action, attrs):
            ctx = {}

            def cb_diskid(statfs):
                ctx[smbtypes.CREATE_QUERY_ON_DISK_ID] = smbtypes.CreateCtxQueryOnDiskId(
                    disk_file_id=attrs["inode"], volume_id=statfs["disk_id64"]
                )

            d = None
            if "ctx" in kwargs:
                if smbtypes.CREATE_QUERY_ON_DISK_ID in kwargs["ctx"]:
                    d = self.__vfs.statfs()
                    d.addCallback(cb_diskid)

                if smbtypes.CREATE_QUERY_MAXIMAL_ACCESS in kwargs["ctx"]:
                    if self.__vfs.read_only:
                        ma = (
                            smbtypes.FILE_READ_DATA
                            | smbtypes.FILE_READ_ATTRIBUTES
                            | smbtypes.FILE_EXECUTE
                        )
                    else:
                        ma = (
                            smbtypes.FILE_READ_DATA
                            | smbtypes.FILE_READ_ATTRIBUTES
                            | smbtypes.FILE_EXECUTE
                            | smbtypes.FILE_WRITE_DATA
                            | smbtypes.FILE_WRITE_ATTRIBUTES
                            | smbtypes.FILE_APPEND_DATA
                            | smbtypes.DELETE
                            | smbtypes.FILE_DELETE_CHILD
                            | smbtypes.WRITE_OWNER
                            | smbtypes.READ_CONTROL
                            | smbtypes.WRITE_DAC
                            | smbtypes.SYNCHRONIZE
                            | smbtypes.FILE_WRITE_EA
                            | smbtypes.FILE_READ_EA
                        )
                    ctx[
                        smbtypes.CREATE_QUERY_MAXIMAL_ACCESS
                    ] = smbtypes.CreateCtxQueryMaximalAccessResp(
                        maximal_access=ma, ntstatus=smbtypes.NTStatus.SUCCESS
                    )
                if smbtypes.CREATE_DURABLE_HANDLE in kwargs["ctx"]:
                    ctx[
                        smbtypes.CREATE_DURABLE_HANDLE
                    ] = smbtypes.CreateCtxDurableHandle()
                if smbtypes.CREATE_RESPONSE_LEASE in kwargs["ctx"]:
                    req_lease = kwargs["ctx"][smbtypes.CREATE_RESPONSE_LEASE]
                    ctx[
                        smbtypes.CREATE_RESPONSE_LEASE
                    ] = smbtypes.CreateCtxResponseLease(
                        key=req_lease.key, state=req_lease.state
                    )
            if d:
                d.addCallback(lambda _: (driver, action, ctx))
                return d
            else:
                return (driver, action, ctx)

        def cb_addshim(fd, action, attrs):
            driver = FileShim(fd, path)
            if attrs:
                driver.setInitialAttrs(attrs)
                return add_ctx(driver, action, attrs)
            else:
                d = self.__vfs.getAttrs(path)
                d.addCallback(cb_addshim2, driver, action)
                return d

        def cb_addshim2(attrs, driver, action):
            driver.setInitialAttrs(attrs)
            return add_ctx(driver, action, attrs)

        def eb_addshim(failure):
            failure.trap(FileNotFoundError)
            raise base.SMBError(
                "file not found", smbtypes.NTStatus.OBJECT_NAME_NOT_FOUND
            )

        def cb_file(attrs, action):
            if attrs and stat.S_ISDIR(attrs["permissions"]) > 0:
                return add_ctx(
                    DirShim(self.__vfs, attrs, path),
                    smbtypes.CreateAction.Opened,
                    attrs,
                )
            else:
                d = self.__vfs.openFile(path, flags)
                d.addCallback(cb_addshim, action, attrs)
                d.addErrback(eb_addshim)
                return d

        def eb_file(failure):
            log.failure("eb_file", failure)
            failure.trap(FileNotFoundError)
            if flags & os.O_CREAT:
                d = self.__vfs.openFile(path, flags)
                d.addCallback(cb_addshim, smbtypes.CreateAction.Created, None)
                d.addErrback(eb_addshim)
                return d
            else:
                raise base.SMBError(
                    "file not found", smbtypes.NTStatus.OBJECT_NAME_NOT_FOUND
                )

        if def_action == smbtypes.CreateAction.Created:
            return cb_file(None, def_action)
        else:
            d2 = self.__vfs.getAttrs(path)
            d2.addCallback(cb_file, def_action)
            d2.addErrback(eb_file)
            return d2

    def getFileFsSizeInformation(self):
        def cb_ffsi(v):
            return smbtypes.FileFsSizeInformation(
                total_units=v["blocks"],
                avail_units=v["free"],
                sectors_per_unit=1,
                bytes_per_sector=v["size"],
            )

        d = self.__vfs.statfs()
        d.addCallback(cb_ffsi)
        return d


class CommonShim:
    """
    an abstract common ancestor for DirShim and FileShim
    """

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

    def _getAttrs(self):
        """get attributes of directory/file"""
        if self.init_attrs:
            a = self.init_attrs
            self.init_attrs = None
            return succeed(a)
        else:
            return self._getAttrs_actual()

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

        d = self._getAttrs()
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

        d = self._getAttrs()
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

        d = self._getAttrs()
        d.addCallback(cb_fai)
        return d

    def getFileStandardInformation(self):
        def cb_attr(a):
            return smbtypes.FileStandardInformation(
                alloc_size=a.get("ext_blksize", smbtypes.CLUSTER_SIZE),
                end_of_file=a["size"],
                delete_pending=self.delete_pending,
                links=a.get("ext_nlinks", 1),
            )

        d = self._getAttrs()
        d.addCallback(cb_attr)
        return d


class DirShim(CommonShim):
    def __init__(self, vfs, attrs, path):
        self.__vfs = vfs
        self.init_attrs = attrs
        self.path = path
        self.is_dir = True
        self.delete_pending = 0
        self.short_names = set()
        self.running = False
        self.cache = []

    def _getAttrs_actual(self):
        return self.__vfs.getAttrs(self.path)

    def getFileNetworkOpenInformation(self):
        def cb_fnoi(a):
            return smbtypes.FileNetworkOpenInformation(
                alloc_size=0,
                end_of_file=0,  # unlike POSIX, Windows directories have no length
                ctime=base.unixToNTTime(a.get("ext_birthtime", a["mtime"])),
                mtime=base.unixToNTTime(a.get("ext_ctime", a["mtime"])),
                wtime=base.unixToNTTime(a["mtime"]),
                atime=base.unixToNTTime(a["atime"]),
                attributes=self._a2attrib(a),
            )

        d = self._getAttrs()
        d.addCallback(cb_fnoi)
        return d

    def _make_short_name(self, long_name):
        s1 = long_name.upper().replace(" ", "")
        l = s1.split(".")
        if len(l) == 1:
            ext = "TXT"
            name = s1
        else:
            ext = l[-1]
            name = l[0]
        if ext == "JPEG":
            ext = "JPG"
        if ext == "DOCX":
            ext = "DOX"
        if len(ext) > 3:
            ext = ext[:3]
        if len(name) > 8:
            # first, try stripping out the vowels
            for i in "AEIOU":
                name = name.replace(i, "")
            # next, cut out the middle
            if len(name) > 8:
                name = name[0:5] + name[-3:]
            if name + "." + ext in self.short_names:
                # uh-oh, a duplicate
                base = name[:5] + name[-2:]
                for i in range(1, 10):
                    fname = "%s%d.%s" % (base, i, ext)
                    if fname not in self.short_names:
                        self.short_names.add(fname)
                        return fname
                base = name[:5] + name[-1:]
                for i in range(10, 100):
                    fname = "%s%d.%s" % (base, i, ext)
                    if fname not in self.short_names:
                        self.short_names.add(fname)
                        return fname
                # seriously...
                name = "%s%07d" % (name[:1], len(self.short_names))
        fname = name + "." + ext
        self.short_names.add(fname)
        return fname

    def _make_dir_entry(self, enum_class, longname, a, shortname):
        file_name_len = len(longname) * 2
        offset = file_name_len + base.calcsize(enum_class)
        if offset % 8 > 0:
            padding = 8 - (offset % 8)
            longname += "\0" * int(padding / 2)
            offset += padding
        e = enum_class(
            alloc_size=a.get("ext_blksize", smbtypes.CLUSTER_SIZE),
            end_of_file=a["size"],
            ctime=base.unixToNTTime(a.get("ext_birthtime", a["mtime"])),
            mtime=base.unixToNTTime(a.get("ext_ctime", a["mtime"])),
            wtime=base.unixToNTTime(a["mtime"]),
            atime=base.unixToNTTime(a["atime"]),
            attributes=self._a2attrib(a),
            next_entry_offset=offset,
            file_name=longname,
            file_name_len=file_name_len,
        )
        if shortname:
            bshortname = shortname.encode("utf-16le")
            shortname_len = len(bshortname)
            bshortname += b"\0" * (24 - shortname_len)
            e.short_name = bshortname
            e.short_name_len = shortname_len
        return e

    def _ret_cache(self, enum_class, obl, first_only):
        if not self.cache:
            return []
        if first_only:
            l, a, s = self.cache[0]
            self.cache = self.cache[1:]
            o = self._make_dir_entry(enum_class, l, a, s)
            o.next_entry_offset = 0
            return [o]
        ret_buffer = []
        for i in range(len(self.cache)):
            l, a, s = self.cache[i]
            o = self._make_dir_entry(enum_class, l, a, s)
            obl -= o.next_entry_offset
            if obl > 0:
                ret_buffer.append(o)
            else:
                # we have run out of output buffer, o is discarded
                self.cache = self.cache[i:]
                ret_buffer[-1].next_entry_offset = 0
                return ret_buffer
        # whole cache used
        self.cache = []
        ret_buffer[-1].next_entry_offset = 0
        return ret_buffer

    def listDir(self, enum_class, glob, restart, first_only, obl):
        def int_listdir(l):
            if (
                enum_class is smbtypes.FileBothDirectoryInformation
                or enum_class is smbtypes.FileIdBothDirectoryInformation
            ):
                self.cache = [(n, a, self._make_short_name(n)) for n, a in sorted(l)]
            else:
                self.cache = [(n, a, None, True) for n, a in l]
            return self._ret_cache(enum_class, obl, first_only)

        if restart or not self.running:
            self.running = True
            if glob == "*.*":
                glob = "*"
            d = self.__vfs.openDirectory(self.path)
            d.addCallback(int_listdir)
            return d
        else:
            return self._ret_cache(enum_class, obl, first_only)

    def close(self):
        return succeed(None)


class FileShim(CommonShim):
    def __init__(self, fd, path):
        self.__fd = fd
        self.init_attrs = None
        self.path = path
        self.is_dir = False
        self.delete_pending = 0

    def setInitialAttrs(self, attrs):
        self.init_attrs = attrs

    def _getAttrs_actual(self):
        return self.__fd.getAttrs()

    def read(self, offset, length):
        return self.__fd.readChunk(offset, length)

    def write(self, offset, data):
        return self.__fd.writeChunk(offset, data)

    def flush(self):
        return self.__fd.flush()

    def close(self):
        return self.__fd.close()
