# -*- test-case-name: twisted.protocols._smb.tests -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
"""Implement Microsoft's Server Message Block protocol

U{https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
5606ad47-5ee0-437a-817e-70c366052962}
"""

import struct
import binascii
from uuid import uuid4
import socket
from collections import namedtuple
import enum
import attr

from twisted.protocols._smb import base, security_blob, dcerpc
from twisted.protocols._smb.base import (byte, short, medium, long, uuid,
                                         octets)
from twisted.protocols._smb.ismb import (ISMBServer, IFilesystem, IPipe, IIPC,
                                         IPrinter, NoSuchShare)

from twisted.internet import protocol
from twisted.logger import Logger
from twisted.cred.checkers import ANONYMOUS
from twisted.internet.defer import maybeDeferred, succeed

log = Logger()

SMBMind = namedtuple('SMBMind', 'session_id domain addr')
SystemData = namedtuple('SystemData', 'server_uuid boot_time domain fqdn fake')
# a collection of, possibly fake, system data that gets reported at various
# points in the protocol


@attr.s
class NegReq:
    """negotiate request"""
    size = short(36, locked=True)
    dialect_count = short()
    security_mode = short()
    reserved = short()
    capabilities = medium()
    client_uuid = uuid()



MAX_READ_SIZE = 0x10000
MAX_TRANSACT_SIZE = 0x10000
MAX_WRITE_SIZE = 0x10000



@attr.s
class NegResp:
    """negotiate response"""
    size = short(65, locked=True)
    signing = short()
    dialect = short()
    reserved = short()
    server_uuid = uuid()
    capabilities = medium()
    max_transact = medium(MAX_TRANSACT_SIZE)
    max_read = medium(MAX_READ_SIZE)
    max_write = medium(MAX_WRITE_SIZE)
    time = long()
    boot_time = long()
    offset = short(128, locked=True)
    buflen = short()
    reserved2 = medium()



@attr.s
class SessionReq:
    """session setup request"""
    size = short(25, locked=True)
    flags = byte()
    security_mode = byte()
    capabilities = medium()
    channel = medium()
    offset = short()
    buflen = short()
    prev_session_id = long()



@attr.s
class SessionResp:
    """seesion setup response"""
    size = short(9, locked=True)
    flags = short()
    offset = short(72, locked=True)
    buflen = short()



@attr.s
class BasicPacket:
    """structure used in several request/response types"""
    size = short(4, locked=True)
    reserved = short()



@attr.s
class TreeReq:
    """tree connect request"""
    size = short(9, locked=True)
    reserved = short()
    offset = short()
    buflen = short()



@attr.s
class TreeResp:
    """tree connect response"""
    size = short(16, locked=True)
    share_type = byte()
    reserved = byte()
    flags = medium()
    capabilities = medium()
    max_perms = medium()

class OplockLevels(enum.Enum):
    NoLock = 0
    Level2 = 0x01
    Exclusive = 0x08
    Batch = 0x09
    Lease = 0xFF
    
class ImpersonationationLevel(enum.Enum):
    Anonymous = 0
    Identification = 1
    Impersonation = 2
    Delegate = 3


FILE_ATTRIBUTE_ARCHIVE=0x00000020
FILE_ATTRIBUTE_COMPRESSED=0x00000800
FILE_ATTRIBUTE_DIRECTORY=0x00000010
FILE_ATTRIBUTE_ENCRYPTED=0x00004000
FILE_ATTRIBUTE_HIDDEN=0x00000002
FILE_ATTRIBUTE_NORMAL=0x00000080
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED=0x00002000
FILE_ATTRIBUTE_OFFLINE=0x00001000
FILE_ATTRIBUTE_READONLY=0x00000001
FILE_ATTRIBUTE_REPARSE_POINT=0x00000400
FILE_ATTRIBUTE_SPARSE_FILE=0x00000200
FILE_ATTRIBUTE_SYSTEM=0x00000004
FILE_ATTRIBUTE_TEMPORARY=0x00000100
FILE_ATTRIBUTE_INTEGRITY_STREAM=0x00008000
FILE_ATTRIBUTE_NO_SCRUB_DATA=0x00020000

# for CreateReq.share_access
FILE_SHARE_READ=0x01
FILE_SHARE_WRITE=0x02
FILE_SHARE_DELETE=0x03

class CreateDisposition(enum.Enum):
    Supersede = 0
    Open = 1
    Create = 2
    OpenIf = 3
    Overwrite = 4
    OverwriteIf = 5

# for CreateReq.options
FILE_DIRECTORY_FILE=0x00000001
FILE_WRITE_THROUGH=0x00000002
FILE_SEQUENTIAL_ONLY=0x00000004
FILE_NO_INTERMEDIATE_BUFFERING=0x00000008
FILE_SYNCHRONOUS_IO_ALERT=0x00000010 # ignored
FILE_SYNCHRONOUS_IO_NONALERT=0x00000020 # ignored
FILE_NON_DIRECTORY_FILE=0x00000040
FILE_COMPLETE_IF_OPLOCKED=0x00000100  # ignored
FILE_NO_EA_KNOWLEDGE=0x00000200
FILE_RANDOM_ACCESS=0x00000800
FILE_DELETE_ON_CLOSE=0x00001000
FILE_OPEN_BY_FILE_ID=0x00002000 # ignored
FILE_OPEN_FOR_BACKUP_INTENT=0x00004000
FILE_NO_COMPRESSION=0x00008000
FILE_OPEN_REMOTE_INSTANCE=0x00000400 # ignored
FILE_OPEN_REQUIRING_OPLOCK=0x00010000 # ignored
FILE_DISALLOW_EXCLUSIVE=0x00020000 # ignored
FILE_RESERVE_OPFILTER=0x00100000 # server must fail if set
FILE_OPEN_REPARSE_POINT=0x00200000
FILE_OPEN_NO_RECALL=0x00400000
FILE_OPEN_FOR_FREE_SPACE_QUERY=0x00800000



@attr.s
class CreateReq:
    """create (actually "open") a file"""
    size = short(57, locked=True)
    security_flags = byte() # unused
    oplock_level = byte()
    impersonation_level = medium()
    flags = long() # unused
    reserved = long() # unused
    desired_access = medium()
    attributes = medium()
    share_access = medium()
    disposition = medium()
    options = medium()
    name_offset = short()
    name_length = short()
    ctx_offset = medium()
    ctx_length = medium()
    
 
class CreateAction(enum.Enum):
    Superseded = 0
    Opened = 1
    Created = 2
    Overwritten = 3

    
@attr.s
class CreateResp:
    size = short(89, locked=True)
    oplock_level = byte()
    flags = byte() # unused on 2.x 
    action = medium()
    ctime = long()
    atime = long()
    wtime = long()
    mtime = long()
    alloc_size = long()
    file_size = long()
    attributes = medium()
    reserved = medium()
    file_id = uuid()
    ctx_offset = medium()
    ctx_length = medium()

CLOSE_FLAG_POSTQUERY_ATTRIB=0x0001


@attr.s 
class CloseReq:
    size = short(24, locked=True)
    flags = short()
    reserved = medium()
    file_id = uuid()
    
@attr.s
class CloseResp:
    size = short(60, locked=True)
    flags = short()
    reserved = medium()
    ctime = long()
    atime = long()
    wtime = long()
    mtime = long()
    alloc_size = long()
    file_size = long()
    attributes = medium()
 
@attr.s
class FlushReq:
    size = short(24, locked=True)
    reserved = octets(6)
    file_id = uuid()
 
@attr.s
class ReadReq:
    size = short(49, locked=True)
    padding = byte()
    flags = byte()
    length = medium()
    offset = long()
    file_id = uuid()
    minimum_count = medium()
    channel = medium() # for RDMA
    remaining_bytes = medium()
    channel_offset = short()
    channel_length = short()
    
@attr.s
class ReadResp:
    size = medium(17, locked=True)
    offset = byte()
    reserved = byte()
    length = medium()
    remaining = medium() # only for RDMA channels
    reserved2 = medium()
 
WRITEFLAG_WRITE_THROUGH=0x00000001
WRITEFLAG_WRITE_UNBUFFERED=0x00000002


@attr.s
class WriteReq:
    size = short(49, locked=True)
    data_offset = short()
    length = medium()
    offset = long()
    file_id = uuid()
    channel = medium() # for RDMA
    remaining_bytes = medium()
    channel_offset = short()
    channel_length = short()
    flags = medium()

@attt.s
class WriteResp:
    size = short(17, locked=True)
    reserved = short()
    count = medium()
    remaining_bytes = medium()  # unused
    channel_offset = short() # unused
    channel_length = short() # unused
 

class Ioctl(enum.Enum):
    """values for Ioctl.ctl_code"""
    FSCTL_DFS_GET_REFERRALS=0x00060194
    FSCTL_PIPE_PEEK=0x0011400C
    FSCTL_PIPE_WAIT=0x00110018
    FSCTL_PIPE_TRANSCEIVE=0x0011C017
    FSCTL_SRV_COPYCHUNK=0x001440F2
    FSCTL_SRV_ENUMERATE_SNAPSHOTS=0x00144064
    FSCTL_SRV_REQUEST_RESUME_KEY=0x00140078
    FSCTL_SRV_READ_HASH=0x001441bb
    FSCTL_SRV_COPYCHUNK_WRITE=0x001480F2
    FSCTL_LMR_REQUEST_RESILIENCY=0x001401D4
    FSCTL_QUERY_NETWORK_INTERFACE_INFO=0x001401FC
    FSCTL_SET_REPARSE_POINT=0x000900A4
    FSCTL_DFS_GET_REFERRALS_EX=0x000601B0
    FSCTL_FILE_LEVEL_TRIM=0x00098208
    FSCTL_VALIDATE_NEGOTIATE_INFO=0x00140204

IOCTL_FLAG_IS_FSCTL=0x01

@attr.s
class IoctlReq:
    size = short(57, locked=True)
    reserved = short()
    ctl_code = medium()
    file_id = uuid()
    input_offset = medium()
    input_length = medium()
    max_input_response = medium()
    output_offset = medium()
    output_length = medium()
    max_output_response = medium()
    flags = medium()
    reserved2 = medium()
    
@attr.s
class IoctlResp:
    size = short(49, locked=True)
    reserved = short()
    ctl_code = medium()
    file_id = uuid()
    input_offset = medium()
    input_length = medium()
    output_offset = medium()
    output_length = medium()
    flags = medium()
    reserved2 = medium()


class InfoType(enum.Enum):
    """
    QueryInfoReq.info_type
    """
    FILE=0x01
    FILESYSTEM=0x02
    SECURITY=0x03
    QUOTA=0x04

class InfoClassFiles(enum.Enum):
    """
    QueryInfoReq.info_class when info_type == INFO_FILE
    """
    FileAccessInformation=8 # query
    FileAlignmentInformation=17 # query
    FileAllInformation=18 # query
    FileAllocationInformation=19 # set
    FileAlternateNameInformation=21 # query
    FileAttributeTagInformation=35  # query
    FileBasicInformation=4 # query set
    FileBothDirectoryInformation=3 # dir
    FileCompressionInformation=28 # query
    FileDirectoryInformation=1 # dir
    FileDispositionInformation=13 # set
    FileEaInformation=7 # query
    FileEndOfFileInformation=20 # set
    FileFullDirectoryInformation=2 # dir
    FileFullEaInformation=15 # query set
    FileIdBothDirectoryInformation=37 # dir
    FileIdFullDirectoryInformation=38
    FileIdInformation=59 # query
    FileInternalInformation=6 # query
    FileLinkInformation=11 # set
    FileModeInformation=16 # query set
    FileNamesInformation=12 # dir
    FileNetworkOpenInformation=34 # query
    FileNormalizedNameInformation=48 # query
    FilePipeInformation=23 # query  set
    FilePipeLocalInformation=24 # query
    FilePipeRemoteInformation=25 # query
    FilePositionInformation=14 # query set
    FileRenameInformation=10 # set
    FileShortNameInformation=40 # set
    FileStandardInformation=5 # query
    FileStreamInformation=22 # query
    FileValidDataLengthInformation=39 # set


class InfoClassFileSystems(enum.Enum):
    """
    QueryInfoReq.info_class when info_type == INFO_FILESYSTEM
    """
    FileFsVolumeInformation=1
    FileFsSizeInformation=3
    FileFsDeviceInformation=4
    FileFsAttributeInformation=5
    FileFsControlInformation=6 # set
    FileFsFullSizeInformation=7
    FileFsObjectIdInformation=8 # set
    FileFsSectorSizeInformation=11




@attr.s
class QueryInfoReq:
    size = short(41, locked=True)
    info_type = byte()
    info_class = byte()
    output_buffer_length = medium()
    offset = short()
    reserved = short()
    length = medium()
    addn_info = medium() # only used for EA queries
    flags = medium() # only used for EA queries
    file_id = uuid()




@attr.s
class QueryInfoResp:
    size = short(9, locked=True)
    offset = short(72)
    length = medium()
    
    
    
    
@attr.s
class SetInfoReq:
    size = short(33, locked=True)
    info_type = byte()
    info_class = byte()    
    length = medium()
    offset = short()
    reserved = short()
    addn_info = medium() # EA only
    file_id = uuid()
    
    
    
@attr.s
class SetInfoResp:
    size = short(2, locked=True)
    


# QueryDirReq.flags
QUERY_DIR_RESTART_SCANS=0x01
QUERY_DIR_RETURN_SINGLE_ENTRY=0x02
QUERY_DIR_INDEX_SPECIFIED=0x04
QUERY_DIR_REOPEN=0x10



@attr.s
class QueryDirReq:
    size = short(33, locked=True)
    info_class = byte()
    flags = byte()
    index = medium()
    file_id = uuid()
    offset = short()
    length = short()
    output_buffer_length = medium()
    
    
# no "QueryDirResp" as identical to QueryInfoResp
QueryDirResp = QueryInfoResp     
    
@attr.s
class LockReq:
r    size = short(48, locked=True)
    num_locks = short()
    lock_sequence = medium()
    file_id = uuid()
 


# LockElement.flags
LOCKFLAG_SHARED_LOCK=0x00000001
LOCKFLAG_EXCLUSIVE_LOCK=0x00000002
LOCKFLAG_UNLOCK=0x00000004
LOCKFLAG_FAIL_IMMEDIATELY=0x00000010 



@attr.s
class LockElement:
    offset = long()
    length = long()
    flags = medium()
    reserved = medium()


# ChangeNotifyReq.flags   
CHANGE_NOTIFY_WATCH_TREE=0x0001

# ChangeNotifyReq.completion_filter
FILE_NOTIFY_CHANGE_FILE_NAME=0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME=0x00000002
FILE_NOTIFY_CHANGE_ATTRIBUTES=0x00000004
FILE_NOTIFY_CHANGE_SIZE=0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE=0x00000010
FILE_NOTIFY_CHANGE_LAST_ACCESS=0x00000020
FILE_NOTIFY_CHANGE_CREATION=0x00000040
FILE_NOTIFY_CHANGE_EA=0x00000080
FILE_NOTIFY_CHANGE_SECURITY=0x00000100
FILE_NOTIFY_CHANGE_STREAM_NAME=0x00000200
FILE_NOTIFY_CHANGE_STREAM_SIZE=0x00000400
FILE_NOTIFY_CHANGE_STREAM_WRITE=0x00000800
  

  
@attr.s
class ChangeNotifyReq:
    size = short(32, locked=True)
    flags = short()
    output_buffer_length = medium()
    file_id = uuid()
    completion_filter = medium()
    reserved = medium()    
 
 
# no "ChangeNotifyResp" as identical to QueryInfoResp
ChangeNotifyResp = QueryInfoResp     
    
@attr.s
class OplockBreakAck:
    size = short(24, locked=True)
    oplock_level = byte()
    reserved = octets(5)
    file_id = uuid()
 
# other uses identical
OplockBreakNotify = OplockBreakAck
OplockBreakResp = OplockBreakAck

 
COMMANDS = [('negotiate', NegReq, NegResp),
            ('session_setup', SessionReq, SessionResp),
            ('logoff', BasicPacket, BasicPacket),
            ('tree_connect', TreeReq, TreeResp),
            ('tree_disconnect', BasicPacket, BasicPacket),
            ('create', CreateReq, CreateResp),
            ('close', CloseReq, CloseResp),
            ('flush', FlushReq, BasicPacket),
            ('read', ReadReq, ReadResp),
            ('write', WriteReq, WriteResp),
            ('lock', LockReq, BasicPacket),
            ('ioctl', IoctlReq, IoctlResp),
            ('cancel', BasicPacket, None),
            ('echo', BasicPacket, BasicPacket),
            ('query_directory', QueryDirReq, QueryInfoResp),
            ('change_notify', ChangeNotifyReq, QueryInfoResp),
            ('query_info', QueryInfoReq, QueryInfoResp),
            ('set_info', SetInfoReq, SetInfoResp),
            ('oplock_break', OplockBreakAck, OplockBreakAck)]
            
            
# the complete list of NT statuses is very large, so just
# add those actually used
class NTStatus(enum.Enum):
    SUCCESS = 0x00
    MORE_PROCESSING = 0xC0000016
    NO_SUCH_FILE = 0xC000000F
    UNSUCCESSFUL = 0xC0000001
    NOT_IMPLEMENTED = 0xC0000002
    NOT_SUPPORTED = 0xC00000BB
    INVALID_HANDLE = 0xC0000008
    ACCESS_DENIED = 0xC0000022
    END_OF_FILE = 0xC0000011
    PIPE_EMPTY = 0xC00000D9
    DATA_ERROR = 0xC000003E
    QUOTA_EXCEEDED = 0xC0000044
    FILE_LOCK_CONFLICT = 0xC0000054  # generated on read/writes
    LOCK_NOT_GRANTED = 0xC0000055  # generated when requesting lock
    LOGON_FAILURE = 0xC000006D
    DISK_FULL = 0xC000007F
    ACCOUNT_RESTRICTION = 0xC000006E
    PASSWORD_EXPIRED = 0xC0000071
    ACCOUNT_DISABLED = 0xC0000072
    FILE_INVALID = 0xC0000098
    DEVICE_DATA_ERROR = 0xC000009C
    BAD_NETWORK_NAME = 0xC00000CC  # = "share not found"
    INVALID_INFO_CLASS = 0xC0000003
    INVALID_PARAMETER = 0xC000000E
    NOT_FOUND = 0xC0000225
    INVALID_DEVICE_REQUEST = 0xC0000010
    
    
FLAG_SERVER = 0x01
FLAG_ASYNC = 0x02
FLAG_RELATED = 0x04
FLAG_SIGNED = 0x08
FLAG_PRIORITY_MASK = 0x70
FLAG_DFS_OPERATION = 0x10000000
FLAG_REPLAY_OPERATION = 0x20000000

NEGOTIATE_SIGNING_ENABLED = 0x0001
NEGOTIATE_SIGNING_REQUIRED = 0x0002

SESSION_FLAG_IS_GUEST = 0x0001
SESSION_FLAG_IS_NULL = 0x0002
SESSION_FLAG_ENCRYPT_DATA = 0x0004

NEGOTIATE_SIGNING_ENABLED = 0x0001
NEGOTIATE_SIGNING_REQUIRED = 0x0002

GLOBAL_CAP_DFS = 0x00000001
GLOBAL_CAP_LEASING = 0x00000002
GLOBAL_CAP_LARGE_MTU = 0x00000004
GLOBAL_CAP_MULTI_CHANNEL = 0x00000008
GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010
GLOBAL_CAP_DIRECTORY_LEASING = 0x00000020
GLOBAL_CAP_ENCRYPTION = 0x00000040

MAX_DIALECT = 0x02FF

CLUSTER_SIZE = 4096

SHARE_DISK = 0x01
SHARE_PIPE = 0x02
SHARE_PRINTER = 0x03

SHAREFLAG_MANUAL_CACHING = 0x00000000
SHAREFLAG_AUTO_CACHING = 0x00000010
SHAREFLAG_VDO_CACHING = 0x00000020
SHAREFLAG_NO_CACHING = 0x00000030
SHAREFLAG_DFS = 0x00000001
SHAREFLAG_DFS_ROOT = 0x00000002
SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS = 0x00000100
SHAREFLAG_FORCE_SHARED_DELETE = 0x00000200
SHAREFLAG_ALLOW_NAMESPACE_CACHING = 0x00000400
SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM = 0x00000800
SHAREFLAG_FORCE_LEVELII_OPLOCK = 0x00001000
SHAREFLAG_ENABLE_HASH_V1 = 0x00002000
SHAREFLAG_ENABLE_HASH_V2 = 0x00004000
SHAREFLAG_ENCRYPT_DATA = 0x00008000
SHAREFLAG_IDENTITY_REMOTING = 0x00040000

SHARE_CAP_DFS = 0x00000008
SHARE_CAP_CONTINUOUS_AVAILABILITY = 0x00000010
SHARE_CAP_SCALEOUT = 0x00000020
SHARE_CAP_CLUSTER = 0x00000040
SHARE_CAP_ASYMMETRIC = 0x00000080
SHARE_CAP_REDIRECT_TO_OWNER = 0x00000100

FILE_READ_DATA = 0x00000001
FILE_LIST_DIRECTORY = 0x00000001
FILE_WRITE_DATA = 0x00000002
FILE_ADD_FILE = 0x00000002
FILE_APPEND_DATA = 0x00000004
FILE_ADD_SUBDIRECTORY = 0x00000004
FILE_READ_EA = 0x00000008  # "Extended Attributes"
FILE_WRITE_EA = 0x00000010
FILE_DELETE_CHILD = 0x00000040
FILE_EXECUTE = 0x00000020
FILE_TRAVERSE = 0x00000020
FILE_READ_ATTRIBUTES = 0x00000080
FILE_WRITE_ATTRIBUTES = 0x00000100
DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
SYNCHRONIZE = 0x00100000
ACCESS_SYSTEM_SECURITY = 0x01000000
MAXIMUM_ALLOWED = 0x02000000
GENERIC_ALL = 0x10000000
GENERIC_EXECUTE = 0x20000000
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000

SMB1_MAGIC = b'\xFFSMB'
SMB2_MAGIC = b'\xFESMB'

ERROR_RESPONSE_MAGIC = b'\x09\0\0\0\0\0\0\0'

@attr.s
class HeaderSync:
    magic = octets(default=SMB2_MAGIC)
    size = short()
    credit_charge = short()
    status = medium()
    command = short()
    credit_request = short()
    flags = medium()
    next_command = medium()
    message_id = long()
    reserved = medium()
    tree_id = medium()
    session_id = long()
    signature = octets(16)
    async_id = attr.ib(default=0)



@attr.s
class HeaderAsync:
    magic = octets(default=SMB2_MAGIC)
    size = short()
    credit_charge = short()
    status = medium()
    command = short()
    credit_request = short()
    flags = medium()
    next_command = medium()
    message_id = long()
    async_id = long()
    session_id = long()
    signature = octets(16)
    tree_id = attr.ib(default=0)



def packetReceived(packet):
    """
    receive a SMB packet with header. Unpacks the
    header then calls the appropriate smb_XXX
    method with data beyond the header.

    @param packet: the raw packet
    @type packet: L{base.SMBPacket}
    """
    offset = 0
    isRelated = True
    while isRelated:
        protocol_id = packet.data[offset:offset + len(SMB2_MAGIC)]
        if protocol_id == SMB1_MAGIC:
            # its a SMB1 packet which we dont support with the exception
            # of the first packet, we try to offer upgrade to SMB2
            if packet.ctx.get('avatar') is None:
                log.debug("responding to SMB1 packet")
                negotiateResponse(packet)
            else:
                packet.close()
                log.error("Got SMB1 packet while logged in")
            return
        elif protocol_id != SMB2_MAGIC:
            packet.close()
            log.error("Unknown packet type")
            log.debug("packet data {data!r}",
                      data=packet.data[offset:offset + 64])
            return
        packet.hdr, o2 = base.unpack(HeaderSync, packet.data, offset,
                                     base.OFFSET)
        isAsync = (packet.hdr.flags & FLAG_ASYNC) > 0
        isRelated = (packet.hdr.flags & FLAG_RELATED) > 0
        isSigned = (packet.hdr.flags & FLAG_SIGNED) > 0
        # FIXME other flags 3.1 or too obscure
        if isAsync:
            packet.hdr = base.unpack(HeaderAsync, packet.data, offset)
        if isRelated:
            this_packet = packet.data[offset:offset + packet.hdr.next_command]
        else:
            this_packet = packet.data[offset:]
        flags_desc = ""
        if isAsync:
            flags_desc += " ASYNC"
        if isRelated:
            flags_desc += " RELATED"
        if isSigned:
            flags_desc += " SIGNED"
        log.debug("""
HEADER
------
protocol ID     {pid!r}
size            {hs}
credit charge   {cc}
status          {status}
command         {cmd!r} {cmdn:02x}
credit request  {cr}
flags           0x{flags:04x}{flags_desc}
next command    0x{nc:x}
message ID      0x{mid:x}
session ID      0x{sid:x}
async ID        0x{aid:x}
tree ID         0x{tid:x}
signature       {sig}""",
                  pid=protocol_id,
                  hs=packet.hdr.size,
                  cc=packet.hdr.credit_charge,
                  status=packet.hdr.status,
                  cmd=COMMANDS[packet.hdr.command][0],
                  cmdn=packet.hdr.command,
                  cr=packet.hdr.credit_request,
                  flags=packet.hdr.flags,
                  flags_desc=flags_desc,
                  nc=packet.hdr.next_command,
                  mid=packet.hdr.message_id,
                  sid=packet.hdr.session_id,
                  aid=packet.hdr.async_id,
                  tid=packet.hdr.tree_id,
                  sig=binascii.hexlify(packet.hdr.signature))
        if packet.hdr.command < len(COMMANDS):
            name, req_type, resp_type = COMMANDS[packet.hdr.command]
            func = 'smb_' + name
            try:
                if func in globals() and req_type:
                    req = base.unpack(req_type, packet.data, o2)
                    new_packet = packet.clone(data=this_packet,
                                              hdr=packet.hdr,
                                              body=req)
                    globals()[func](new_packet, resp_type)
                else:
                    log.error("command '{cmd}' not implemented",
                              cmd=COMMANDS[packet.hdr.command][0])
                    errorResponse(packet, NTStatus.NOT_IMPLEMENTED)
            except NotImplementedError as e:
                log.failure("in {cmd}", cmd=COMMANDS[packet.hdr.command][0])
                errorResponse(packet, NTStatus.NOT_IMPLEMENTED)
            except base.SMBError as e:
                log.error("SMB error: {e}", e=str(e))
                errorResponse(packet, e.ntstatus)
            except BaseException:
                log.failure("in {cmd}", cmd=COMMANDS[packet.hdr.command][0])
                errorResponse(packet, NTStatus.UNSUCCESSFUL)
        else:
            log.error("unknown command 0x{cmd:x}", cmd=packet.hdr.command)
            errorResponse(packet, NTStatus.NOT_IMPLEMENTED)

        offset += packet.hdr.next_command



def sendHeader(packet, command=None, status=NTStatus.SUCCESS):
    """
    prepare and transmit a SMB header and payload
    so actually a full packet but focus of function on header construction

    @param command: command name or id, defaults to same as received packet
    @type command: L{str} or L{int}

    @param packet: the packet, C{data} contains after-header data
    @type packet: L{base.SMBPacket}

    @param status: packet status, an NTSTATUS code
    @type status: L{int} or L{NTStatus}
    """
    # FIXME credit and signatures not supported yet
    if packet.hdr is None:
        packet.hdr = HeaderSync()
    packet.hdr.flags |= FLAG_SERVER
    packet.hdr.flags &= ~FLAG_RELATED
    if isinstance(command, str):
        cmds = [c[0] for c in COMMANDS]
        command = cmds.index(command)
    if command is not None:
        packet.hdr.command = command
    if isinstance(status, NTStatus):
        status = status.value
    packet.hdr.status = status
    packet.hdr.credit_request = 1
    packet.data = base.pack(packet.hdr) + packet.data
    packet.send()



def smb_negotiate(packet, resp_type):
    # capabilities is ignored as a 3.1 feature
    # as are final field complex around "negotiate contexts"
    dialects = struct.unpack_from("<%dH" % packet.body.dialect_count,
                                  packet.data,
                                  offset=base.calcsize(HeaderSync) +
                                  packet.body.size)
    signing_enabled = (packet.body.security_mode
                       & NEGOTIATE_SIGNING_ENABLED) > 0
    # by spec this should never be false
    signing_required = (packet.body.security_mode
                        & NEGOTIATE_SIGNING_REQUIRED) > 0
    desc = ""
    if signing_enabled:
        desc += "ENABLED "
    if signing_required:
        desc += "REQUIRED"
    log.debug("""
NEGOTIATE
---------
size            {sz}
dialect count   {dc}
signing         0x{sm:02x} {desc}
client UUID     {uuid!r}
dialects        {dlt!r}""",
              sz=packet.body.size,
              dc=packet.body.dialect_count,
              sm=packet.body.security_mode,
              desc=desc,
              uuid=packet.body.client_uuid,
              dlt=["%04x" % x for x in dialects])
    negotiateResponse(packet, dialects)



def errorResponse(packet, ntstatus):
    """
    send SMB error response

    @type packet: L{base.SMBPacket}
    @type ntstatus: L{int} or L{NTStatus}
    """
    packet.data = ERROR_RESPONSE_MAGIC
    sendHeader(packet, status=ntstatus)
    # pre 3.1.1 no variation in structure



def negotiateResponse(packet, dialects=None):
    """
    send negotiate response

    @type packet: L{base.SMBPacket}

    @param dialects: dialects offered by client, if C{None}, 2.02 used
    @type dialects: L{list} of L{int}
    """
    log.debug("negotiateResponse")
    blob_manager = packet.ctx['blob_manager']
    blob = blob_manager.generateInitialBlob()
    if dialects is None:
        log.debug("no dialects data, using 0x0202")
        dialect = 0x0202
    else:
        dialect = sorted(dialects)[0]
        if dialect == 0x02FF:
            dialect = 0x0202
        if dialect > MAX_DIALECT:
            raise base.SMBError(
                "min client dialect %04x higher than our max %04x" %
                (dialect, MAX_DIALECT))
        log.debug("dialect {dlt:04x} chosen", dlt=dialect)
    resp = NegResp()
    resp.signing = NEGOTIATE_SIGNING_ENABLED
    resp.dialect = dialect
    resp.server_uuid = packet.ctx['sys_data'].server_uuid
    resp.capabilities = GLOBAL_CAP_DFS
    resp.time = base.unixToNTTime(base.wiggleTime())
    bt = packet.ctx['sys_data'].boot_time
    if bt == 0:
        resp.boot_time = 0
    else:
        resp.boot_time = base.unixToNTTime(bt)
    resp.buflen = len(blob)
    packet.data = base.pack(resp) + blob
    sendHeader(packet, 'negotiate')



def smb_session_setup(packet, resp_type):
    blob = packet.data[packet.body.offset:packet.body.offset +
                       packet.body.buflen]
    log.debug("""
SESSION SETUP
-------------
Size             {sz}
Security mode    0x{sm:08x}
Capabilities     0x{cap:08x}
Channel          0x{chl:08x}
Prev. session ID 0x{pid:016x}""",
              sz=packet.body.size,
              sm=packet.body.security_mode,
              cap=packet.body.capabilities,
              chl=packet.body.channel,
              pid=packet.body.prev_session_id)
    blob_manager = packet.ctx['blob_manager']
    if packet.ctx.get('first_session_setup', True):
        blob_manager.receiveInitialBlob(blob)
        blob = blob_manager.generateChallengeBlob()
        sessionSetupResponse(packet, blob, NTStatus.MORE_PROCESSING)
        packet.ctx['first_session_setup'] = False
    else:
        blob_manager.receiveResp(blob)
        if blob_manager.credential:
            log.debug("got credential: %r" % blob_manager.credential)
            d = packet.ctx['portal'].login(
                blob_manager.credential,
                SMBMind(packet.body.prev_session_id,
                        blob_manager.credential.domain, packet.ctx['addr']),
                ISMBServer)

            def cb_login(t):
                _, packet.ctx['avatar'], packet.ctx['logout_thunk'] = t
                blob = blob_manager.generateAuthResponseBlob(True)
                log.debug("successful login")
                sessionSetupResponse(packet, blob, NTStatus.SUCCESS)

            def eb_login(failure):
                log.debug(failure.getTraceback())
                blob = blob_manager.generateAuthResponseBlob(False)
                sessionSetupResponse(packet, blob, NTStatus.LOGON_FAILURE)

            d.addCallback(cb_login)
            d.addErrback(eb_login)
        else:
            blob = blob_manager.generateChallengeBlob()
            sessionSetupResponse(packet, blob, NTStatus.MORE_PROCESSING)



def sessionSetupResponse(packet, blob, ntstatus):
    """
    send session setup response

    @type packet: L{base.SMBPacket}

    @param blob: the security blob to include in the response
    @type blob: L{bytes}

    @param ntstatus: response status
    @type ntstatus: L{NTStatus}
    """
    log.debug("sessionSetupResponse")
    resp = SessionResp()
    if packet.ctx['blob_manager'].credential == ANONYMOUS:
        resp.flags |= SESSION_FLAG_IS_NULL
    resp.buflen = len(blob)
    packet.data = base.pack(resp) + blob
    sendHeader(packet, 'session_setup', ntstatus)

def eb_common(failure, packet):
    """
    utility errback used by a number of different handlers
    
    @param failure: the active Failure
    @param packet: the current packet
    @type packet: L{base.SMBPacket}
    """
    if failure.check(NoSuchShare):
        errorResponse(packet, NTStatus.BAD_NETWORK_NAME)
    elif failure.check(base.SMBError):
        log.failure("SMB error {e}", failure, e=str(failure.value))
        errorResponse(packet, failure.value.ntstatus)
    else:
        log.failure("eb_common", failure)
        errorResponse(packet, NTStatus.UNSUCCESSFUL)


def smb_logoff(packet, resp_type):
    def cb_logoff(_):
        packet.data = base.pack(resp_type())
        sendHeader(packet)
    logout_thunk = packet.ctx.get('logout_thunk')
    if logout_thunk:
        d = maybeDeferred(logout_thunk)
        d.addCallback(cb_logoff)
        d.addErrback(eb_common, packet)
     else:
        cb_logoff(None)



def smb_tree_connect(packet, resp_type):
    avatar = packet.ctx.get('avatar')
    if avatar is None:
        errorResponse(packet, NTStatus.ACCESS_DENIED)
        return
    path = packet.data[packet.body.offset:packet.body.offset +
                       packet.body.buflen]
    path = path.decode("utf-16le")
    log.debug("""
TREE CONNECT
------------
Size   {sz}
Path   {path!r}
""",
              sz=packet.body.size,
              path=path)
    path = path.split("\\")[-1]
    if path == 'IPC$':
        d = succeed(dcerpc.BasicIPC(packet.ctx['sys_data']))
    else:
        d = maybeDeferred(avatar.getShare, path)

  
    def cb_tree(share):
        resp = None
        if IFilesystem.providedBy(share):
            resp = resp_type(
                share_type=SHARE_DISK,
                # FUTURE: select these values from share object
                flags=SHAREFLAG_MANUAL_CACHING,
                capabilities=0,
                max_perms=(FILE_READ_DATA | FILE_WRITE_DATA
                           | FILE_APPEND_DATA 
                           #| FILE_WRITE_EA | FILE_READ_EA
                           | FILE_DELETE_CHILD | FILE_EXECUTE
                           | FILE_READ_ATTRIBUTES
                           | FILE_WRITE_ATTRIBUTES
                           | DELETE | READ_CONTROL | WRITE_DAC
                           | WRITE_OWNER
                           | SYNCHRONIZE))
        if IIPC.providedBy(share):
            assert resp is None, "share can only be one type"
            resp = resp_type(
                share_type=SHARE_PIPE,
                flags=0,
                max_perms=(
                    FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA  |
                    #| FILE_READ_EA |
                    # FILE_WRITE_EA |
                    # FILE_DELETE_CHILD |
                    FILE_EXECUTE | FILE_READ_ATTRIBUTES |
                    # FILE_WRITE_ATTRIBUTES |
                    DELETE | READ_CONTROL |
                    # WRITE_DAC |
                    # WRITE_OWNER |
                    SYNCHRONIZE))
        if IPrinter.providedBy(share):
            assert resp is None, "share can only be one type"
            resp = resp_type(
                share_type=SHARE_PRINTER,
                flags=0,
                # FIXME need to check printer  max perms
                max_perms=(
                    FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA |
                    #| FILE_READ_EA |
                    # FILE_WRITE_EA |
                    # FILE_DELETE_CHILD |
                    FILE_EXECUTE | FILE_READ_ATTRIBUTES |
                    # FILE_WRITE_ATTRIBUTES |
                    DELETE | READ_CONTROL |
                    # WRITE_DAC |
                    # WRITE_OWNER |
                    SYNCHRONIZE))
        if resp is None:
            log.error("unknown share object {share!r}", share=share)
            errorResponse(packet, NTStatus.UNSUCCESSFUL)
            return
        packet.hdr.tree_id = base.int32key(packet.ctx['trees'], share)
        packet.data = base.pack(resp)
        sendHeader(packet)

    d.addCallback(cb_tree)
    d.addErrback(eb_common, packet)



def smb_tree_disconnect(packet, resp_type):
    del packet.ctx['trees'][packet.hdr.tree_id]
    packet.data = base.pack(resp_type())
    sendHeader(packet)

def smb_create(packet, resp_type):
    avatar = packet.ctx.get('avatar')
    if avatar is None:
        errorResponse(packet, NTStatus.ACCESS_DENIED)
        return
    tree = packet.ctx['trees'][packet.hdr.tree_id]
    path = packet.data[packet.body.name_offset:packet.body.name_offset +
                       packet.body.name_length]
    path = path.decode("utf-16le")
    log.debug("""
CREATE
------
Size   {sz}
Path   {path!r}
""",
              sz=packet.body.size,
              path=path)
    if IIPC.providedBy(tree):
        d1 = maybeDeferred(tree.open, path)
 
        def cb_create_ipc2(s, file_id):
            resp = resp_type(file_size=s.size,
                alloc_size=s.size,
                oplock_level=OplockLevels.NoLock,
                action=CreateAction.Opened,
                file_id=file_id,
                attributes=FILE_ATTRIBUTE_NORMAL,
                ctime=base.unixToNTTime(s.ctime),
                atime=base.unixToNTTime(s.atime),
                wtime=base.unixToNTTime(s.mtime),
                mtime=base.unixToNTTime(s.mtime),
                ctx_offset=0)
            packet.data = base.pack(resp)
            sendHeader(packet)

        def cb_create_ipc(pipe):
            file_id = uuid4()
            packet.ctx['files'][file_id] = pipe
            d2 = maybeDeferred(pipe.stat)
            d2.addCallback(cb_create_ipc2, file_id)
            d2.addErrback(eb_common, packet)
 
        d1.addCallback(cb_create_ipc)
        d1.addErrback(eb_common, packet)
    else:
        raise NotImplementedError()
  
def smb_close(packet, resp_type):
    fd = packet.ctx['files'][packet.body.file_id]
    log.debug("""
CLOSE
-----
size    {sz}
file id {file_id}
flags   {flags}
file    {fd!r}
""",
    sz=packet.body.size,
    file_id=packet.body.file_id,
    flags=packet.body.flags,
    fd=fd)
 
    def cb_close(_, resp):
       packet.data = base.pack(resp)
       sendHeader(packet) 
       del packet.ctx['files'][packet.body.file_id]
     
    def cb_close_stat(s):
        resp = resp_type(file_size=s.size,
            alloc_size=s.size,
            flags=CLOSE_FLAG_POSTQUERY_ATTRIB,
            attributes=statFlagsToAttrib(s),
            ctime=base.unixToNTTime(s.ctime),
            atime=base.unixToNTTime(s.atime),
            wtime=base.unixToNTTime(s.mtime),
            mtime=base.unixToNTTime(s.mtime))
        d1 = maybeDeferred(fd.fileClosed)          
        d1.addCallback(cb_close, resp)
        d1.addErrback(lambda f: log.failure("in smb_close", f))      
        
    if packet.body.flags & CLOSE_FLAG_POSTQUERY_ATTRIB > 0:
        d2 = maybeDeferred(fd.stat)
        d2.addCallback(cb_close_stat)
        d2.addErrback(eb_common, packet)
    else:
        resp = resp_type() # everything's zero
        d3 = maybeDeferred(fd.fileClosed)
        d3.addCallback(cb_close, resp)
        d3.addErrback(lambda f: log.failure("in smb_close", f))
   
def smb_flush(packet, resp_type):
    fd = packet.ctx['files'][packet.body.file_id]
    log.debug("""
FLUSH
-----
size    {sz}
file id {file_id}
file    {fd!r}
""",
    sz=packet.body.size,
    file_id=packet.body.file_id,
    fd=fd)
 
    def cb_flush(_):
       packet.data = base.pack(resp_type())
       sendHeader(packet) 
          
    d = maybeDeferred(fd.fileFlushed)
    d.addCallback(cb_flush)
    d.addErrback(lambda f: log.failure("in smb_close", f))
  
                
def smb_read(packet, resp_type):
    fd = packet.ctx['files'][packet.body.file_id]
    log.debug("""
READ
----
size    {sz}
file id {file_id}
offset  {offset}
length  {length}
min     {min}
file    {fd!r}
""",
    sz=packet.body.size,
    file_id=packet.body.file_id,
    offset=packet.body.offset,
    length=packet.body.length,
    min=packet.body.minimum_count,
    fd=fd) 
    
    if IPipe.providedBy(fd):
        data = fd.dataAvailable(packet.body.length)
        if len(data) == 0:
            raise base.SMBError('pipe empty', NTStatus.PIPE_EMPTY)
        if len(data) < packet.body.minimum_count:
            raise base.SMBError('below minimum_count', NTStatus.DATA_ERROR)
        read_response(packet, data)
    else:
        raise NotImplementedError()
   
def read_response(packet, data):
    min_offset = base.calcsize(HeaderAsync) + base.calcsize(ReadResp)
    offset = max(min_offset, packet.body.padding)
    if offset > min_offset:
        padding = b'\0'*(offset-min_offset)
    else:
        padding = b''
    resp = ReadResp(offset=offset,length=len(data))
    packet.data = base.pack(resp) + padding + data
    sendHeader(packet)
    
def smb_write(packet, resp_type):
    fd = packet.ctx['files'][packet.body.file_id]
    do = packet.body.data_offset
    data = packet.data[do:do+packet.body.length]
    log.debug("""
WRITE
-----
size    {sz}
file id {file_id}
offset  {offset}
length  {length}
flags   {flags:04x}
file    {fd!r}
data    {data!r}
""",
    sz=packet.body.size,
    file_id=packet.body.file_id,
    offset=packet.body.offset,
    length=packet.body.length,
    flags=packet.body.flags,
    fd=fd,
    data=data[:32]) 
    
    def cb_write(count1, count2=None):
        count = count1 or count2
        resp = resp_type(count=count)
        packet.data = base.pack(resp)
        sendHeader(packet)
    
    if IPipe.providedBy(fd):
        d = maybeDeferred(fd.dataReceived, data)
        d.addCallback(cb_write, len(data))
        d.addErrback(eb_common, packet)
    else:
        raise NotImplementedError()


@attr.s
class FileStandardInformation:
    alloc_size = long()
    end_of_file = long()
    links = medium()
    delete_pending = byte()
    directory = byte()
    reserved = medium()


 
def smb_query_info(packet, resp_type):
    if packet.body.file_id == base.UUID_MAX:
        fd = None
    else:
        fd = packet.ctx['files'][packet.body.file_id]
    try:
        info_type = InfoType(packet.body.info_type)
    except ValueError:
        raise base.SMBError("invalid info_type", NTStatus.INVALID_PARAMETER)   
    if info_type == InfoType.QUOTA:
        raise base.SMBError("Quotas not supported", NTStatus.NOT_SUPPORTED)
    elif info_type == InfoType.SECURITY:
        raise base.SMBError('"security" not supported', NTStatus.NOT_SUPPORTED)
    elif info_type == InfoType.FILE:
        try:
            info_class = InfoClassFiles(packet.body.info_class)
        except ValueError:
            raise SMBError("info_class", NTStatus.INVALID_INFO_CLASS)
    elif info_type == InfoType.FILESYSTEM:
        try:
            info_class = InfoClassFileSystems(packet.body.info_class)
        except ValueError:
            raise SMBError("info_class", NTStatus.INVALID_INFO_CLASS) 
    else:
        raise base.SMBError("invalid info_type", NTStatus.INVALID_PARAMETER)
    log.debug("""
QUERY INFO
----------
size    {sz}
file id {file_id}
flags   {flags:04x}
file    {fd!r}
type    {info_type}
class   {info_class}
output  {obl}
""",
    sz=packet.body.size,
    file_id=packet.body.file_id,
    flags=packet.body.flags,
    fd=fd,
    info_class=info_class,
    info_type=info_type,
    obl=packet.body.output_buffer_length) 
 
    extra = b''
    if info_class == InfoClassFiles.FileStandardInformation and IPipe.providedBy(fd):
        resp_data = FileStandardInformation(alloc_size=CLUSTER_SIZE, end_of_file=0, delete_pending=1, links=1)
        # for pipes "canned" data will suffice
    else:
        raise base.SMBError("%r not supported" % info_class, NTStatus.NOT_SUPPORTED)
    
    data = base.pack(resp_data)
    l = len(data) + len(extra)
    if l > packet.body.output_buffer_length:
        raise base.SMBError("output buffer too long",NTStatus.BUFFER_OVERFLOW)
    packet.data = base.pack(resp_type(length=l)) + data + extra
    sendHeader(packet)   
        
        .
   
def smb_ioctl(packet, resp_type):
    # this is a minimal implementation to satisfy clients that insist on
    # trying to obtain DFS referrals
    if packet.body.file_id == base.UUID_MAX:
        fd = None
    else:    
        fd = packet.ctx['files'][packet.body.file_id]
    il = packet.body.input_length
    if il == 0:
        input_data = b''
    else:
        io = packet.body.input_offset
        input_data = packet.data[io:io+il]
        
    ol = packet.body.output_length
    if ol == 0:
        output_data = b''
    else:
        oo = packet.body.output_offset
        output_data = packet.data[oo:oo+ol]
    
    ctl_code = Ioctl(packet.body.ctl_code)
    
    log.debug("""
IOCTL
-----
size     {sz}
file id  {file_id}
flags    {flags:04x}
file     {fd!r}
ctl_code {ctl_code}
input    {jnput_data!r}
output   {output_data!r}
max input  {max_input_response}
max output {max_output_response}
""",
    sz=packet.body.size,
    file_id=packet.body.file_id,
    flags=packet.body.flags,
    fd=fd,
    ctl_code=ctl_code,
    max_output_response=packet.body.max_output_response,    
    max_input_response=packet.body.max_input_response,
    input_data=input_data[:32],
    output_data=output_data[:32])

    if ctl_code == Ioctl.FSCTL_DFS_GET_REFERRALS or \
       ctl_code == Ioctl.FSCTL_DFS_GET_REFERRALS_EX:
        raise base.SMBError("no DFS", NTStatus.NOT_FOUND)
    else:
        raise base.SMBError("fsctl %r not supported" % ctl_code, NTStatus.INVALID_DEVICE_REQUEST)
        
        
        
        
        
        
class SMBFactory(protocol.Factory):
    """
    Factory for SMB servers
    """
    def __init__(self, portal, domain="WORKGROUP", fake=False):
        """
        @param portal: the configured portal
        @type portal: L{twisted.cred.portal.Portal}

        @param domain: the server's Windows/NetBIOS domain name
        @type domain: L{str}
        
        @param fake: whether to report fake or real system data
        @type fake: L{bool}
        """
        protocol.Factory.__init__(self)
        self.portal = portal
        if fake:
            server_uuid = uuid4()
            boot_time = 0
            fqdn = domain + '.localdomain'
        else:
            boot_time = base.wiggleTime()
            fqdn = socket.getfqdn()
            server_uuid = base.getMachineUUID()
        self.sys_data = SystemData(server_uuid, boot_time, domain, fqdn, fake)
         

    def buildProtocol(self, addr):
        log.debug("new SMB connection from {addr!r}", addr=addr)
        return base.SMBPacketReceiver(
            packetReceived,
            dict(addr=addr,
                 portal=self.portal,
                 sys_data=self.sys_data,
                 blob_manager=security_blob.BlobManager(self.sys_data),
                 trees={},
                 files={}))
