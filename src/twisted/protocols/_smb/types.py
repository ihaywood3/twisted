# -*- test-case-name: twisted.protocols._smb.tests -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
"""
holds data structures and associated bitmasks, enums and constants
used in the core protocol
"""

from collections import namedtuple
import enum
import attr

from twisted.protocols._smb.base import (byte, short, medium, long, uuid,
                                         octets)

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



FILE_ATTRIBUTE_ARCHIVE = 0x00000020
FILE_ATTRIBUTE_COMPRESSED = 0x00000800
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_ENCRYPTED = 0x00004000
FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
FILE_ATTRIBUTE_OFFLINE = 0x00001000
FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200
FILE_ATTRIBUTE_SYSTEM = 0x00000004
FILE_ATTRIBUTE_TEMPORARY = 0x00000100
FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x00008000
FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x00020000

# for CreateReq.share_access
FILE_SHARE_READ = 0x01
FILE_SHARE_WRITE = 0x02
FILE_SHARE_DELETE = 0x03



class CreateDisposition(enum.Enum):
    Supersede = 0
    Open = 1
    Create = 2
    OpenIf = 3
    Overwrite = 4
    OverwriteIf = 5



# for CreateReq.options
FILE_DIRECTORY_FILE = 0x00000001
FILE_WRITE_THROUGH = 0x00000002
FILE_SEQUENTIAL_ONLY = 0x00000004
FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008
FILE_SYNCHRONOUS_IO_ALERT = 0x00000010  # ignored
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020  # ignored
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_COMPLETE_IF_OPLOCKED = 0x00000100  # ignored
FILE_NO_EA_KNOWLEDGE = 0x00000200
FILE_RANDOM_ACCESS = 0x00000800
FILE_DELETE_ON_CLOSE = 0x00001000
FILE_OPEN_BY_FILE_ID = 0x00002000  # ignored
FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000
FILE_NO_COMPRESSION = 0x00008000
FILE_OPEN_REMOTE_INSTANCE = 0x00000400  # ignored
FILE_OPEN_REQUIRING_OPLOCK = 0x00010000  # ignored
FILE_DISALLOW_EXCLUSIVE = 0x00020000  # ignored
FILE_RESERVE_OPFILTER = 0x00100000  # server must fail if set
FILE_OPEN_REPARSE_POINT = 0x00200000
FILE_OPEN_NO_RECALL = 0x00400000
FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000



@attr.s
class CreateReq:
    """create (actually "open") a file"""
    size = short(57, locked=True)
    security_flags = byte()  # unused
    oplock_level = byte()
    impersonation_level = medium()
    flags = long()  # unused
    reserved = long()  # unused
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
    flags = byte()  # unused on 2.x
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



CLOSE_FLAG_POSTQUERY_ATTRIB = 0x0001



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
    channel = medium()  # for RDMA
    remaining_bytes = medium()
    channel_offset = short()
    channel_length = short()



@attr.s
class ReadResp:
    size = medium(17, locked=True)
    offset = byte()
    reserved = byte()
    length = medium()
    remaining = medium()  # only for RDMA channels
    reserved2 = medium()



WRITEFLAG_WRITE_THROUGH = 0x00000001
WRITEFLAG_WRITE_UNBUFFERED = 0x00000002



@attr.s
class WriteReq:
    size = short(49, locked=True)
    data_offset = short()
    length = medium()
    offset = long()
    file_id = uuid()
    channel = medium()  # for RDMA
    remaining_bytes = medium()
    channel_offset = short()
    channel_length = short()
    flags = medium()



@attr.s
class WriteResp:
    size = short(17, locked=True)
    reserved = short()
    count = medium()
    remaining_bytes = medium()  # unused
    channel_offset = short()  # unused
    channel_length = short()  # unused



class Ioctl(enum.Enum):
    """values for Ioctl.ctl_code"""
    FSCTL_DFS_GET_REFERRALS = 0x00060194
    FSCTL_PIPE_PEEK = 0x0011400C
    FSCTL_PIPE_WAIT = 0x00110018
    FSCTL_PIPE_TRANSCEIVE = 0x0011C017
    FSCTL_SRV_COPYCHUNK = 0x001440F2
    FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064
    FSCTL_SRV_REQUEST_RESUME_KEY = 0x00140078
    FSCTL_SRV_READ_HASH = 0x001441bb
    FSCTL_SRV_COPYCHUNK_WRITE = 0x001480F2
    FSCTL_LMR_REQUEST_RESILIENCY = 0x001401D4
    FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC
    FSCTL_SET_REPARSE_POINT = 0x000900A4
    FSCTL_DFS_GET_REFERRALS_EX = 0x000601B0
    FSCTL_FILE_LEVEL_TRIM = 0x00098208
    FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204



IOCTL_FLAG_IS_FSCTL = 0x01



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
    FILE = 0x01
    FILESYSTEM = 0x02
    SECURITY = 0x03
    QUOTA = 0x04



class InfoClassFiles(enum.Enum):
    """
    QueryInfoReq.info_class when info_type == INFO_FILE
    """
    FileAccessInformation = 8  # query
    FileAlignmentInformation = 17  # query
    FileAllInformation = 18  # query
    FileAllocationInformation = 19  # set
    FileAlternateNameInformation = 21  # query
    FileAttributeTagInformation = 35  # query
    FileBasicInformation = 4  # query set
    FileBothDirectoryInformation = 3  # dir
    FileCompressionInformation = 28  # query
    FileDirectoryInformation = 1  # dir
    FileDispositionInformation = 13  # set
    FileEaInformation = 7  # query
    FileEndOfFileInformation = 20  # set
    FileFullDirectoryInformation = 2  # dir
    FileFullEaInformation = 15  # query set
    FileIdBothDirectoryInformation = 37  # dir
    FileIdFullDirectoryInformation = 38
    FileIdInformation = 59  # query
    FileInternalInformation = 6  # query
    FileLinkInformation = 11  # set
    FileModeInformation = 16  # query set
    FileNamesInformation = 12  # dir
    FileNetworkOpenInformation = 34  # query
    FileNormalizedNameInformation = 48  # query
    FilePipeInformation = 23  # query  set
    FilePipeLocalInformation = 24  # query
    FilePipeRemoteInformation = 25  # query
    FilePositionInformation = 14  # query set
    FileRenameInformation = 10  # set
    FileShortNameInformation = 40  # set
    FileStandardInformation = 5  # query
    FileStreamInformation = 22  # query
    FileValidDataLengthInformation = 39  # set



class InfoClassFileSystems(enum.Enum):
    """
    QueryInfoReq.info_class when info_type == INFO_FILESYSTEM
    """
    FileFsVolumeInformation = 1
    FileFsSizeInformation = 3
    FileFsDeviceInformation = 4
    FileFsAttributeInformation = 5
    FileFsControlInformation = 6  # set
    FileFsFullSizeInformation = 7
    FileFsObjectIdInformation = 8  # set
    FileFsSectorSizeInformation = 11



@attr.s
class QueryInfoReq:
    size = short(41, locked=True)
    info_type = byte()
    info_class = byte()
    output_buffer_length = medium()
    offset = short()
    reserved = short()
    length = medium()
    addn_info = medium()  # only used for EA queries
    flags = medium()  # only used for EA queries
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
    addn_info = medium()  # EA only
    file_id = uuid()



@attr.s
class SetInfoResp:
    size = short(2, locked=True)



# QueryDirReq.flags
QUERY_DIR_RESTART_SCANS = 0x01
QUERY_DIR_RETURN_SINGLE_ENTRY = 0x02
QUERY_DIR_INDEX_SPECIFIED = 0x04
QUERY_DIR_REOPEN = 0x10



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
    size = short(48, locked=True)
    num_locks = short()
    lock_sequence = medium()
    file_id = uuid()



# LockElement.flags
LOCKFLAG_SHARED_LOCK = 0x00000001
LOCKFLAG_EXCLUSIVE_LOCK = 0x00000002
LOCKFLAG_UNLOCK = 0x00000004
LOCKFLAG_FAIL_IMMEDIATELY = 0x00000010



@attr.s
class LockElement:
    offset = long()
    length = long()
    flags = medium()
    reserved = medium()



# ChangeNotifyReq.flags
CHANGE_NOTIFY_WATCH_TREE = 0x0001

# ChangeNotifyReq.completion_filter
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
FILE_NOTIFY_CHANGE_EA = 0x00000080
FILE_NOTIFY_CHANGE_SECURITY = 0x00000100
FILE_NOTIFY_CHANGE_STREAM_NAME = 0x00000200
FILE_NOTIFY_CHANGE_STREAM_SIZE = 0x00000400
FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800



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



@attr.s
class FileStandardInformation:
    alloc_size = long()
    end_of_file = long()
    links = medium()
    delete_pending = byte()
    directory = byte()
    reserved = medium()



@attr.s
class FileBasicInformation:
    ctime = long()
    atime = long()
    wtime = long()
    mtime = long()
    attributes = medium()
    reserved = medium()



@attr.s
class FileNetworkOpenInformation:
    ctime = long()
    atime = long()
    wtime = long()
    mtime = long()
    alloc_size = long()
    end_of_file = long()
    attributes = medium()
    reserved = medium()



@attr.s
class FileRenameInformation:
    replace = byte()
    padding = octets(7)
    root_dir = long()  # not used
    length = medium()
    filename = attr.ib(default="")



@attr.s
class FileDispositionInformation:
    delete_pending = byte()
