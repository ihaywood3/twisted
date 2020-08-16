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

from twisted.protocols._smb import base, security_blob, dcerpc, types
from twisted.protocols._smb.ismb import (ISMBServer, IFilesystem, IPipe, IIPC,
                                         IPrinter, NoSuchShare)

from twisted.internet import protocol
from twisted.logger import Logger
from twisted.cred.checkers import ANONYMOUS
from twisted.internet.defer import maybeDeferred, succeed

log = Logger()

COMMANDS = [('negotiate', types.NegReq, types.NegResp),
            ('session_setup', types.SessionReq, types.SessionResp),
            ('logoff', types.BasicPacket, types.BasicPacket),
            ('tree_connect', types.TreeReq, types.TreeResp),
            ('tree_disconnect', types.BasicPacket, types.BasicPacket),
            ('create', types.CreateReq, types.CreateResp),
            ('close', types.CloseReq, types.CloseResp),
            ('flush', types.FlushReq, types.BasicPacket),
            ('read', types.ReadReq, types.ReadResp),
            ('write', types.WriteReq, types.WriteResp),
            ('lock', types.LockReq, types.BasicPacket),
            ('ioctl', types.IoctlReq, types.IoctlResp),
            ('cancel', types.BasicPacket, None),
            ('echo', types.BasicPacket, types.BasicPacket),
            ('query_directory', types.QueryDirReq, types.QueryInfoResp),
            ('change_notify', types.ChangeNotifyReq, types.QueryInfoResp),
            ('query_info', types.QueryInfoReq, types.QueryInfoResp),
            ('set_info', types.SetInfoReq, types.SetInfoResp),
            ('oplock_break', types.OplockBreakAck, types.OplockBreakAck)]
            
            


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
        protocol_id = packet.data[offset:offset + len(types.SMB2_MAGIC)]
        if protocol_id == types.SMB1_MAGIC:
            # its a SMB1 packet which we dont support with the exception
            # of the first packet, we try to offer upgrade to SMB2
            if packet.ctx.get('avatar') is None:
                log.debug("responding to SMB1 packet")
                negotiateResponse(packet)
            else:
                packet.close()
                log.error("Got SMB1 packet while logged in")
            return
        elif protocol_id != types.SMB2_MAGIC:
            packet.close()
            log.error("Unknown packet type")
            log.debug("packet data {data!r}",
                      data=packet.data[offset:offset + 64])
            return
        packet.hdr, o2 = base.unpack(types.HeaderSync, packet.data, offset,
                                     base.OFFSET)
        isAsync = (packet.hdr.flags & types.FLAG_ASYNC) > 0
        isRelated = (packet.hdr.flags & types.FLAG_RELATED) > 0
        isSigned = (packet.hdr.flags & types.FLAG_SIGNED) > 0
        # FIXME other flags 3.1 or too obscure
        if isAsync:
            packet.hdr = base.unpack(types.HeaderAsync, packet.data, offset)
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
                    errorResponse(packet, types.NTStatus.NOT_IMPLEMENTED)
            except NotImplementedError as e:
                log.failure("in {cmd}", cmd=COMMANDS[packet.hdr.command][0])
                errorResponse(packet, types.NTStatus.NOT_IMPLEMENTED)
            except base.SMBError as e:
                log.error("SMB error: {e}", e=str(e))
                errorResponse(packet, e.ntstatus)
            except BaseException:
                log.failure("in {cmd}", cmd=COMMANDS[packet.hdr.command][0])
                errorResponse(packet, types.NTStatus.UNSUCCESSFUL)
        else:
            log.error("unknown command 0x{cmd:x}", cmd=packet.hdr.command)
            errorResponse(packet, types.NTStatus.NOT_IMPLEMENTED)

        offset += packet.hdr.next_command



def sendHeader(packet, command=None, status=types.NTStatus.SUCCESS):
    """
    prepare and transmit a SMB header and payload
    so actually a full packet but focus of function on header construction

    @param command: command name or id, defaults to same as received packet
    @type command: L{str} or L{int}

    @param packet: the packet, C{data} contains after-header data
    @type packet: L{base.SMBPacket}

    @param status: packet status, an NTSTATUS code
    @type status: L{int} or L{types.NTStatus}
    """
    # FIXME credit and signatures not supported yet
    if packet.hdr is None:
        packet.hdr = types.HeaderSync()
    packet.hdr.flags |= types.FLAG_SERVER
    packet.hdr.flags &= ~types.FLAG_RELATED
    if isinstance(command, str):
        cmds = [c[0] for c in COMMANDS]
        command = cmds.index(command)
    if command is not None:
        packet.hdr.command = command
    if isinstance(status, types.NTStatus):
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
                                  offset=base.calcsize(types.HeaderSync) +
                                  packet.body.size)
    signing_enabled = (packet.body.security_mode
                       & types.NEGOTIATE_SIGNING_ENABLED) > 0
    # by spec this should never be false
    signing_required = (packet.body.security_mode
                        & types.NEGOTIATE_SIGNING_REQUIRED) > 0
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
    @type ntstatus: L{int} or L{types.NTStatus}
    """
    packet.data = types.ERROR_RESPONSE_MAGIC
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
        if dialect > types.MAX_DIALECT:
            raise base.SMBError(
                "min client dialect %04x higher than our max %04x" %
                (dialect, types.MAX_DIALECT))
        log.debug("dialect {dlt:04x} chosen", dlt=dialect)
    resp = types.NegResp()
    resp.signing = types.NEGOTIATE_SIGNING_ENABLED
    resp.dialect = dialect
    resp.server_uuid = packet.ctx['sys_data'].server_uuid
    resp.capabilities = types.GLOBAL_CAP_DFS
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
        sessionSetupResponse(packet, blob, types.NTStatus.MORE_PROCESSING)
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
                sessionSetupResponse(packet, blob, types.NTStatus.SUCCESS)

            def eb_login(failure):
                log.debug(failure.getTraceback())
                blob = blob_manager.generateAuthResponseBlob(False)
                sessionSetupResponse(packet, blob, types.NTStatus.LOGON_FAILURE)

            d.addCallback(cb_login)
            d.addErrback(eb_login)
        else:
            blob = blob_manager.generateChallengeBlob()
            sessionSetupResponse(packet, blob, types.NTStatus.MORE_PROCESSING)



def sessionSetupResponse(packet, blob, ntstatus):
    """
    send session setup response

    @type packet: L{base.SMBPacket}

    @param blob: the security blob to include in the response
    @type blob: L{bytes}

    @param ntstatus: response status
    @type ntstatus: L{types.NTStatus}
    """
    log.debug("sessionSetupResponse")
    resp = types.SessionResp()
    if packet.ctx['blob_manager'].credential == ANONYMOUS:
        resp.flags |= types.SESSION_FLAG_IS_NULL
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
        errorResponse(packet, types.NTStatus.BAD_NETWORK_NAME)
    elif failure.check(base.SMBError):
        log.failure("SMB error {e}", failure, e=str(failure.value))
        errorResponse(packet, failure.value.ntstatus)
    else:
        log.failure("eb_common", failure)
        errorResponse(packet, types.NTStatus.UNSUCCESSFUL)


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
        errorResponse(packet, types.NTStatus.ACCESS_DENIED)
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
                share_type=types.SHARE_DISK,
                # FUTURE: select these values from share object
                flags=types.SHAREFLAG_MANUAL_CACHING,
                capabilities=0,
                max_perms=(types.FILE_READ_DATA | types.FILE_WRITE_DATA
                           | types.FILE_APPEND_DATA 
                           #| FILE_WRITE_EA | FILE_READ_EA
                           | types.FILE_DELETE_CHILD | types.FILE_EXECUTE
                           | types.FILE_READ_ATTRIBUTES
                           | types.FILE_WRITE_ATTRIBUTES
                           | types.DELETE | types.READ_CONTROL | types.WRITE_DAC
                           | types.WRITE_OWNER
                           | types.SYNCHRONIZE))
        if IIPC.providedBy(share):
            assert resp is None, "share can only be one type"
            resp = resp_type(
                share_type=types.SHARE_PIPE,
                flags=0,
                max_perms=(
                    types.FILE_READ_DATA | types.FILE_WRITE_DATA | types.FILE_APPEND_DATA  |
                    #| FILE_READ_EA |
                    # FILE_WRITE_EA |
                    # FILE_DELETE_CHILD |
                    types.FILE_EXECUTE | types.FILE_READ_ATTRIBUTES |
                    # FILE_WRITE_ATTRIBUTES |
                    types.DELETE | types.READ_CONTROL |
                    # WRITE_DAC |
                    # WRITE_OWNER |
                    types.SYNCHRONIZE))
        if IPrinter.providedBy(share):
            assert resp is None, "share can only be one type"
            resp = resp_type(
                share_type=types.SHARE_PRINTER,
                flags=0,
                # FIXME need to check printer  max perms
                max_perms=(
                    types.FILE_READ_DATA | types.FILE_WRITE_DATA | types.FILE_APPEND_DATA |
                    #| FILE_READ_EA |
                    # FILE_WRITE_EA |
                    # FILE_DELETE_CHILD |
                    types.FILE_EXECUTE | types.FILE_READ_ATTRIBUTES |
                    # FILE_WRITE_ATTRIBUTES |
                    types.DELETE | types.READ_CONTROL |
                    # WRITE_DAC |
                    # WRITE_OWNER |
                    types.SYNCHRONIZE))
        if resp is None:
            log.error("unknown share object {share!r}", share=share)
            errorResponse(packet, types.NTStatus.UNSUCCESSFUL)
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
        errorResponse(packet, types.NTStatus.ACCESS_DENIED)
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
              
    def cb_create_final(s, file_id, action):
        resp = resp_type(file_size=s.end_of_file,
                alloc_size=s.alloc_size,
                oplock_level=types.OplockLevels.NoLock,
                action=action,
                file_id=file_id,
                attributes=s.attributes,
                ctime=s.ctime,
                atime=s.atime,
                wtime=s.wtime,
                mtime=s.mtime,
                ctx_offset=0)
        packet.data = base.pack(resp)
        sendHeader(packet)
        
              
    if IIPC.providedBy(tree):
        d1 = maybeDeferred(tree.open, path)
 
        def cb_create_ipc(pipe):
            shim = shim.PipeShim(pipe)
            file_id = uuid4()
            packet.ctx['files'][file_id] = shim
            # for pipes not a Deferred, but otherwise would be
            noi = shim.getFileNetworkOpenInformation()
            cb_create_final(noi, file_id, types.CreateAction.Opened)
 
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
        resp = resp_type(file_size=s.end_of_file,
            alloc_size=s.alloc_size,
            flags=types.CLOSE_FLAG_POSTQUERY_ATTRIB,
            attributes=s.attributes,
            ctime=s.ctime,
            atime=s.atime,
            wtime=s.wtime,
            mtime=s.mtime)
        d1 = fd.close()
        d1.addCallback(cb_close, resp)
        d1.addErrback(lambda f: log.failure("in smb_close", f))      
        
    if packet.body.flags & types.CLOSE_FLAG_POSTQUERY_ATTRIB > 0:
        d2 = maybeDeferred(fd.getFileNetworkOpenInformation)
        d2.addCallback(cb_close_stat)
        d2.addErrback(eb_common, packet)
    else:
        resp = resp_type() # everything's zero
        d3 = fd.close()
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
          
    d = fd.flush()
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
    
    def cb_read(data):
        if len(data) < packet.body.minimum_count:
            raise base.SMBError('below minimum_count', types.NTStatus.DATA_ERROR)
        min_offset = base.calcsize(types.HeaderAsync) + base.calcsize(types.ReadResp)
        offset = max(min_offset, packet.body.padding)
        if offset > min_offset:
            padding = b'\0'*(offset-min_offset)
        else:
            padding = b''
        resp = types.ReadResp(offset=offset,length=len(data))
        packet.data = base.pack(resp) + padding + data
        sendHeader(packet)
   
    d = fd.read(packet.body.offset, packet.body.length)
    d.addCallback(cb_read)
    d.addErrback(eb_common, packet)
   
         
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
    
    def cb_write(count):
        resp = resp_type(count=count)
        packet.data = base.pack(resp)
        sendHeader(packet)
    
    d = fd.write(packet.body.offset, data)
    d.addCallback(cb_write)
    d.addErrback(eb_common, packet)



 
def smb_query_info(packet, resp_type):
    if packet.body.file_id == base.UUID_MAX:
        fd = None
    else:
        fd = packet.ctx['files'][packet.body.file_id]
    tree = packet.ctx['trees'][packet.hdr.tree_id]
    try:
        info_type = types.InfoType(packet.body.info_type)
    except ValueError:
        raise base.SMBError("invalid info_type", types.NTStatus.INVALID_PARAMETER)   
    if info_type == types.InfoType.QUOTA:
        raise base.SMBError("Quotas not supported", types.NTStatus.NOT_SUPPORTED)
    elif info_type == types.InfoType.SECURITY:
        raise base.SMBError('"security" not supported', types.NTStatus.NOT_SUPPORTED)
    elif info_type == types.InfoType.FILE:
        try:
            info_class = types.InfoClassFiles(packet.body.info_class)
        except ValueError:
            raise SMBError("info_class", types.NTStatus.INVALID_INFO_CLASS)
    elif info_type == types.InfoType.FILESYSTEM:
        try:
            info_class = types.InfoClassFileSystems(packet.body.info_class)
        except ValueError:
            raise SMBError("info_class", types.NTStatus.INVALID_INFO_CLASS) 
    else:
        raise base.SMBError("invalid info_type", types.NTStatus.INVALID_PARAMETER)
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
 
    def cb_info(resp):
        if hasattr(resp, "extra"):
            extra = resp.extra
            if type(extra) is str:
                extra = extra.encode("utf-16le")
            resp.buflen = len(extra)
        else:
            extra = b''
        data = base.pack(resp)
        l = len(data) + len(extra)
        if l > packet.body.output_buffer_length:
            raise base.SMBError("output buffer too long",types.NTStatus.BUFFER_OVERFLOW)
        packet.data = base.pack(resp_type(length=l)) + data + extra
        sendHeader(packet)   
    
    func_name = 'get' + info_class.name    
    try:
        if info_type == types.InfoType.FILE:
            if fd is None:
                raise base.SMBError("must have file_id for FILE info type", types.NTStatus.INVALID_PARAMETER)
            func = getattr(fd, func_name)
        else:
            func = getattr(tree, func_name) 
    except AttributeError:
        raise base.SMBError("%s not available" % info_class.name, types.NTStatus.NOT_SUPPORTED)
    d = maybeDeferred(func)
    d.addCallback(cb_info)
    d.addErrback(eb_common, packet)    
   
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
    
    ctl_code = types.Ioctl(packet.body.ctl_code)
    
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

    if ctl_code == types.Ioctl.FSCTL_DFS_GET_REFERRALS or \
        ctl_code == types.Ioctl.FSCTL_DFS_GET_REFERRALS_EX:
        raise base.SMBError("no DFS", types.NTStatus.NOT_FOUND)
    else:
        raise base.SMBError("fsctl %r not supported" % ctl_code, types.NTStatus.INVALID_DEVICE_REQUEST)
        
        
        
        
        
        
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
