# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
# -*- test-case-name: twisted.protocols._smb.tests -*-
"""
SMB has an RPC subprotocol called DCE/RPC ("Distributed Computing
Environment") It's quite old, one of those overengineered we-solve-everything
systems in the style of CORBA and SOAP.

This module is B{NOT} a conformant implementation, in particular it cannot
parse the DCE/RPC IDL, but a minimal module to support RPC necessary for
filesharing. IDLs need to be converted to a simpler format see L{pack} /
L{unpack}

Intregation
===========

Clients connect to an unlisted IPC share that exists on every SMB server:
C{IPC$}, within that they can open several different SMB named pipes, speaking
DCE/RPC across the pipe. The pipes have fixed names and interfaces, in sum they
offer access to a lot of Windows OS functions.

Again this module only implements the subset of these interfaces required for
filesharing, new functions can be added using the decorator L{register}

Links
=====

- the DCE/RPC spec itself
  U{https://pubs.opengroup.org/onlinepubs/009629399/toc.htm}
- Microsoft's
  U{extensions<https://docs.microsoft.com/en-us/openspecs/windows_protocols/
  ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15>} to the above
- the named pipes known so far
  - U{C{wkssvc}<https://docs.microsoft.com/en-us/openspecs/windows_protocols/
    ms-wkst/5bb08058-bc36-4d3c-abeb-b132228281b7>}
    "workstation service"
  - U{C{srvsvc}<https://docs.microsoft.com/en-us/openspecs/windows_protocols/
    ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9>}
    "server service"
  - U{C{samr}<https://docs.microsoft.com/en-us/openspecs/windows_protocols/
    ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380>} "security manager"
  - U{C{winreg}<https://wiki.wireshark.org/WINREG>} "windows registry"
"""

import struct
import io
import enum
import attr
import random
import platform
import uuid as uuid_mod

from zope.interface import implementer

from twisted.protocols._smb import base, ismb
from twisted.protocols._smb.base import (byte, short, medium, uuid, octets)
from twisted.logger import Logger
from twisted.internet.defer import maybeDeferred

log = Logger()

RPC_FUNCTIONS = {}
# keyed by pipe name, in turn keyed by opcode

MAX_ASSOC_GROUP_ID = 2**32 - 1



def register(pipe, opcode):
    """
    a Python decorator

    register a function as a handler for a DCE/RPC call.
    the function receives and returns a single C{bytes}
    It is responsible for marshalling/unmarshalling its own
    data frames, but see L{pack} / L{unpack}

    @param pipe: the pipe name: C{srvsvc}, C{wkssvc}, I{et al.}
    @type pipe: L{str}
    @param opcode: the function's opcode (see specs for that interface)
    @type opcode: L{int}
    """
    return lambda f: _register(f, pipe, opcode)



def _register(f, pipe, opcode):
    if pipe not in RPC_FUNCTIONS:
        RPC_FUNCTIONS[pipe] = {}
    RPC_FUNCTIONS[pipe][opcode] = f
    return f



WCHAR = "W"



def wchar(default=""):
    """a Windows "wide char" (UTF-16) string"""
    return attr.ib(default=default,
                   type=str,
                   metadata={base.SMB_METADATA: WCHAR})



def referent():
    """ a DCE/RPC "referent",as best as I can read the spec is an
    attempt to represent the semantics of a C pointer on the wire
    Can largely be ignored for our purposes
    """
    return attr.ib(factory=_referent_factory,
                   type=int,
                   metadata={base.SMB_METADATA: "I"})



def _referent_factory():
    global ref_counter
    ref_counter += 1
    return ref_counter



REFERENT_START = 0x20000  # from wireshark, unsure origin



def resetReferents():
    global ref_counter
    ref_counter = REFERENT_START



def unpack(cls, data, offset=0):
    """
    L{base.unpack} is  extended to support one exrra
    nonstandard struct type
    - C{W} a Windows "wide char" (UTF-16) string

    @rtype: C{tuple}: (object, offset)

    B{NOTE:} this is much more inefficient than L{base.unpack}, only use when
    necessary
    """
    values = {}
    for f in base.smb_fields(cls):
        if f.metadata[base.SMB_METADATA] == WCHAR:
            values[f.name], offset = _unpackWchar(data, offset)
        else:
            fmt = "<" + f.metadata[base.SMB_METADATA]
            v, = struct.unpack_from(fmt, data, offset)
            values[f.name] = v
            offset += struct.calcsize(fmt)
    return (cls(**values), offset)



_3ints = struct.Struct("<III")



def _unpackWchar(data, offset):
    max_count, offset2, actual_count = _3ints.unpack_from(data, offset)
    offset += _3ints.size
    s = data[offset + (offset2 * 2):offset + (actual_count - 1) * 2]
    assert data[offset + (actual_count - 1) * 2:offset +
                (actual_count * 2)] == b'\0\0'
    offset += actual_count * 2
    if actual_count % 2 > 0:
        offset += 2  # maintain 4-byte alignment
    return (s.decode('utf-16le'), offset)



def pack(obj, caller_bio=None):
    """
    L{base.pack} is extended to support L{wchar}

    @param caller_bio: a I/O buffer to write the result to
    @type caller_bio: L{io.BytesIO}

    @rtype: L{bytes}


    B{NOTE:} this is much more inefficient than L{base.pack}, only use when
    necessary
    """
    if caller_bio:
        bio = caller_bio
    else:
        bio = io.BytesIO()
    for f in base.smb_fields(type(obj)):
        t = f.metadata[base.SMB_METADATA]
        n = f.name
        if t == WCHAR:
            v = getattr(obj, n, "")
            logical_len = len(v) + 1
            v = v.encode("utf-16le")
            bio.write(_3ints.pack(logical_len, 0, logical_len))
            bio.write(v)
            if logical_len % 2 == 0:
                bio.write(b'\0\0')
            else:
                bio.write(b'\0\0\0\0')  # maintain 4-byte alignment
        else:
            fmt = "<" + t
            v = getattr(obj, n)
            bio.write(struct.pack(fmt, v))
    if caller_bio:
        return None
    else:
        return bio.getvalue()



PTYPES = [
    'request', 'ping', 'response', 'fault', 'working', 'nocall', 'reject',
    'ack', 'cl_cancel', 'fack', 'cancel_ack', 'bind', 'bind_ack', 'bind_nak',
    'alter_context', 'alter_context_resp', 'shutdown', 'co_cancel', 'orphaned'
]

RPC_VERSION = 5
RPC_VERSION_MINOR = 1

SERVER_VERSION = 6
SERVER_VERSION_MINOR = 1

PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02
PFC_PENDING_CANCEL = 0x04
PFC_CONC_MPX = 0x10  # supports concurrent multiplexing of a single connection.
PFC_DID_NOT_EXECUTE = 0x20  # on fault only
PFC_MAYBE = 0x40  # `maybe' call semantics requested
PFC_OBJECT_UUID = 0x80  # if true, a non-nil object UUID

# drep = data representation. drep[2] and [3] are blank
# flags for drep[0]
DREP_CHAR_EBCDIC = 0x01
DREP_INT_LITTLEENDIAN = 0x10



# values for drep[1]
class FloatFormat(enum.Enum):
    IEEE = 0
    VAX = 1
    CRAY = 2
    IBM = 3



# we only accept ASCII, little-endian, IEEE-float



@attr.s
class DceHeader:
    rpc_vers = byte(RPC_VERSION)
    rpc_vers_minor = byte()
    ptype = byte()
    pfc_flags = byte()
    drep = octets(4)
    frag_length = short()
    auth_length = short()
    callid = medium()



@attr.s
class Bind:
    max_xmit_frag = short()
    max_recv_frag = short()
    assoc_group_id = medium()
    n_contexts = byte()
    padding = octets(3)



@attr.s
class PresentationContext:
    p_cont_id = short()
    n_transfer_syntaxes = byte()
    pad = byte()
    abstract_uuid = uuid()
    abstract_version = medium()



@attr.s
class TransferSyntax:
    uuid = uuid()
    vers = medium()



# BindAck: acknowledgement of a bind



# result codes
class BindAckResult(enum.Enum):
    ACCEPTANCE = 0
    USER_REJECTION = 1
    PROVIDER_REJECTION = 2



# reason codes
class BindAckReason(enum.Enum):
    REASON_NOT_SPECIFIED = 0
    ABSTRACT_SYNTAX_NOT_SUPPORTED = 1
    PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED = 2
    LOCAL_LIMIT_EXCEEDED = 3



@attr.s
class BindAck:
    max_xmit_frag = short()
    max_recv_frag = short()
    assoc_group_id = medium()
    sec_addr = short()
    # we dont support actually sending secondary address
    pad = octets(2)
    n_results = byte()
    pad2 = octets(3)



@attr.s
class ResultItem:
    result = short()
    reason = short()
    uuid = uuid()
    vers = medium()



# we only support one transfer syntax, the "standard" 32-bit one
TRANSFER_SYNTAX = uuid_mod.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")



# bind nak failure codes
class BindNakFailure(enum.Enum):
    REASON_NOT_SPECIFIED = 0
    TEMPORARY_CONGESTION = 1
    LOCAL_LIMIT_EXCEEDED = 2
    PROTOCOL_VERSION_NOT_SUPPORTED = 4



@attr.s
class BindNak:
    """refuse a binding"""
    provider_reject_reason = short()
    n_versions = byte()



@attr.s
class BindNakVersion:
    major = byte()
    minor = byte()



class FaultStatus(enum.Enum):
    object_not_found = 0x1C000024
    cancel = 0x1C00000D
    addr_error = 0x1C000002
    context_mismatch = 0x1C00001A
    fp_div_zero = 0x1C000003
    fp_error = 0x1C00000F
    fp_overflow = 0x1C000005
    fp_underflow = 0x1C000004
    ill_inst = 0x1C00000E
    int_div_by_zero = 0x1C000001
    int_overflow = 0x1C000010
    invalid_bound = 0x1C000007
    invalid_tag = 0x1C000006
    pipe_closed = 0x1C000015
    pipe_comm_error = 0x1C000018
    pipe_discipline = 0x1C000017
    pipe_empty = 0x1C000014
    pipe_memory = 0x1C000019
    pipe_order = 0x1C000016
    remote_no_memory = 0x1C00001B
    user_defined = 0x1C000021
    tx_open_failed = 0x1C000022
    codeset_conv_error = 0x1C000023
    no_client_stub = 0x1C000025
    protocol_error = 0x1C01000B
    unknown_interface = 0x1C010003
    server_busy = 0x1C010014
    unsupported_operation = 0x1C010017
    invalid_pres_context_id = 0x1C00001C



class TooBusy(Exception):
    """
    an exception for functions to signal congestion
    """



@attr.s
class Fault:
    alloc_hint = medium()
    p_cont_id = short()
    cancel_count = byte()
    reserved = byte()
    status = medium()
    reserved2 = medium()



@attr.s
class Request:
    alloc_hint = medium()
    p_cont_id = short()
    opnum = short()



@attr.s
class Response:
    alloc_hint = medium()
    p_cont_id = short()
    cancel_count = byte()
    reserved = byte()  # essentially a pad byte to maintain 8-byte alignment



SEC_HEADER_MAP = {
    'request': Request,
    'response': Response,
    'fault': Fault,
    'bind': Bind,
    'bind_ack': BindAck,
    'bind_nak': BindNak,
}



@implementer(ismb.IIPC)
class BasicIPC:
    """
    An IPC share that returns a named pipe under whatever file name opened,
    bound to the Windows API of the same name
    """
    def __init__(self, sys_data, avatar):
        """
        @param sys_data: tuple for system data
        @type sys_data: L{types.SystemData}

        @param avatar: avatar of logged-in user
        @type avatar; L{ismb.ISMBServer}
        """
        self.avatar = avatar
        self.sys_data = sys_data

    def open(self, name):
        return DceRpcProcessor(self.sys_data, self.avatar, name)



@implementer(ismb.IPipe)
class DceRpcProcessor:
    """
    A pipe that speaks the DCE/RPC protocol
    """
    def __init__(self, sys_data, avatar, pipe_name):
        """
        @param sys_data: tuple for system data
        @type sys_data: L{types.SystemData}

        @param avatar: avatar of logged-in user
        @type avatar; L{ismb.ISMBServer}

        @param pipe_name: filename of pipe (determines API offered)
        @type pipe_name: L{str}
        """
        self.pipe = pipe_name
        self.reply = io.BytesIO()
        self.cancellations = set()
        self.sys_data = sys_data
        self.avatar = avatar
        self.buffer = b''
        self.rpc_vers_minor = 0  # use lowest version initially

    def dataReceived(self, data):
        self.buffer += data
        while True:
            if len(self.buffer) < base.calcsize(DceHeader):
                return
            header, offset = base.unpack(DceHeader, self.buffer, 0,
                                         base.OFFSET)
            if self._sanity_check(header):
                self.buffer = b''
                return
            if len(self.buffer) < header.frag_length:
                return
            self.fragmentReceived(header,
                                  self.buffer[offset:header.frag_length])
            self.buffer = self.buffer[header.frag_length:]

    def _sanity_check(self, header):
        insane = False
        version = False
        if header.rpc_vers != RPC_VERSION:
            insane = True
            version = True
            log.error("DCE/RPC major version {n}, must be {m}",
                      n=header.rpc_vers,
                      m=RPC_VERSION)
        if header.rpc_vers_minor > RPC_VERSION_MINOR:
            insane = True
            version = True
            log.error("DCE/RPC minor version {n}, must be {m} or lower",
                      n=header.rpc_vers_minor,
                      m=RPC_VERSION_MINOR)
        if not header.drep[0] & DREP_INT_LITTLEENDIAN:
            insane = True
            log.error("DCE/RPC must be little-endian")
        if header.drep[0] & DREP_CHAR_EBCDIC:
            insane = True
            log.error("DCE/RPC EBCDIC not supported")
        if header.auth_length > 0:
            insane = True
            log.error("DCE/RPC authentication not supported")
        if header.ptype >= len(PTYPES):
            insane = True
            log.error("DCE/RPC ptype={n} isn't valid", n=header.ptype)
            ptype_name = None
        else:
            self.ptype_name = ptype_name = PTYPES[header.ptype]
            if not hasattr(self, 'dcerpc_' + ptype_name):
                insane = True
                log.error('DCE/RPC ptype={n} not implemented', n=ptype_name)
        if insane and ptype_name == 'bind':
            # we can communicate our displeasure using bind_nak
            if version:
                nak = BindNak(provider_reject_reason=BindNakFailure.
                              PROTOCOL_VERSION_NOT_SUPPORTED.value,
                              n_versions=1)
                vers = BindNakVersion(major=RPC_VERSION,
                                      minor=RPC_VERSION_MINOR)
                self.send('bind_nak',
                          base.pack(nak),
                          base.pack(vers),
                          callid=header.callid)
            else:
                nak = BindNak(provider_reject_reason=BindNakFailure.
                              REASON_NOT_SPECIFIED.value,
                              n_versions=0)
                self.send('bind_nak', base.pack(nak), callid=header.callid)
        return insane

    def fragmentReceived(self, header, fragment):
        ptype_name = PTYPES[header.ptype]
        if ptype_name in SEC_HEADER_MAP:
            cls = SEC_HEADER_MAP[ptype_name]
            sec_header, fragment = base.unpack(cls, fragment, 0, base.DATA)
        else:
            sec_header = None
        if ptype_name in ['request', 'response', 'fault']:
            if header.pfc_flags & PFC_FIRST_FRAG:
                self.payload = b''
            self.payload += fragment
            if header.pfc_flags & PFC_LAST_FRAG:
                self.packetRecieved(header, sec_header, self.payload)
        else:
            # other packet types lack a splittable payload
            self.packetRecieved(header, sec_header, fragment)

    def packetRecieved(self, header, sec_header, payload):
        ptype_name = PTYPES[header.ptype]
        getattr(self, 'dcerpc_' + ptype_name)(header, sec_header, payload)

    def dcerpc_bind(self, header, sec_header, payload):
        offset = 0
        self.contexts = {}
        replies = []
        for i in range(sec_header.n_contexts):
            pc, offset = base.unpack(PresentationContext, payload, offset,
                                     base.OFFSET)
            log.debug(
                "DCE/RPC bind presentation context abstract_uuid={u!r}.{v!r}",
                u=pc.abstract_uuid,
                v=pc.abstract_version)
            found_ts = False
            ts_version = 0
            for j in range(pc.n_transfer_syntaxes):
                ts, offset = base.unpack(TransferSyntax, payload, offset,
                                         base.OFFSET)
                if ts.uuid == TRANSFER_SYNTAX:
                    found_ts = True
                    ts_version = ts.vers
            if found_ts:
                self.contexts[pc.p_cont_id] = (pc.abstract_uuid,
                                               pc.abstract_version)
                replies.append(
                    ResultItem(result=BindAckResult.ACCEPTANCE.value,
                               uuid=TRANSFER_SYNTAX,
                               vers=ts_version))
            else:
                replies.append(
                    ResultItem(result=BindAckResult.PROVIDER_REJECTION.value,
                               reason=BindAckReason.
                               PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED.value))
        if sec_header.assoc_group_id > 0:
            self.assoc_group_id = sec_header.assoc_group_id
        else:
            self.assoc_group_id = random.randint(1, MAX_ASSOC_GROUP_ID)
        self.rpc_vers_minor = header.rpc_vers_minor
        ack = BindAck(n_results=len(replies),
                      max_xmit_frag=sec_header.max_xmit_frag,
                      max_recv_frag=sec_header.max_recv_frag,
                      assoc_group_id=self.assoc_group_id)
        r = b"".join(base.pack(i) for i in replies)
        self.send('bind_ack', base.pack(ack), r, callid=header.callid)

    def dcerpc_request(self, header, sec_header, payload):
        p_cont_id = sec_header.p_cont_id
        callid = header.callid
        log.debug("DCE/RPC request {pipe}/{opnum}",
                  pipe=self.pipe,
                  opnum=sec_header.opnum)
        try:
            func = RPC_FUNCTIONS[self.pipe][sec_header.opnum]
        except KeyError:
            log.error("function not found")
            self.send_fault(FaultStatus.unsupported_operation.value,
                            p_cont_id,
                            callid,
                            no_exec=True)
            return

        resetReferents()
        d = maybeDeferred(func, self.sys_data, self.avatar, payload)

        def cb_request(reply):
            if callid in self.cancellations:
                self.cancellations.discard(callid)
                return
            resp = Response(p_cont_id=p_cont_id, alloc_hint=len(reply))
            self.send('response', base.pack(resp), reply, callid=callid)

        def eb_request(failure):
            log.failure("failure on {pipe}/{opnum}",
                        failure,
                        pipe=self.pipe,
                        opnum=sec_header.opnum)
            if failure.check(ZeroDivisionError):
                if 'float' in failure.value.args[0]:
                    status = FaultStatus.fp_div_zero
                else:
                    status = FaultStatus.int_div_by_zero
            elif failure.check(MemoryError):
                status = FaultStatus.remote_no_memory
            elif failure.check(NotImplementedError):
                status = FaultStatus.unsupported_operation
            elif failure.check(OverflowError):
                status = FaultStatus.fp_overflow
            elif failure.check(struct.error):
                status = FaultStatus.int_overflow
            elif failure.check(UnicodeError):
                status = FaultStatus.codeset_conv_error
            elif failure.check(TooBusy):
                status = FaultStatus.server_busy
            else:
                status = FaultStatus.user_defined
            self.send_fault(status.value, p_cont_id, callid)

        d.addCallback(cb_request)
        d.addErrback(eb_request)

    def send_fault(self, status, p_cont_id, callid, no_exec=False):
        resp = Fault(p_cont_id=p_cont_id, alloc_hint=0, status=status)
        self.send('fault',
                  base.pack(resp),
                  b'',
                  callid=callid,
                  fault_noexec=no_exec)

    def send(self,
             ptype_name,
             sec_header,
             payload,
             callid,
             fault_noexec=False):
        flags = PFC_FIRST_FRAG | PFC_LAST_FRAG
        if fault_noexec:
            flags |= PFC_DID_NOT_EXECUTE
        header = DceHeader(
            callid=callid,
            drep=bytes([DREP_INT_LITTLEENDIAN, FloatFormat.IEEE.value, 0, 0]),
            frag_length=len(payload) + len(sec_header) +
            base.calcsize(DceHeader),
            ptype=PTYPES.index(ptype_name),
            rpc_vers_minor=self.rpc_vers_minor,
            pfc_flags=flags)
        self.reply.write(base.pack(header))
        if sec_header:
            self.reply.write(sec_header)
            if payload:
                self.reply.write(payload)

    def dcerpc_cancel(self, header, sec_header, payload):
        self.cancellations.add(header.callid)

    def dataAvailable(self, length=-1):
        r = self.reply.getvalue()
        if r:
            if length > -1 and len(r) > length:
                self.reply = io.BytesIO(r[length:])
                r = r[:length]
            else:
                self.reply = io.BytesIO()
        return r



# *************************************************************************
# *                 WINDOWS DCE/RPC FUNCTIONS                             *
# *************************************************************************



@attr.s
class WkstaInfoInput:
    ref1 = referent()
    server = wchar()
    level = medium()



@attr.s
class WkstaInfo100:
    info = medium(default=100)
    ref1 = referent()
    platform_id = medium(
        default=500)  # 500= Windows any other value will upset clients
    ref2 = referent()
    ref3 = referent()
    vers_major = medium(default=SERVER_VERSION)
    vers_minor = medium(default=SERVER_VERSION_MINOR)
    computername = wchar()
    langroup = wchar()
    werror = medium(0)



@register('wkssvc', 0)
def NetWkstaGetInfo(sys_data, avatar, payload):
    p, _ = unpack(WkstaInfoInput, payload)
    if p.level == 100:
        r = WkstaInfo100(computername=sys_data.domain, langroup=sys_data.fqdn)
        return pack(r)
    else:
        raise NotImplementedError()



@attr.s
class NetSvrInfoInput:
    ref1 = referent()
    server = wchar()
    level = medium()



NETSRV_COMMENT = "Twisted SMB2 server"



@attr.s
class NetSvrInfo101:
    info = medium(101)
    ref1 = referent()
    platform_id = medium(
        default=500)  # 500= Windows any other value will upset clients
    ref2 = referent()
    vers_major = medium(default=SERVER_VERSION)
    vers_minor = medium(default=SERVER_VERSION_MINOR)
    server_type = medium()
    ref3 = referent()
    name = wchar()
    comment = wchar(NETSRV_COMMENT)
    werror = medium(0)



@attr.s
class NetSvrInfo100:
    info = medium(100)
    ref1 = referent()
    platform_id = medium(
        default=500)  # 500= Windows any other value will upset clients
    ref2 = referent()
    name = wchar()
    werror = medium(0)



TYPE_WORKSTATION = 0x0001
TYPE_SERVER = 0x0002
TYPE_APPLE = 0x0080
TYPE_XENIX = 0x0800
TYPE_NT = 0x1000
TYPE_SERVER_NT = 0x8000
TYPE_PRINT = 0x0200



@register('srvsvc', 21)
def NetSvrGetInfo(sys_data, avatar, payload):
    p, _ = unpack(NetSvrInfoInput, payload)
    if p.level == 100:
        r = NetSvrInfo100(name=sys_data.domain)
    elif p.level == 101:
        st = TYPE_SERVER | TYPE_WORKSTATION | TYPE_SERVER_NT
        if sys_data.fake:
            st |= TYPE_NT
        else:
            if platform.system() == "Darwin":
                st |= TYPE_APPLE
            elif platform.system() == "Windows":
                st |= TYPE_NT
            else:
                st |= TYPE_XENIX
        r = NetSvrInfo101(name=sys_data.domain, server_type=st)
    else:
        raise NotImplementedError()
    return pack(r)



@attr.s
class NetShareEnumInput:
    ref1 = referent()
    server = wchar()
    level = medium()
    # rest of this structure very poorly documented
    # only required if we want multiple calls of very long
    # lists of shares. For now just truncate the list until
    # we understand this a bit more



MAX_SHARES = 20



@attr.s
class NetShareEnumResp:
    level = medium()
    counter = medium(1)  # undocumented, role unclear
    ref1 = referent()
    count1 = medium()
    ref2 = referent()
    count2 = medium()



@attr.s
class NetShareEnumArray:
    ref1 = referent()
    share_type = medium()
    ref2 = referent()



SHARE_DISC = 0
SHARE_PRINTER = 1
SHARE_IPC = 3
SHARE_SPECIAL_MASK = 0x80000000

SHARES_T = {
    id(ismb.IFilesystem): SHARE_DISC,
    id(ismb.IPrinter): SHARE_PRINTER,
    id(ismb.IIPC): SHARE_IPC
}



@attr.s
class NetShareEnumStrings:
    name = wchar()
    remark = wchar()



@attr.s
class NetShareEnumEnd:
    total_entries = medium()
    resume_handle = medium(0)
    werror = medium(0)



@register('srvsvc', 15)
def NetShareEnumAll(sys_data, avatar, payload):
    i, offset = unpack(NetShareEnumInput, payload)
    if i.level == 1:
        d = maybeDeferred(avatar.listShares)

        def cb_ShareEnum(shares):
            shares = shares[:MAX_SHARES]
            shares = [(n, SHARES_T[id(t)], r) for n, t, r in shares]
            shares.append(
                ("IPC$", SHARE_IPC | SHARE_SPECIAL_MASK, "Internal IPC"))
            nser = NetShareEnumResp(count1=len(shares),
                                    count2=len(shares),
                                    level=1)
            resp = base.pack(nser)
            for _, t, _ in shares:
                resp += base.pack(NetShareEnumArray(share_type=t))
            for n, _, r in shares:
                resp += pack(NetShareEnumStrings(name=n, remark=r))
            resp += base.pack(NetShareEnumEnd(total_entries=len(shares)))
            return resp

        d.addCallback(cb_ShareEnum)
        return d
    else:
        raise NotImplementedError()



@attr.s
class NetShareGetInfoInput:
    ref1 = referent()
    server = wchar()
    share = wchar()
    level = medium()



@attr.s
class NetShareInfo1:
    info = medium(1)
    ref1 = referent()
    ref2 = referent()
    share_type = medium()
    ref3 = referent()
    name = wchar()
    remark = wchar()
    werror = medium(0)



@register('srvsvc', 16)
def NetShareGetInfo(sys_data, avatar, payload):
    i, _ = unpack(NetShareGetInfoInput, payload)
    if i.level == 1:
        d = maybeDeferred(avatar.listShares)

        def cb_ShareGetInfo(shares):
            shares.append(
                ("IPC$", SHARE_IPC | SHARE_SPECIAL_MASK, "Internal IPC"))
            shares = [(n, SHARES_T[id(t)], r) for n, t, r in shares
                      if n == i.name]
            n, t, r = shares[0]
            resp = NetShareInfo1(name=n, share_type=t, remark=r)
            return pack(resp)

        d.addCallback(cb_ShareGetInfo)
        return d
    else:
        raise NotImplementedError()
