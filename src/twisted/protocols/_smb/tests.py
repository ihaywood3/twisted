#!/usr/bin/python3

import sys
import struct
import calendar
import io
import socket
import re
import attr
import uuid
import os
import unittest as python_unittest

from twisted.protocols._smb import (
    base,
    core,
    security_blob,
    ntlm,
    dcerpc,
    smbtypes,
    vfs,
)
from twisted.protocols._smb.ismb import ISMBServer, NoSuchShare

from twisted.cred import portal, checkers, credentials
from twisted.trial import unittest
from twisted.internet import reactor
from twisted.logger import globalLogBeginner, textFileLogObserver, Logger
from twisted.internet.protocol import ProcessProtocol
from twisted.internet.defer import Deferred
from twisted.python.failure import Failure
from zope.interface import implementer

log = Logger()
observers = [textFileLogObserver(sys.stdout)]
globalLogBeginner.beginLoggingTo(observers)


@attr.s
class FakeStruct:
    one = base.short()
    two = base.byte()
    three = base.single(4.2)
    four = base.octets(3)
    five = base.long(424242, locked=True)


@attr.s
class FakeStruct2:
    i = base.short()
    b = base.byte()
    s = base.octets(3)


@attr.s
class FakeStruct3:
    six_len = base.short()
    six = base.endstring()


class TestBase(unittest.TestCase):
    def test_base_pack(self):
        data = struct.pack("<HBf3sQ", 525, 42, 4.2, b"bob", 424242)
        r = FakeStruct(one=525)
        r.two = 42
        r.four = b"bob"
        self.assertEqual(base.pack(r), data)
        with self.assertRaises(AssertionError):
            r = FakeStruct(five=424243)

    def test_base_endstring(self):
        s1 = "burble"
        b1 = s1.encode("utf-16le")
        data = struct.pack("<H", len(b1)) + b1
        r = FakeStruct3(six=s1)
        self.assertEquals(base.pack(r), data)

    def test_base_calcsize(self):
        self.assertEqual(base.calcsize(FakeStruct), 18)
        self.assertEqual(base.calcsize(FakeStruct2), 6)

    def test_smb_packet_receiver(self):
        def recv(x):
            global rdata
            rdata = x

        pr = base.SMBPacketReceiver(recv, {})
        pr.transport = io.BytesIO()

        # send fake packet
        pr.sendPacket(b"bur ble")
        r = pr.transport.getvalue()
        self.assertEqual(r, b"\0\0\0\x07bur ble")
        # receive fake packet
        pr.dataReceived(b"\0\0\0\x03abc")
        self.assertEqual(rdata.data, b"abc")

    def test_int32key(self):
        d = {}
        n = base.int32key(d, "123")
        self.assertEqual(d, {n: "123"})
        self.assertIs(type(n), int)
        self.assertTrue(n > 0)
        self.assertTrue(n < 2 ** 32)

    def test_unpack(self):
        data = b"\x0B\x02\x0Etwisted"
        with self.subTest(remainder=base.IGNORE):
            r = base.unpack(FakeStruct2, data, remainder=base.IGNORE)
            self.assertEqual(r.i, 523)
            self.assertEqual(r.b, 0x0E)
            self.assertEqual(r.s, b"twi")
        with self.subTest(remainder=base.ERROR):
            with self.assertRaises(base.SMBError):
                r = base.unpack(FakeStruct2, data, remainder=base.ERROR)
        with self.subTest(remainder=base.OFFSET):
            r, rem = base.unpack(FakeStruct2, data, remainder=base.OFFSET)
            self.assertEqual(r.i, 523)
            self.assertEqual(r.b, 0x0E)
            self.assertEqual(r.s, b"twi")
            self.assertEqual(rem, 6)
        with self.subTest(remainder=base.DATA):
            r, rem = base.unpack(FakeStruct2, data, remainder=base.DATA)
            self.assertEqual(r.i, 523)
            self.assertEqual(r.b, 0x0E)
            self.assertEqual(r.s, b"twi")
            self.assertEqual(rem, b"sted")

    def test_unixToNTTime(self):
        s = b"\x46\x63\xdc\x91\xd2\x29\xd6\x01"
        (nttime,) = struct.unpack("<Q", s)
        # 2020/5/14 09:32:22.101895
        epoch = calendar.timegm((2020, 5, 14, 9, 32, 22.101895, 0, -1, 0))
        self.assertEqual(base.unixToNTTime(epoch), nttime)

        s = b"\x24\xba\x1c\x33\x9f\x14\xd6\x01"
        (nttime,) = struct.unpack("<Q", s)
        # 2020/4/17 10:01:44.388458
        epoch = calendar.timegm((2020, 4, 17, 10, 1, 44.388458, 0, -1, 0))
        self.assertEqual(base.unixToNTTime(epoch), nttime)


# captured auth packets from Windows 10 <-> Samba session
NEG_PACKET = (
    b"`H\x06\x06+\x06\x01\x05\x05\x02\xa0>0<\xa0\x0e0\x0c"
    + b"\x06\n+\x06\x01\x04\x01\x827\x02\x02\n\xa2*\x04(NTLMSSP\x00\x01"
    + b"\x00\x00\x00\x97\x82\x08\xe2\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    + b"\x00\x00\x00\x00\x00\x00\x00\n\x00\xbaG\x00\x00\x00\x0f"
)

AUTH_PACKET = (
    b"\xa1\x82\x01\xd30\x82\x01\xcf\xa0\x03\n\x01\x01\xa2\x82"
    b"\x01\xb2\x04\x82\x01\xaeNTLMSSP\x00\x03\x00"
    b"\x00\x00\x18\x00\x18\x00\x9e"
    b"\x00\x00\x00\xe8\x00\xe8\x00\xb6\x00"
    b"\x00\x00 \x00 \x00X\x00\x00\x00\x08"
    b"\x00\x08\x00x\x00\x00\x00\x1e\x00\x1e\x00\x80\x00\x00\x00\x10\x00\x10"
    b"\x00\x9e\x01\x00\x00\x15\x82\x88"
    b"\xe2\n\x00\xbaG\x00\x00\x00\x0f\xbe\xde"
    b'\xe7\xedl\x97\xbe\x84\xdb\x06\x87\x8cT.#"M\x00i\x00c\x00r\x00o\x00s\x00'
    b"o\x00f\x00t\x00A\x00c\x00c\x00o\x00u\x00n\x00t\x00u\x00s\x00e\x00r\x00D"
    b"\x00E\x00S\x00K\x00T\x00O\x00P\x00-\x00E\x009\x006\x00H\x00U\x009\x000"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\xfb@EX\xef#t\xfa\xcf@\x12\xe8p\x95Uo"
    b"\x01\x01\x00\x00\x00\x00\x00\x00\xe6\xfdG\xa0\xd2)\xd6\x01/(\xe8\x98."
    b"\xc0\x17\xec\x00\x00\x00\x00\x02\x00\x0e\x00M\x00I\x00N\x00T\x00B\x00O"
    b"\x00X\x00\x01\x00\x0e\x00M\x00I\x00N\x00T\x00B\x00O\x00X\x00\x04\x00"
    b"\x02\x00\x00\x00\x03\x00\x0e\x00m\x00i"
    b"\x00n\x00t\x00b\x00o\x00x\x00\x07"
    b"\x00\x08\x00\xe6\xfdG\xa0\xd2)\xd6\x01\x06\x00\x04\x00\x02\x00\x00\x00"
    b"\x08\x000\x000\x00\x00\x00\x00\x00\x00"
    b"\x00\x01\x00\x00\x00\x00 \x00\x004"
    b"\x89\xe2\xfa]\xaa\xceM\xe7\xda~\xbf\x1eO\x8c/\x14n\xa2SF\x99j\x11_\x1c"
    b"\xfd%m\x7f\x1d(\n\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\t\x00\x18\x00c\x00i\x00f\x00s\x00/\x00m\x00i"
    b"\x00n\x00t\x00b\x00o\x00x\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb9\xc7"
    b"\xa5?\xcc\x1c%\xb3\x867\x1eY?$\x99\x98\xa3\x12\x04\x10\x01\x00\x00\x00"
    b"\x95_\x1e4\x12?\x07x\x00\x00\x00\x00"
)

CHALLENGE = b"&z\xd3>Cu\xdd+"
SYS_DATA = smbtypes.SystemData(base.NULL_UUID, 0, "DOMAIN", "localhost", False)


class TestSecurity(unittest.TestCase):
    def test_negotiate(self):
        blob_manager = security_blob.BlobManager(SYS_DATA)
        blob_manager.receiveInitialBlob(NEG_PACKET)
        flags = {
            "Negotiate128",
            "TargetTypeServer",
            "RequestTarget",
            "NegotiateVersion",
            "NegotiateUnicode",
            "NegotiateAlwaysSign",
            "NegotiateSign",
            "Negotiate56",
            "NegotiateKeyExchange",
            "NegotiateExtendedSecurity",
            "NegotiateNTLM",
            "NegotiateTargetInfo",
        }
        self.assertEqual(blob_manager.manager.flags, flags)
        self.assertIsNone(blob_manager.manager.client_domain)
        self.assertIsNone(blob_manager.manager.workstation)

    def test_auth(self):
        blob_manager = security_blob.BlobManager(SYS_DATA)
        blob_manager.receiveInitialBlob(NEG_PACKET)
        blob_manager.generateChallengeBlob()
        blob_manager.manager.challenge = CHALLENGE
        blob_manager.receiveResp(AUTH_PACKET)
        self.assertEqual(blob_manager.credential.domain, "MicrosoftAccount")
        self.assertEqual(blob_manager.credential.username, "user")
        self.assertTrue(blob_manager.credential.checkPassword("password"))
        self.assertFalse(blob_manager.credential.checkPassword("wrong"))

    def test_invalid(self):
        manager = ntlm.NTLMManager(SYS_DATA)
        with self.assertRaises(base.SMBError):
            manager.receiveToken(b"I'm too short")
        with self.assertRaises(AssertionError):
            manager.receiveToken(b"I'm long enough but have an invalid header")
        with self.assertRaises(base.SMBError):
            manager.receiveToken(
                b"NTLMSSP\x00\xFF\0\0\0invalid message"
                + b"type                             "
            )


DCERPC_BIND = (
    b"\x05\x00\x0b\x03\x10\x00\x00\x00\xa0\x00\x00\x00\x02\x00"
    b"\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x01"
    b"\x00\x98\xd0\xffk\x12\xa1\x106\x983F\xc3\xf8~4Z\x01\x00\x00\x00\x04]"
    b"\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00+\x10H`\x02\x00\x00\x00\x01"
    b"\x00\x01\x00\x98\xd0\xffk\x12\xa1\x106\x983F\xc3\xf8~4Z\x01\x00\x00"
    b"\x003\x05qq\xba\xbe7I\x83\x19\xb5\xdb\xef\x9c\xcc6\x01\x00\x00\x00"
    b"\x02\x00\x01\x00\x98\xd0\xffk\x12\xa1\x106\x983F\xc3\xf8~4Z\x01\x00"
    b"\x00\x00,\x1c\xb7l\x12\x98@E\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00"
    b"\x00\x00"
)

DCERPC_REQUEST = (
    b"\x05\x00\x00\x03\x10\x00\x00\x00P\x00\x00\x00\x02\x00"
    b"\x00\x008\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x11\x00\x00\x00"
    b"\x00\x00\x00\x00\x11\x00\x00\x00\\\x00\\\x001\x009\x002\x00.\x001\x00"
    b"6\x008\x00.\x001\x007\x008\x00.\x003\x009\x00\x00\x00\x00\x00d\x00"
    b"\x00\x00"
)


class TestDcerpc(unittest.TestCase):
    def test_bind(self):
        pipe = dcerpc.DceRpcProcessor(None, None, "test")
        pipe.dataReceived(DCERPC_BIND)
        abstract_uuid, abstract_version = list(pipe.contexts.values())[0]
        self.assertEqual(
            abstract_uuid, uuid.UUID("{6BFFD098-A112-3610-9833-46C3F87E345A}")
        )
        self.assertEqual(abstract_version, 1)

    def test_request(self):
        pipe = dcerpc.DceRpcProcessor("fake sys_data", "fake avatar", "test")

        def cb_test(sys_data, avatar, payload):
            p, _ = dcerpc.unpack(dcerpc.WkstaInfoInput, payload)
            self.assertEqual(sys_data, "fake sys_data")
            self.assertEqual(avatar, "fake avatar")
            self.assertEqual(p.level, 100)
            self.assertEqual(p.server, "\\\\192.168.178.39")
            return b"some data"

        func = dcerpc.register("test", 0)
        func(cb_test)
        pipe.dataReceived(DCERPC_REQUEST)


@implementer(ISMBServer)
class TestAvatar:
    def __init__(self, tvfs):
        self.tvfs = tvfs

    def getShare(self, name):
        if name == "share":
            return self.tvfs
        else:
            raise NoSuchShare(name)

    def listShares(self):
        return [("share", vfs.IFilesystem, "test disc share")]

    session_id = 0


@implementer(portal.IRealm)
class TestRealm:
    def __init__(self, tvfs):
        self.tvfs = tvfs

    def requestAvatar(self, avatarId, mind, *interfaces):
        log.debug("avatarId={a!r} mind={m!r}", a=avatarId, m=mind)
        return (ISMBServer, TestAvatar(self.tvfs), lambda: None)


class ChatNotFinished(Exception):
    pass


class ChatProcess(ProcessProtocol):
    def __init__(self, chat, ignoreRCode):
        self.chat = chat
        self.d = Deferred()
        self.matches = []
        self.ignoreRCode = ignoreRCode

    def outReceived(self, data):
        data = data.decode("utf-8")
        print(data)
        if self.chat:
            prompt, reply = self.chat[0]
            if prompt.startswith("/"):
                use_re = True
                m = re.search(prompt[1:], data)
            else:
                use_re = False
                m = prompt in data
            if m:
                if use_re:
                    self.matches.append(m)
                else:
                    self.matches.append(data)
                if reply:
                    if use_re:
                        for i in range(1, 10):
                            t = "\\%d" % i
                            if t in reply:
                                reply = reply.replace(t, m.group(i))
                    self.transport.write(reply.encode("utf-8"))
                else:
                    self.transport.closeStdin()
                del self.chat[0]

    def errReceived(self, data):
        print(data.decode("utf-8"))

    def processEnded(self, status):
        if (not self.ignoreRCode) and status.value.exitCode != 0:
            self.d.errback(status)
        elif self.chat:
            try:
                raise ChatNotFinished()
            except BaseException:
                self.d.errback(Failure())
        else:
            self.d.callback(self.matches)


def spawn(chat, args, ignoreRCode=False, usePTY=True):
    pro = ChatProcess(chat, ignoreRCode)
    reactor.spawnProcess(pro, args[0], args, usePTY=usePTY)
    return pro.d


TESTPORT = 5445
TESTUSER = "user"
TESTPASSWORD = "password"
SMBCLIENT = "/usr/bin/smbclient"
PROMPT = "smb: \\>"


@python_unittest.skipUnless(os.access(SMBCLIENT, os.X_OK), "smbclient unavailable")
class TestSambaClient(unittest.TestCase):
    def setUp(self):
        # set up some directories
        self.oldpath = os.getcwd()
        self.tpath1 = tempfile.mkdtemp()
        os.chdir(self.tpath1)
        with open("one.txt", "w") as fd:
            fd.write("blah" * 3)
        with open("two.txt", "w") as fd:
            fd.write("blah")
        self.tpath2 = tempfile.mkdtemp()
        with open(os.path.join(self.tpath2, "three.txt"), "w") as fd:
            fd.write("blaz" * 3)
        with open(os.path.join(self.tpath2, "four.txt"), "w") as fd:
            fd.write("blaz")
        self.tvfs = vfs.ThreadVfs(self.tpath2)
        # Start the server
        r = TestRealm(self.tvfs)
        p = portal.Portal(r)
        users_checker = checkers.InMemoryUsernamePasswordDatabaseDontUse()
        users_checker.addUser(TESTUSER, TESTPASSWORD)
        p.registerChecker(users_checker, credentials.IUsernameHashedPassword)
        self.factory = core.SMBFactory(p)
        self.port = port = reactor.listenTCP(TESTPORT, self.factory)
        self.addCleanup(port.stopListening)

    def tearDown(self):
        for i in os.listdir():
            os.unlink(i)
        os.chdir(self.tpath2)
        os.rmdir(self.tpath1)
        for i in os.listdir():
            os.unlink(i)
        os.chdir(self.oldpath)
        os.rmdir(self.tpath2)
        self.tvfs.unregister()

    def smbclient(self, chat, ignoreRCode=False):
        return spawn(
            chat,
            [
                SMBCLIENT,
                "\\\\%s\\share" % socket.gethostname(),
                TESTPASSWORD,
                "-m",
                "SMB2",
                "-U",
                TESTUSER,
                "-I",
                "127.0.0.1",
                "-p",
                str(TESTPORT),
                "-d",
                "10",
            ],
            ignoreRCode=ignoreRCode,
            usePTY=True,
        )

    def smbclient_list(self, chat, ignoreRCode=False):
        return spawn(
            chat,
            [
                SMBCLIENT,
                "-L",
                "\\\\%s" % socket.gethostname(),
                "-m",
                "SMB2",
                "-U",
                TESTUSER + "%" + TESTPASSWORD,
                "-I",
                "127.0.0.1",
                "-p",
                str(TESTPORT),
            ],
            ignoreRCode=ignoreRCode,
        )

    def test_logon(self):
        return self.smbclient([(PROMPT, "quit\n")])

    def test_listshares(self):
        return self.smbclient_list([("test disc share", None)])

    def test_get(self):
        def cb_get(_):
            with open("three.txt", "r") as fd:
                self.assertEqual(fd.read(), "blaz" * 3)

        d = self.smbclient([(PROMPT, "get third.txt\n"), (PROMPT, "quit\n")])
        d.addCallback(cb_get)
        return d


if __name__ == "__main__":
    r = TestRealm()
    p = portal.Portal(r)
    users_checker = checkers.InMemoryUsernamePasswordDatabaseDontUse()
    users_checker.addUser(TESTUSER, TESTPASSWORD)
    p.registerChecker(users_checker, credentials.IUsernameHashedPassword)
    factory = core.SMBFactory(p)
    port = reactor.listenTCP(445, factory)
    reactor.run()
