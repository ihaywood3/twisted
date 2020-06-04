#!/usr/bin/python3

import sys
import struct
import calendar
import io
import socket
import re

from twisted.protocols._smb import base, core, security_blob, ntlm
from twisted.protocols._smb.interfaces import (ISMBServer, IFilesystem)

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



class TestBase(unittest.TestCase):
    def test_base_pack(self):
        data = struct.pack("<HBH", 525, 24, 17) + b'bob'
        t = base.nstruct("one:H two:B three:H")
        r = t()
        r.one = 525
        r.two = 24
        r.three = 17
        r.buffer = b'bob'
        self.assertEqual(r.pack(), data)

    def test_smb_packet_receiver(self):
        pr = base.SMBPacketReceiver()
        pr.transport = io.BytesIO()

        def recv(x):
            global rdata
            rdata = x

        pr.packetReceived = recv
        # send fake packet
        pr.sendPacket(b'bur ble')
        r = pr.transport.getvalue()
        self.assertEqual(r, b'\0\0\0\x07bur ble')
        # receive fake packet
        pr.dataReceived(b'\0\0\0\x03abc')
        self.assertEqual(rdata, b'abc')

    def test_int32key(self):
        d = {}
        n = base.int32key(d, "123")
        self.assertEqual(d, {n: "123"})
        self.assertIs(type(n), int)
        self.assertTrue(n > 0)
        self.assertTrue(n < 2**32)

    def test_unpack(self):
        t = base.nstruct("i:H b:B s:3s")
        r = t(b'\x0B\x02\x0Etwisted')
        self.assertEqual(r.i, 523)
        self.assertEqual(r.b, 0x0E)
        self.assertEqual(r.s, b'twi')
        self.assertEqual(r.buffer, b'sted')

    def test_u2nt_time(self):
        s = b'\x46\x63\xdc\x91\xd2\x29\xd6\x01'
        nttime, = struct.unpack("<Q", s)
        # 2020/5/14 09:32:22.101895
        epoch = calendar.timegm((2020, 5, 14, 9, 32, 22.101895, 0, -1, 0))
        self.assertEqual(base.u2nt_time(epoch), nttime)

        s = b'\x24\xba\x1c\x33\x9f\x14\xd6\x01'
        nttime, = struct.unpack("<Q", s)
        # 2020/4/17 10:01:44.388458
        epoch = calendar.timegm((2020, 4, 17, 10, 1, 44.388458, 0, -1, 0))
        self.assertEqual(base.u2nt_time(epoch), nttime)



# captured auth packets from Windows 10 <-> Samba session
NEG_PACKET = b'`H\x06\x06+\x06\x01\x05\x05\x02\xa0>0<\xa0\x0e0\x0c' + \
    b'\x06\n+\x06\x01\x04\x01\x827\x02\x02\n\xa2*\x04(NTLMSSP\x00\x01' + \
    b'\x00\x00\x00\x97\x82\x08\xe2\x00\x00\x00\x00\x00\x00\x00\x00\x00' + \
    b'\x00\x00\x00\x00\x00\x00\x00\n\x00\xbaG\x00\x00\x00\x0f'

AUTH_PACKET = b'\xa1\x82\x01\xd30\x82\x01\xcf\xa0\x03\n\x01\x01\xa2\x82' \
    b'\x01\xb2\x04\x82\x01\xaeNTLMSSP\x00\x03\x00' \
    b'\x00\x00\x18\x00\x18\x00\x9e' \
    b'\x00\x00\x00\xe8\x00\xe8\x00\xb6\x00' \
    b'\x00\x00 \x00 \x00X\x00\x00\x00\x08' \
    b'\x00\x08\x00x\x00\x00\x00\x1e\x00\x1e\x00\x80\x00\x00\x00\x10\x00\x10' \
    b'\x00\x9e\x01\x00\x00\x15\x82\x88' \
    b'\xe2\n\x00\xbaG\x00\x00\x00\x0f\xbe\xde' \
    b'\xe7\xedl\x97\xbe\x84\xdb\x06\x87\x8cT.#"M\x00i\x00c\x00r\x00o\x00s\x00'\
    b'o\x00f\x00t\x00A\x00c\x00c\x00o\x00u\x00n\x00t\x00u\x00s\x00e\x00r\x00D'\
    b'\x00E\x00S\x00K\x00T\x00O\x00P\x00-\x00E\x009\x006\x00H\x00U\x009\x000' \
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
    b'\x00\x00\x00\x00\x00\x00\x00\x00\xfb@EX\xef#t\xfa\xcf@\x12\xe8p\x95Uo' \
    b'\x01\x01\x00\x00\x00\x00\x00\x00\xe6\xfdG\xa0\xd2)\xd6\x01/(\xe8\x98.' \
    b'\xc0\x17\xec\x00\x00\x00\x00\x02\x00\x0e\x00M\x00I\x00N\x00T\x00B\x00O' \
    b'\x00X\x00\x01\x00\x0e\x00M\x00I\x00N\x00T\x00B\x00O\x00X\x00\x04\x00' \
    b'\x02\x00\x00\x00\x03\x00\x0e\x00m\x00i' \
    b'\x00n\x00t\x00b\x00o\x00x\x00\x07' \
    b'\x00\x08\x00\xe6\xfdG\xa0\xd2)\xd6\x01\x06\x00\x04\x00\x02\x00\x00\x00' \
    b'\x08\x000\x000\x00\x00\x00\x00\x00\x00' \
    b'\x00\x01\x00\x00\x00\x00 \x00\x004' \
    b'\x89\xe2\xfa]\xaa\xceM\xe7\xda~\xbf\x1eO\x8c/\x14n\xa2SF\x99j\x11_\x1c' \
    b'\xfd%m\x7f\x1d(\n\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
    b'\x00\x00\x00\x00\x00\x00\t\x00\x18\x00c\x00i\x00f\x00s\x00/\x00m\x00i' \
    b'\x00n\x00t\x00b\x00o\x00x\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb9\xc7' \
    b'\xa5?\xcc\x1c%\xb3\x867\x1eY?$\x99\x98\xa3\x12\x04\x10\x01\x00\x00\x00' \
    b'\x95_\x1e4\x12?\x07x\x00\x00\x00\x00'

CHALLENGE = b'&z\xd3>Cu\xdd+'



class TestSecurity(unittest.TestCase):
    def test_negotiate(self):
        blob_manager = security_blob.BlobManager("DOMAIN")
        blob_manager.receiveInitialBlob(NEG_PACKET)
        flags = {
            'Negotiate128', 'TargetTypeServer', 'RequestTarget',
            'NegotiateVersion', 'NegotiateUnicode', 'NegotiateAlwaysSign',
            'NegotiateSign', 'Negotiate56', 'NegotiateKeyExchange',
            'NegotiateExtendedSecurity', 'NegotiateNTLM', 'NegotiateTargetInfo'
        }
        self.assertEqual(blob_manager.manager.flags, flags)
        self.assertIsNone(blob_manager.manager.client_domain)
        self.assertIsNone(blob_manager.manager.workstation)

    def test_auth(self):
        blob_manager = security_blob.BlobManager("DOMAIN")
        blob_manager.receiveInitialBlob(NEG_PACKET)
        blob_manager.generateChallengeBlob()
        blob_manager.manager.challenge = CHALLENGE
        blob_manager.receiveResp(AUTH_PACKET)
        self.assertEqual(blob_manager.credential.domain, "MicrosoftAccount")
        self.assertEqual(blob_manager.credential.username, "user")
        self.assertTrue(blob_manager.credential.checkPassword("password"))
        self.assertFalse(blob_manager.credential.checkPassword("wrong"))

    def test_invalid(self):
        manager = ntlm.NTLMManager("DOMAIN")
        with self.assertRaises(base.SMBError):
            manager.receiveToken(b"I'm too short")
        with self.assertRaises(base.SMBError):
            manager.receiveToken(b"I'm long enough but have an invalid header")
        with self.assertRaises(base.SMBError):
            manager.receiveToken(b"NTLMSSP\x00\xFF\0\0\0invalid message" +
                                 b"type                             ")



@implementer(IFilesystem)
class TestDisc:
    pass



@implementer(ISMBServer)
class TestAvatar:
    def getShare(self, name):
        if name == "share":
            return TestDisc()
        else:
            raise KeyError(name)

    def listShares(self):
        return ["share"]



@implementer(portal.IRealm)
class TestRealm:
    def requestAvatar(self, avatarId, mind, interfaces):
        log.debug("avatarId={a!r} mind={m!r}", a=avatarId, m=mind)
        return (ISMBServer, TestAvatar(), lambda: None)



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
            m = re.search(prompt, data)
            if m:
                self.matches.append(m)
                if reply:
                    for i in range(1, 10):
                        t = "\\%d" % i
                        if t in reply:
                            reply = reply.replace(t, m.group(i))
                    self.transport.write(reply.encode('utf-8'))
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



class SambaClientTests(unittest.TestCase):
    def setUp(self):
        # Start the server
        r = TestRealm()
        p = portal.Portal(r)
        users_checker = checkers.InMemoryUsernamePasswordDatabaseDontUse()
        self.username = "user"
        self.password = "test-password"
        users_checker.addUser(self.username, self.password)
        p.registerChecker(users_checker, credentials.IUsernameHashedPassword)
        self.factory = core.SMBFactory(p)
        self.port = port = reactor.listenTCP(TESTPORT, self.factory)
        self.addCleanup(port.stopListening)

    def smbclient(self, chat, ignoreRCode=False):
        return spawn(chat, [
            "/usr/bin/smbclient",
            "\\\\%s\\share" % socket.gethostname(), self.password, "-m",
            "SMB2", "-U", self.username, "-I", "127.0.0.1", "-p",
            str(TESTPORT), "-d", "10"
        ],
                     ignoreRCode=ignoreRCode,
                     usePTY=True)

    def test_logon(self):
        return self.smbclient([("session setup ok", None)], ignoreRCode=True)
