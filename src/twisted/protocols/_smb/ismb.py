# -*- test-case-name: twisted.protocols._smb.tests -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
"""
Various interfaces for realms, avatars and related objects
"""

from zope.interface import Interface, Attribute

from collections import namedtuple

StatData = namedtuple(
    'StatData', 'size ctime mtime atime read_only system hidden archive dir')



class NoSuchShare(Exception):
    pass



class ISMBServer(Interface):
    """
    A SMB server avatar, contains a number of "shares" (filesystems/printers/
    IPC pipes)
    """

    session_id = Attribute("the assigned int64 session ID")

    def getShare(name):
        """
        get a share object by name

        @param name: the share
        @type name: L{str}

        @rtype: instance implementing one of L{IFilesystem}, L{IPrinter}, or
                L{IPipe}
        """

    def listShares():
        """
        list shares available on the server.
        Note servers are free to have different lists for different users
        and have "silent" shares that don't appear in list

        @rtype: L{list} of L{str}
        """



class IFilesystem(Interface):
    """
    A share representing a filesystem ("disk" in the SMB spec)
    """



class IPrinter(Interface):
    """
    A share representing a printer
    """



class IIPC(Interface):
    """
    A share representing a interprocess communication (IPC) service
    """
    def open(name):
        """
        open a named pipe

        @param name: name of the pipe
        @type name: L{str}

        @rtype: L{IPipe}
        """



class IPipe(Interface):
    """
    a single named pipe
    """
    def dataReceived(data):
        """
        data received (written to) the pipe

        @param data: the data written
        @type data: L{bytes}
        """

    def dataAvailable(length):
        """
        returns data immediately available for reading, if no data returns
        b''

        B{does not block and not allowed to return a L{defer.Deferred}}

        @param length: maximum length of returned data
        @type length: L{int}

        @rtype: L{bytes}
        """

    def fileClosed():
        """
        remote end has closed the pipe

        @rtype: None
        """

    closed = Attribute("flag, True if pipe closed locally")

    def fileFlushed():
        """
       remote end wants to flush

       @rtype: None
       """

    def stat():
        """
       return stat data for the pipe

       @rtype: L{StatData}
       """
