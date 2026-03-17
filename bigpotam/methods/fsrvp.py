"""MS-FSRVP trigger functions."""

import logging

from bigpotam.paths import fsrvp_path
from bigpotam.structures import IsPathShadowCopied, IsPathSupported

log = logging.getLogger("bigpotam")

SUCCESS_CODES = ("rpc_s_access_denied", "ERROR_BAD_NETPATH")


def _check_success(e):
    err = str(e)
    return any(code in err for code in SUCCESS_CODES)


def trigger_is_path_supported(dce, listener, listener_port=445, **kw):
    try:
        request = IsPathSupported()
        request["ShareName"] = fsrvp_path(listener, listener_port)
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("IsPathSupported: %s", e)
        return False


def trigger_is_path_shadow_copied(dce, listener, listener_port=445, **kw):
    try:
        request = IsPathShadowCopied()
        request["ShareName"] = fsrvp_path(listener, listener_port)
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("IsPathShadowCopied: %s", e)
        return False
