"""RPC/DCOM connection helpers and EFS auto-activation."""

import logging

from impacket.dcerpc.v5 import epm, transport
from impacket.dcerpc.v5.rpcrt import (
    RPC_C_AUTHN_GSS_NEGOTIATE,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    RPC_C_AUTHN_WINNT,
)
from impacket.uuid import uuidtup_to_bin

log = logging.getLogger("bigpotam")


def activate_efs(target, timeout=2):
    """Poke EPM on port 135 to trigger on-demand EFS service start.

    The exception is the success condition — this is the rpc2efs trick.
    Silently ignored if port 135 is filtered.
    """
    EFS_UUID = uuidtup_to_bin(("df1941c5-fe89-4e79-bf10-463657acf44d", "0.0"))
    try:
        string_binding = f"ncacn_ip_tcp:{target}[135]"
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_connect_timeout(timeout)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        epm.hept_map(target, EFS_UUID, protocol="ncacn_ip_tcp", dce=dce)
        dce.disconnect()
    except Exception:
        pass


def get_dynamic_endpoint(interface_uuid, target, timeout=5):
    """Query EPM for a dynamic TCP endpoint for the given interface UUID."""
    string_binding = rf"ncacn_ip_tcp:{target}[135]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.set_connect_timeout(timeout)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    result = epm.hept_map(target, interface_uuid, protocol="ncacn_ip_tcp", dce=dce)
    dce.disconnect()
    return result


def connect_rpc(
    target,
    pipe,
    uuid_tuple,
    target_ip=None,
    port=445,
    username="",
    password="",
    domain="",
    lmhash="",
    nthash="",
    do_kerberos=False,
    dc_host=None,
    timeout=5,
    use_epm=False,
):
    """Connect to an RPC endpoint via named pipe or EPM dynamic endpoint.

    Returns a connected and bound DCE/RPC session, or None on failure.
    """
    try:
        uuid_bin = uuidtup_to_bin(uuid_tuple)

        if use_epm:
            string_binding = get_dynamic_endpoint(uuid_bin, target, timeout)
        else:
            string_binding = rf"ncacn_np:{target}[\PIPE\{pipe}]"

        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_connect_timeout(timeout)

        if not use_epm:
            rpctransport.set_dport(port)
            if target_ip:
                rpctransport.setRemoteHost(target_ip)

        if hasattr(rpctransport, "set_credentials"):
            rpctransport.set_credentials(
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash,
            )

        if do_kerberos:
            rpctransport.set_kerberos(True, kdcHost=dc_host)

        dce = rpctransport.get_dce_rpc()

        if do_kerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        else:
            dce.set_auth_type(RPC_C_AUTHN_WINNT)

        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(uuid_bin)

        return dce

    except Exception as e:
        label = "dcerpc" if use_epm else pipe
        log.debug("Connection failed [%s]: %s", label, e)
        return None


def connect_smb(
    target,
    target_ip=None,
    port=445,
    username="",
    password="",
    domain="",
    lmhash="",
    nthash="",
    do_kerberos=False,
    dc_host=None,
    timeout=5,
):
    """Create an SMB connection for WSP (returns smbClient or None)."""
    try:
        from impacket.smbconnection import SMBConnection

        smb = SMBConnection(
            target if not target_ip else target_ip,
            target if not target_ip else target_ip,
            sess_port=port,
        )
        smb.setTimeout(timeout)

        if do_kerberos:
            smb.kerberosLogin(
                username,
                password,
                domain,
                lmhash,
                nthash,
                kdcHost=dc_host,
            )
        else:
            smb.login(username, password, domain, lmhash, nthash)

        return smb

    except Exception as e:
        log.debug("SMB connection failed: %s", e)
        return None
