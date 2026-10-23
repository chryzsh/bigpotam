"""RPC/DCOM connection helpers and EFS auto-activation."""

import logging
import time

from impacket.dcerpc.v5 import epm, transport
from impacket.dcerpc.v5.rpcrt import (
    DCERPCException,
    RPC_C_AUTHN_GSS_NEGOTIATE,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    RPC_C_AUTHN_LEVEL_NONE,
    RPC_C_AUTHN_WINNT,
)
from impacket.uuid import uuidtup_to_bin

log = logging.getLogger("bigpotam")


def _is_tcp_pipe(pipe):
    return pipe in {"tcp_lsarpc", "tcp_efsr"}


def _set_transport_auth(
    rpctransport,
    target_ip=None,
    port=445,
    set_dport=True,
    username="",
    password="",
    domain="",
    lmhash="",
    nthash="",
    do_kerberos=False,
    dc_host=None,
):
    if target_ip:
        rpctransport.setRemoteHost(target_ip)

    if set_dport:
        rpctransport.set_dport(port)

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


def _activate_efs_named_pipe(
    target,
    pipe,
    target_ip=None,
    port=445,
    username="",
    password="",
    domain="",
    lmhash="",
    nthash="",
    do_kerberos=False,
    dc_host=None,
    timeout=2,
):
    efs_uuid = uuidtup_to_bin(("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0"))
    string_binding = rf"ncacn_np:{target}[\PIPE\{pipe}]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.set_connect_timeout(timeout)
    _set_transport_auth(
        rpctransport,
        target_ip=target_ip,
        port=port,
        username=username,
        password=password,
        domain=domain,
        lmhash=lmhash,
        nthash=nthash,
        do_kerberos=do_kerberos,
        dc_host=dc_host,
    )

    dce = rpctransport.get_dce_rpc()
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_NONE)

    try:
        dce.connect()
        dce.bind(efs_uuid)
        dce.disconnect()
        return True
    except DCERPCException as e:
        # A rejected bind means the EFS interface is not listening, so the
        # service is not running yet. Let the caller try the EPM fallback.
        log.debug("EFS activation via %s returned DCERPCException: %s", pipe, e)
        return False
    except Exception as e:
        log.debug("EFS activation via %s failed: %s", pipe, e)
        return False


def activate_efs(
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
    timeout=2,
):
    """Trigger on-demand EFS service start.

    Prefer named-pipe probes over SMB because they are more reliable through
    SOCKS/proxychains setups, then fall back to the original EPM/135 poke.
    """
    for pipe in ("efsrpc", "lsarpc"):
        if _activate_efs_named_pipe(
            target,
            pipe,
            target_ip=target_ip,
            port=port,
            username=username,
            password=password,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            do_kerberos=do_kerberos,
            dc_host=dc_host,
            timeout=timeout,
        ):
            return

    # The EPM lookup of the EFSR interface starts the service. The lookup
    # itself usually fails with ept_s_not_registered because EFS is not up yet.
    EFS_UUID = uuidtup_to_bin(("df1941c5-fe89-4e79-bf10-463657acf44d", "0.0"))
    network_target = target_ip or target
    try:
        string_binding = f"ncacn_ip_tcp:{network_target}[135]"
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_connect_timeout(timeout)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        epm.hept_map(network_target, EFS_UUID, protocol="ncacn_ip_tcp", dce=dce)
        dce.disconnect()
    except Exception as e:
        if "ept_s_not_registered" not in str(e):
            log.debug("EFS activation via EPM failed: %s", e)
            return
        log.debug("EFS activation via EPM sent: %s", e)

    # Give EFS time to start and register on the named pipes.
    time.sleep(2)


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
    tcp_port=None,
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
        is_tcp_pipe = _is_tcp_pipe(pipe)

        if use_epm:
            string_binding = get_dynamic_endpoint(uuid_bin, target, timeout)
        elif is_tcp_pipe:
            if tcp_port is None:
                raise ValueError(f"tcp_port is required for {pipe}")
            string_binding = rf"ncacn_ip_tcp:{target}[{tcp_port}]"
        else:
            string_binding = rf"ncacn_np:{target}[\PIPE\{pipe}]"

        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_connect_timeout(timeout)

        if not use_epm:
            _set_transport_auth(
                rpctransport,
                target_ip=target_ip,
                port=port,
                set_dport=not is_tcp_pipe,
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash,
                do_kerberos=do_kerberos,
                dc_host=dc_host,
            )

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
        log.info("  Connection failed [%s]: %s", label, e)
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
