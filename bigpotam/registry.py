"""Method registry — ordered list of all coercion methods."""

from bigpotam.methods.efsr import (
    trigger_add_users_to_file,
    trigger_add_users_to_file_ex,
    trigger_decrypt_file_srv,
    trigger_duplicate_encryption_info_file,
    trigger_encrypt_file_srv,
    trigger_file_key_info,
    trigger_file_key_info_ex,
    trigger_open_file_raw,
    trigger_query_recovery_agents,
    trigger_query_users_on_file,
    trigger_remove_users_from_file,
)
from bigpotam.methods.rprn import (
    trigger_par_async_open_printer,
    trigger_rprn_notification,
    trigger_rprn_notification_ex,
)
from bigpotam.methods.dfsnm import (
    trigger_add_root_target,
    trigger_add_std_root,
    trigger_add_std_root_forced,
    trigger_manager_initialize,
    trigger_remove_root_target,
    trigger_remove_std_root,
)
from bigpotam.methods.fsrvp import (
    trigger_is_path_shadow_copied,
    trigger_is_path_supported,
)
from bigpotam.methods.even import trigger_elfr_open_belw

# UUIDs
EFSR_UUID_LSARPC = ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0")
EFSR_UUID_EFSRPC = ("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0")
RPRN_UUID = ("12345678-1234-abcd-ef00-0123456789ab", "1.0")
PAR_UUID = ("76f03f96-cdfd-44fc-a22c-64950a001209", "1.0")
FSRVP_UUID = ("a8e0653c-2744-4389-a61d-7373df8b2292", "1.0")
DFSNM_UUID = ("4fc742e0-4a10-11cf-8273-00aa004ae673", "3.0")
EVEN_UUID = ("82273fdc-e32a-18c3-3f78-827929dc23ea", "0.0")


def _efsr_method(name, trigger, opnum):
    """Helper to build an EFSR method entry with all 5 pipes."""
    return {
        "protocol": "MS-EFSR",
        "name": name,
        "opnum": opnum,
        "pipe": "lsarpc",
        "all_pipes": ["lsarpc", "efsrpc", "samr", "lsass", "netlogon"],
        "uuid": EFSR_UUID_LSARPC,
        "uuid_by_pipe": {"efsrpc": EFSR_UUID_EFSRPC},
        "trigger": trigger,
        "requires_efs_activation": True,
        "connection_type": "rpc",
    }


# Ordered: most reliable/universal first
METHODS = [
    # --- MS-EFSR via lsarpc (11 functions) ---
    _efsr_method("EfsRpcEncryptFileSrv", trigger_encrypt_file_srv, 4),
    _efsr_method("EfsRpcDecryptFileSrv", trigger_decrypt_file_srv, 5),
    _efsr_method("EfsRpcQueryUsersOnFile", trigger_query_users_on_file, 6),
    _efsr_method("EfsRpcQueryRecoveryAgents", trigger_query_recovery_agents, 7),
    _efsr_method("EfsRpcRemoveUsersFromFile", trigger_remove_users_from_file, 8),
    _efsr_method("EfsRpcAddUsersToFile", trigger_add_users_to_file, 9),
    _efsr_method("EfsRpcFileKeyInfo", trigger_file_key_info, 12),
    _efsr_method("EfsRpcDuplicateEncryptionInfoFile", trigger_duplicate_encryption_info_file, 13),
    _efsr_method("EfsRpcAddUsersToFileEx", trigger_add_users_to_file_ex, 15),
    _efsr_method("EfsRpcFileKeyInfoEx", trigger_file_key_info_ex, 16),
    _efsr_method("EfsRpcOpenFileRaw", trigger_open_file_raw, 0),  # patched — try last

    # --- MS-RPRN via spoolss ---
    {
        "protocol": "MS-RPRN",
        "name": "RpcRemoteFindFirstPrinterChangeNotification",
        "opnum": 62,
        "pipe": "spoolss",
        "all_pipes": ["spoolss"],
        "uuid": RPRN_UUID,
        "uuid_by_pipe": {},
        "trigger": trigger_rprn_notification,
        "requires_efs_activation": False,
        "connection_type": "rpc",
        "needs_target_name": True,
    },
    {
        "protocol": "MS-RPRN",
        "name": "RpcRemoteFindFirstPrinterChangeNotificationEx",
        "opnum": 65,
        "pipe": "spoolss",
        "all_pipes": ["spoolss"],
        "uuid": RPRN_UUID,
        "uuid_by_pipe": {},
        "trigger": trigger_rprn_notification_ex,
        "requires_efs_activation": False,
        "connection_type": "rpc",
        "needs_target_name": True,
    },

    # --- MS-RPRN via EPM/TCP dynamic endpoint ---
    {
        "protocol": "MS-RPRN",
        "name": "RpcRemoteFindFirstPrinterChangeNotificationEx [dcerpc]",
        "opnum": 65,
        "pipe": "dcerpc",
        "all_pipes": ["dcerpc"],
        "uuid": RPRN_UUID,
        "uuid_by_pipe": {},
        "trigger": trigger_rprn_notification_ex,
        "requires_efs_activation": False,
        "connection_type": "rpc_epm",
        "needs_target_name": True,
    },

    # --- MS-PAR ---
    {
        "protocol": "MS-PAR",
        "name": "RpcAsyncOpenPrinter",
        "opnum": 0,
        "pipe": "spoolss",
        "all_pipes": ["spoolss"],
        "uuid": PAR_UUID,
        "uuid_by_pipe": {},
        "trigger": trigger_par_async_open_printer,
        "requires_efs_activation": False,
        "connection_type": "rpc",
    },

    # --- MS-DFSNM ---
    {
        "protocol": "MS-DFSNM",
        "name": "NetrDfsAddStdRoot",
        "opnum": 12,
        "pipe": "netdfs",
        "all_pipes": ["netdfs"],
        "uuid": DFSNM_UUID,
        "uuid_by_pipe": {},
        "trigger": trigger_add_std_root,
        "requires_efs_activation": False,
        "connection_type": "rpc",
    },
    {
        "protocol": "MS-DFSNM",
        "name": "NetrDfsAddStdRootForced",
        "opnum": 15,
        "pipe": "netdfs",
        "all_pipes": ["netdfs"],
        "uuid": DFSNM_UUID,
        "uuid_by_pipe": {},
        "trigger": trigger_add_std_root_forced,
        "requires_efs_activation": False,
        "connection_type": "rpc",
    },
    {
        "protocol": "MS-DFSNM",
        "name": "NetrDfsAddRootTarget",
        "opnum": 23,
        "pipe": "netdfs",
        "all_pipes": ["netdfs"],
        "uuid": DFSNM_UUID,
        "uuid_by_pipe": {},
        "trigger": trigger_add_root_target,
        "requires_efs_activation": False,
        "connection_type": "rpc",
    },
    {
        "protocol": "MS-DFSNM",
        "name": "NetrDfsRemoveRootTarget",
        "opnum": 24,
        "pipe": "netdfs",
        "all_pipes": ["netdfs"],
        "uuid": DFSNM_UUID,
        "uuid_by_pipe": {},
        "trigger": trigger_remove_root_target,
        "requires_efs_activation": False,
        "connection_type": "rpc",
    },
    {
        "protocol": "MS-DFSNM",
        "name": "NetrDfsRemoveStdRoot",
        "opnum": 13,
        "pipe": "netdfs",
        "all_pipes": ["netdfs"],
        "uuid": DFSNM_UUID,
        "uuid_by_pipe": {},
        "trigger": trigger_remove_std_root,
        "requires_efs_activation": False,
        "connection_type": "rpc",
    },
    {
        "protocol": "MS-DFSNM",
        "name": "NetrDfsManagerInitialize",
        "opnum": 14,
        "pipe": "netdfs",
        "all_pipes": ["netdfs"],
        "uuid": DFSNM_UUID,
        "uuid_by_pipe": {},
        "trigger": trigger_manager_initialize,
        "requires_efs_activation": False,
        "connection_type": "rpc",
    },

    # --- MS-FSRVP ---
    {
        "protocol": "MS-FSRVP",
        "name": "IsPathSupported",
        "opnum": 8,
        "pipe": "FssagentRpc",
        "all_pipes": ["FssagentRpc"],
        "uuid": FSRVP_UUID,
        "uuid_by_pipe": {},
        "trigger": trigger_is_path_supported,
        "requires_efs_activation": False,
        "connection_type": "rpc",
    },
    {
        "protocol": "MS-FSRVP",
        "name": "IsPathShadowCopied",
        "opnum": 9,
        "pipe": "FssagentRpc",
        "all_pipes": ["FssagentRpc"],
        "uuid": FSRVP_UUID,
        "uuid_by_pipe": {},
        "trigger": trigger_is_path_shadow_copied,
        "requires_efs_activation": False,
        "connection_type": "rpc",
    },

    # --- MS-EVEN ---
    {
        "protocol": "MS-EVEN",
        "name": "ElfrOpenBELW",
        "opnum": 9,
        "pipe": "eventlog",
        "all_pipes": ["eventlog"],
        "uuid": EVEN_UUID,
        "uuid_by_pipe": {},
        "trigger": trigger_elfr_open_belw,
        "requires_efs_activation": False,
        "connection_type": "rpc",
    },

    # --- MS-WSP (handled separately — not RPC) ---
    {
        "protocol": "MS-WSP",
        "name": "WSP Connect/Query",
        "opnum": None,
        "pipe": "MsFteWds",
        "all_pipes": ["MsFteWds"],
        "uuid": None,
        "uuid_by_pipe": {},
        "trigger": None,  # WSP has its own trigger in wsp.py
        "requires_efs_activation": False,
        "connection_type": "wsp",
    },

    # --- DCOM UpdateSession (handled separately — not named pipe) ---
    {
        "protocol": "DCOM",
        "name": "UpdateSession.AddScanPackageService",
        "opnum": None,
        "pipe": None,
        "all_pipes": [],
        "uuid": None,
        "uuid_by_pipe": {},
        "trigger": None,  # DCOM has its own trigger in dcom.py
        "requires_efs_activation": False,
        "connection_type": "dcom",
    },
]
