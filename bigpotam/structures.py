"""NDR structure definitions for all supported coercion protocols."""

from impacket import system_errors
from impacket.dcerpc.v5.dtypes import (
    BOOL,
    DWORD,
    LPBYTE,
    LPWSTR,
    NDRPOINTERNULL,
    PCHAR,
    RPC_SID,
    ULONG,
    WSTR,
)
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.rpcrt import DCERPCException


class DCERPCSessionError(DCERPCException):
    """Maps Win32 error codes to human-readable names.

    Impacket's NDRCALL machinery looks for this class in the module
    where request structures are defined. Without it, RPC error
    responses raise a bare AttributeError instead of a proper exception
    with error_code and named error strings.
    """

    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            short, verbose = system_errors.ERROR_MESSAGES[key]
            return f"SessionError: 0x{key:08x} - {short} - {verbose}"
        return f"SessionError: unknown error code: 0x{key:08x}"


# =============================================================================
# MS-EFSR structures
# =============================================================================


class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT):
    align = 1
    structure = (("Data", "20s"),)


class EFS_EXIM_PIPE(NDRSTRUCT):
    align = 1
    structure = (("Data", ":"),)


class EFS_HASH_BLOB(NDRSTRUCT):
    structure = (
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class EFS_RPC_BLOB(NDRSTRUCT):
    structure = (
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class EFS_CERTIFICATE_BLOB(NDRSTRUCT):
    structure = (
        ("Type", DWORD),
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
    structure = (
        ("Lenght", DWORD),
        ("SID", RPC_SID),
        ("Hash", EFS_HASH_BLOB),
        ("Display", LPWSTR),
    )


class ENCRYPTION_CERTIFICATE(NDRSTRUCT):
    structure = (
        ("Lenght", DWORD),
        ("SID", RPC_SID),
        ("Hash", EFS_CERTIFICATE_BLOB),
    )


class ENCRYPTION_CERTIFICATE_HASH_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ("Cert", DWORD),
        ("Users", ENCRYPTION_CERTIFICATE_HASH),
    )


class ENCRYPTED_FILE_METADATA_SIGNATURE(NDRSTRUCT):
    structure = (
        ("Type", DWORD),
        ("HASH", ENCRYPTION_CERTIFICATE_HASH_LIST),
        ("Certif", ENCRYPTION_CERTIFICATE),
        ("Blob", EFS_RPC_BLOB),
    )


class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ("nUsers", DWORD),
        ("Users", NDRPOINTERNULL),
    )


# --- EFSR NDRCALL classes ---


class EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (
        ("fileName", WSTR),
        ("Flag", ULONG),
    )


class EfsRpcOpenFileRawResponse(NDRCALL):
    structure = (
        ("hContext", EXIMPORT_CONTEXT_HANDLE),
        ("ErrorCode", ULONG),
    )


class EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (("FileName", WSTR),)


class EfsRpcEncryptFileSrvResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcDecryptFileSrv(NDRCALL):
    opnum = 5
    structure = (
        ("FileName", WSTR),
        ("Flag", ULONG),
    )


class EfsRpcDecryptFileSrvResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcQueryUsersOnFile(NDRCALL):
    opnum = 6
    structure = (("FileName", WSTR),)


class EfsRpcQueryUsersOnFileResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcQueryRecoveryAgents(NDRCALL):
    opnum = 7
    structure = (("FileName", WSTR),)


class EfsRpcQueryRecoveryAgentsResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcRemoveUsersFromFile(NDRCALL):
    opnum = 8
    structure = (
        ("FileName", WSTR),
        ("Users", ENCRYPTION_CERTIFICATE_HASH_LIST),
    )


class EfsRpcRemoveUsersFromFileResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcAddUsersToFile(NDRCALL):
    opnum = 9
    structure = (
        ("FileName", WSTR),
        ("EncryptionCertificates", ENCRYPTION_CERTIFICATE_LIST),
    )


class EfsRpcAddUsersToFileResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcFileKeyInfo(NDRCALL):
    opnum = 12
    structure = (
        ("FileName", WSTR),
        ("infoClass", DWORD),
    )


class EfsRpcFileKeyInfoResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcDuplicateEncryptionInfoFile(NDRCALL):
    opnum = 13
    structure = (
        ("SrcFileName", WSTR),
        ("DestFileName", WSTR),
        ("dwCreationDisposition", DWORD),
        ("dwAttributes", DWORD),
        ("RelativeSD", EFS_RPC_BLOB),
        ("bInheritHandle", BOOL),
    )


class EfsRpcDuplicateEncryptionInfoFileResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcAddUsersToFileEx(NDRCALL):
    opnum = 15
    structure = (
        ("dwFlags", DWORD),
        ("Reserved", NDRPOINTERNULL),
        ("FileName", WSTR),
        ("EncryptionCertificates", ENCRYPTION_CERTIFICATE_LIST),
    )


class EfsRpcAddUsersToFileExResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcFileKeyInfoEx(NDRCALL):
    opnum = 16
    structure = (
        ("dwFileKeyInfoFlags", DWORD),
        ("Reserved", EFS_RPC_BLOB),
        ("FileName", WSTR),
        ("InfoClass", DWORD),
    )


class EfsRpcFileKeyInfoExResponse(NDRCALL):
    structure = ()


# =============================================================================
# MS-RPRN structures (opnum 62 - custom, not in impacket)
# =============================================================================


class PRINTER_HANDLE(NDRSTRUCT):
    structure = (("Data", '20s=b""'),)

    def getAlignment(self):
        return 8 if self._isNDR64 else 4


class RpcRemoteFindFirstPrinterChangeNotification(NDRCALL):
    opnum = 62
    structure = (
        ("hPrinter", PRINTER_HANDLE),
        ("fdwFlags", DWORD),
        ("fdwOptions", DWORD),
        ("pszLocalMachine", LPWSTR),
        ("dwPrinterLocal", DWORD),
        ("cbBuffer", DWORD),
        ("pBuffer", LPBYTE),
    )


class RpcRemoteFindFirstPrinterChangeNotificationResponse(NDRCALL):
    structure = ()


# =============================================================================
# MS-FSRVP structures
# =============================================================================


class IsPathSupported(NDRCALL):
    opnum = 8
    structure = (("ShareName", WSTR),)


class IsPathSupportedResponse(NDRCALL):
    structure = ()


class IsPathShadowCopied(NDRCALL):
    opnum = 9
    structure = (("ShareName", WSTR),)


class IsPathShadowCopiedResponse(NDRCALL):
    structure = ()


# =============================================================================
# MS-DFSNM structures
# =============================================================================


class NetrDfsAddStdRoot(NDRCALL):
    opnum = 12
    structure = (
        ("ServerName", WSTR),
        ("RootShare", WSTR),
        ("Comment", WSTR),
        ("ApiFlags", DWORD),
    )


class NetrDfsAddStdRootResponse(NDRCALL):
    structure = ()


class NetrDfsRemoveStdRoot(NDRCALL):
    opnum = 13
    structure = (
        ("ServerName", WSTR),
        ("RootShare", WSTR),
        ("ApiFlags", DWORD),
    )


class NetrDfsRemoveStdRootResponse(NDRCALL):
    structure = ()


class NetrDfsManagerInitialize(NDRCALL):
    opnum = 14
    structure = (
        ("ServerName", WSTR),
        ("Flags", DWORD),
    )


class NetrDfsManagerInitializeResponse(NDRCALL):
    structure = ()


class NetrDfsAddStdRootForced(NDRCALL):
    opnum = 15
    structure = (
        ("ServerName", WSTR),
        ("RootShare", WSTR),
        ("Comment", WSTR),
        ("Share", WSTR),
    )


class NetrDfsAddStdRootForcedResponse(NDRCALL):
    structure = ()


class NetrDfsAddRootTarget(NDRCALL):
    opnum = 23
    structure = (
        ("pDfsPath", LPWSTR),
        ("pTargetPath", LPWSTR),
        ("MajorVersion", ULONG),
        ("pComment", LPWSTR),
        ("NewNamespace", BOOL),
        ("Flags", ULONG),
    )


class NetrDfsAddRootTargetResponse(NDRCALL):
    structure = ()


class NetrDfsRemoveRootTarget(NDRCALL):
    opnum = 24
    structure = (
        ("pDfsPath", LPWSTR),
        ("pTargetPath", LPWSTR),
        ("Flags", ULONG),
    )


class NetrDfsRemoveRootTargetResponse(NDRCALL):
    structure = ()
