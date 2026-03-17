# Agent Development Plan: Unified Coercion Tool

## Objective

Build a standalone Python coercion tool that consolidates all known NTLM
authentication coercion primitives across MS-EFSR, MS-RPRN, MS-PAR, MS-FSRVP,
MS-DFSNM, MS-EVEN, MS-WSP, and DCOM (machine account variant only) into a
single script. Fire-and-forget design (no relay feedback). Stop on first
success by default, configurable via `--all` flag. Single target scope.

---

## Clarification: PrinterBug vs SpoolSample

These are the **same attack**, different implementations of MS-RPRN abuse:
- **SpoolSample** — original C# PoC by Lee Christensen (@tifkin_), 2018.
  Requires compiling. GitHub: https://github.com/leechristensen/SpoolSample
- **PrinterBug** — Dirk-jan Mollema's Python reimplementation of the same
  technique. The source code shared in this conversation IS PrinterBug.

Both call `RpcRemoteFindFirstPrinterChangeNotification` on the `\PIPE\spoolss`
named pipe. They are already covered under MS-RPRN in the method table. Do not
treat them as separate protocols.

---

## Step 1: Read and Understand Existing Source Code

Before writing any code, clone and read the following. They contain all RPC
structures, bindings, and trigger logic to consolidate.

### 1.1 Clone These Repositories

```bash
git clone https://github.com/topotam/PetitPotam
git clone https://github.com/p0dalirius/Coercer
git clone https://github.com/Pennyw0rth/NetExec
git clone https://github.com/p0dalirius/windows-coerced-authentication-methods
git clone https://github.com/RedTeamPentesting/wspcoerce
git clone https://github.com/xforcered/RemoteMonologue
```

### 1.2 Read These Files in Order

**1. `PetitPotam/PetitPotam.py`** (topotam original)
Read for: 5-pipe EFSR binding approach (`lsarpc`, `efsr`, `samr`, `lsass`,
`netlogon`), `EfsRpcOpenFileRaw` trigger, fallback to `EfsRpcEncryptFileSrv`.

**2. ly4k PetitPotam** (provided inline in this conversation)
Read for: `NDRPOINTERNULL` usage in `ENCRYPTION_CERTIFICATE_LIST`, per-method
error code checking (each `hEfsRpc*` function checks specific error codes rather
than catching all exceptions), random method selection pattern, cleaner
class-based structure, and intentional exclusion of `EfsRpcOpenFileRaw` from the
callable TECHNIQUES dict (it is the patched opnum).

**3. `Coercer/coercer/methods/MS_EFSR/` — all files**
Read for: `exploit_paths` format showing both SMB (`\\{{listener}}`) and HTTP
(`\\{{listener}}@{{port}}/{{rnd}}`) path variants, full list of confirmed
working EFSR functions.

**4. `Coercer/coercer/methods/MS_RPRN/RpcRemoteFindFirstPrinterChangeNotification.py`
and `RpcRemoteFindFirstPrinterChangeNotificationEx.py`**
Read for: `\PIPE\spoolss` binding, `RpcOpenPrinter` handle requirement before
notification call (mandatory — you cannot call the notification functions
directly), opnum 62 and 65.

**5. `Coercer/coercer/methods/MS_FSRVP/IsPathSupported.py` and
`IsPathShadowCopied.py`**
Read for: `\PIPE\Fssagentrpc` pipe, UUID `a8e0653c-2744-4389-a61d-7373df8b2292`,
opnums 8 and 9.

**6. `Coercer/coercer/methods/MS_DFSNM/NetrDfsAddStdRoot.py` and
`NetrDfsRemoveStdRoot.py`**
Read for: `\PIPE\netdfs` pipe, UUID `4fc742e0-4a10-11cf-8273-00aa004ae673`,
basic confirmed DFS coercion.

**7. `Coercer/coercer/methods/MS_EVEN/ElfrOpenBELW.py`**
Read for: `\PIPE\eventlog` pipe, UUID `82273fdc-e32a-18c3-3f78-827929dc23ea`,
and critically the `\\??\UNC\{listener}{port}\{random}\aa` device path format —
this is different from all other methods and must be used exactly as shown.

**8. `NetExec/nxc/modules/coerce_plus.py`** ← most important file
Read for:
- `get_dynamic_endpoint()` function — the EFS auto-activation trick equivalent
  to rpc2efs.py. Queries EPM on port 135 before EFSR attempts to activate the
  EFS service on-demand. Call this once per target before any EFSR attempt.
- Additional MS-DFSNM functions not in Coercer: `NetrDfsAddStdRootForced`
  (opnum 15), `NetrDfsAddRootTarget` (opnum 23), `NetrDfsRemoveRootTarget`
  (opnum 24), `NetrDfsManagerInitialize` (opnum 14).
- PrinterBug via `[dcerpc]` dynamic endpoint — queries EPM for RPRN over TCP
  rather than assuming `\PIPE\spoolss` is accessible, useful when named pipe is
  blocked.
- `handle_exception()` pattern — checks multiple success error codes:
  `rpc_s_access_denied`, `ERROR_BAD_NETPATH`, `RPC_S_INVALID_NET_ADDR`.

**9. `windows-coerced-authentication-methods/methods/` — ALL files**
This is p0dalirius's reference repo. The `methods/` subdirectory contains
confirmed working coercion PoCs. Read all of them. Key additions vs Coercer:

- `MS-EFSR/16. Remote call to EfsRpcFileKeyInfoEx (opnum 16)/coerce_poc.py` —
  an additional EFSR function not in Coercer or coerce_plus.
- `MS-PAR - Print System Asynchronous Remote Protocol/00. Remote call to
  RpcAsyncOpenPrinter (opnum 0)/coerce_poc.py` — a confirmed new protocol not
  covered by any existing tool. Read carefully for pipe name and UUID.

Also read the `possible-working-calls/` subdirectory for situational/unconfirmed
methods. These are not worth implementing by default but notable protocols
include MS-NRPC, MS-SRVS, MS-DNSP, MS-FAX, MS-TSCH, and MS-SWN. Do not
implement these in the initial version — flag them as future work.

**10. `wspcoerce/` — the RedTeamPentesting Python implementation**
Read for: MS-WSP (`\pipe\MsFteWds`) implementation, WSP Connect/Query/Disconnect
sequence, the `file:////attacksystem/share` path format (different from all
others — uses forward slashes). Note: SMB only, no HTTP/WebDAV variant. Only
effective against workstations since Windows Search Service is disabled by
default on servers since Server 2016.

**11. `RemoteMonologue/RemoteMonologue.py`** ← read for DCOM machine account coercion only
This tool implements DCOM-based coercion. Only one of its four DCOM objects is
in scope for our tool — `UpdateSession` (CLSID `4CB43D7F-7EEE-4906-8698-60DA1C38F2FE`),
which coerces the **machine account** rather than an interactive user session.

Read for:
- `dcom_coerce()` method — specifically the `UpdateSession` branch. It uses
  impacket's `DCOMConnection` and `IDispatch` over DCOM (port 135/dynamic), not
  named pipes. The flow is: connect via DCOM → `CoCreateInstanceEx` with
  UpdateSession CLSID → get `IUpdateServiceManager` interface →
  call `AddScanPackageService` with a UNC path pointing to the listener.
- `AuthenticationCoercer.execute_remote()` — shows UNC path format:
  `\\{listener}\{random_share}\{random_file}.txt`. This is different from all
  RPC-based methods.
- Impacket imports needed: `DCOMConnection`, `IID_IDispatch`, `IDispatch`,
  `DISPPARAMS`, `DISPATCH_METHOD`, `VARIANT`, `VARENUM` from
  `impacket.dcerpc.v5.dcom.oaut` and `impacket.dcerpc.v5.dcomrt`.

The other three DCOM objects (`ServerDataCollectorSet`, `FileSystemImage`,
`MSTSWebProxy`) are **out of scope** — they coerce interactive user sessions,
not machine accounts, and require Remote Registry modification with local admin
to set RunAs = Interactive User. This is a different goal entirely (coercing a
specific logged-on user's credentials). Do not implement these in this tool.
Note them in the out-of-scope section instead.

---

## Step 2: Complete Method Table

This is the full set of methods to implement, derived from reading all sources
above. Confirmed working methods first, then the new additions.

### Confirmed Working (implement all)

| Protocol | Function | Opnum | Pipe | SMB | HTTP | Source |
|---|---|---|---|---|---|---|
| MS-RPRN | RpcRemoteFindFirstPrinterChangeNotification | 62 | `\PIPE\spoolss` | ✅ | ✅ | PrinterBug/SpoolSample/Coercer/coerce_plus |
| MS-RPRN | RpcRemoteFindFirstPrinterChangeNotificationEx | 65 | `\PIPE\spoolss` | ✅ | ✅ | Coercer/coerce_plus |
| MS-RPRN | Both via EPM/TCP dynamic endpoint | — | `[dcerpc]` | ✅ | ❌ | coerce_plus |
| MS-EFSR | EfsRpcOpenFileRaw | 0 | lsarpc/efsr/samr/lsass/netlogon | ✅ | ✅ | topotam PetitPotam/Coercer |
| MS-EFSR | EfsRpcEncryptFileSrv | 4 | same | ✅ | ✅ | topotam PetitPotam (fallback)/Coercer |
| MS-EFSR | EfsRpcDecryptFileSrv | 5 | same | ✅ | ✅ | ly4k PetitPotam/Coercer/coerce_plus |
| MS-EFSR | EfsRpcQueryUsersOnFile | 6 | same | ✅ | ✅ | ly4k PetitPotam/Coercer/coerce_plus |
| MS-EFSR | EfsRpcQueryRecoveryAgents | 7 | same | ✅ | ✅ | ly4k PetitPotam/Coercer/coerce_plus |
| MS-EFSR | EfsRpcRemoveUsersFromFile | 8 | same | ✅ | ✅ | ly4k PetitPotam/Coercer/coerce_plus |
| MS-EFSR | EfsRpcAddUsersToFile | 9 | same | ✅ | ✅ | ly4k PetitPotam/Coercer/coerce_plus |
| MS-EFSR | EfsRpcFileKeyInfo | 12 | same | ✅ | ✅ | Coercer/coerce_plus |
| MS-EFSR | EfsRpcDuplicateEncryptionInfoFile | 13 | same | ✅ | ✅ | Coercer/coerce_plus |
| MS-EFSR | EfsRpcAddUsersToFileEx | 15 | same | ✅ | ✅ | Coercer/coerce_plus |
| MS-EFSR | EfsRpcFileKeyInfoEx | 16 | same | ✅ | ✅ | p0dalirius repo only |
| MS-PAR | RpcAsyncOpenPrinter | 0 | (read from p0dalirius repo) | ✅ | ❌ | p0dalirius repo only |
| MS-FSRVP | IsPathSupported | 8 | `\PIPE\Fssagentrpc` | ✅ | ✅ | ShadowCoerce/Coercer/coerce_plus |
| MS-FSRVP | IsPathShadowCopied | 9 | `\PIPE\Fssagentrpc` | ✅ | ✅ | ShadowCoerce/Coercer/coerce_plus |
| MS-DFSNM | NetrDfsAddStdRoot | 12 | `\PIPE\netdfs` | ✅ | ✅ | DFSCoerce/Coercer/coerce_plus |
| MS-DFSNM | NetrDfsRemoveStdRoot | 13 | `\PIPE\netdfs` | ✅ | ✅ | DFSCoerce/Coercer/coerce_plus |
| MS-DFSNM | NetrDfsManagerInitialize | 14 | `\PIPE\netdfs` | ✅ | ❌ | coerce_plus only |
| MS-DFSNM | NetrDfsAddStdRootForced | 15 | `\PIPE\netdfs` | ✅ | ❌ | coerce_plus only |
| MS-DFSNM | NetrDfsAddRootTarget | 23 | `\PIPE\netdfs` | ✅ | ❌ | coerce_plus only |
| MS-DFSNM | NetrDfsRemoveRootTarget | 24 | `\PIPE\netdfs` | ✅ | ❌ | coerce_plus only |
| MS-EVEN | ElfrOpenBELW | 9 | `\PIPE\eventlog` | ✅ | ❌ | Coercer/coerce_plus |
| MS-WSP | WSP Connect/Query | — | `\pipe\MsFteWds` | ✅ | ❌ | WSPCoerce (workstations only) |
| DCOM | UpdateSession.AddScanPackageService | — | DCOM/135 | ✅ | ❌ | RemoteMonologue (machine account) |

### EFS Auto-Activation
Also implement the rpc2efs trick as a pre-flight step before all EFSR attempts.
Source from `coerce_plus.py` → `get_dynamic_endpoint()` and the silent EPM call
in `PetitPotamtTrigger.connect()`.

---

## Step 3: Architecture

Single Python file. Sections in order:

### 3.1 Imports and Dependencies

```
impacket (latest from pip)
- impacket.dcerpc.v5.transport
- impacket.dcerpc.v5.rprn
- impacket.dcerpc.v5.even
- impacket.dcerpc.v5.epm
- impacket.dcerpc.v5.ndr
- impacket.dcerpc.v5.dtypes
- impacket.dcerpc.v5.rpcrt
- impacket.uuid
- impacket.examples.utils (parse_target)
- impacket.dcerpc.v5.dcomrt (DCOMConnection, IRemUnknown2, INTERFACE, OBJREF etc.)
- impacket.dcerpc.v5.dcom.oaut (IID_IDispatch, IDispatch, DISPPARAMS,
  DISPATCH_METHOD, VARIANT, VARENUM, string_to_bin)
```

### 3.2 NDR Structure Definitions

Source all structures directly from the files listed in Step 1.2. Key
structures needed:

**MS-EFSR:**
- `EXIMPORT_CONTEXT_HANDLE`
- `EFS_HASH_BLOB`, `EFS_RPC_BLOB`, `EFS_CERTIFICATE_BLOB`
- `ENCRYPTION_CERTIFICATE_HASH`, `ENCRYPTION_CERTIFICATE`
- `ENCRYPTION_CERTIFICATE_HASH_LIST`
- `ENCRYPTION_CERTIFICATE_LIST` — use `NDRPOINTERNULL` for Users field
  (ly4k's approach, not raw `:` type from topotam's version)
- `ENCRYPTED_FILE_METADATA_SIGNATURE`
- All `EfsRpc*` NDRCALL classes (opnums 0,4,5,6,7,8,9,12,13,15,16)

**MS-RPRN:**
- `PRINTER_HANDLE`, `USHORT_ARRAY`, `PUSHORT_ARRAY`
- `RPC_V2_NOTIFY_OPTIONS_TYPE`, `RPC_V2_NOTIFY_OPTIONS`, `PRPC_V2_NOTIFY_OPTIONS`
- `RpcRemoteFindFirstPrinterChangeNotification` (opnum 62, custom struct)
- Use impacket's built-in `rprn.RpcRemoteFindFirstPrinterChangeNotificationEx`
  (opnum 65)

**MS-PAR:**
- Source `RpcAsyncOpenPrinter` structure from
  `windows-coerced-authentication-methods/methods/MS-PAR/00.../coerce_poc.py`
- Read for pipe name and UUID — do not guess these.

**MS-FSRVP:**
- `IsPathSupported` (opnum 8)
- `IsPathShadowCopied` (opnum 9)

**MS-DFSNM:**
- `NetrDfsAddStdRoot` (opnum 12)
- `NetrDfsRemoveStdRoot` (opnum 13)
- `NetrDfsManagerInitialize` (opnum 14)
- `NetrDfsAddStdRootForced` (opnum 15)
- `NetrDfsAddRootTarget` (opnum 23)
- `NetrDfsRemoveRootTarget` (opnum 24)

**MS-EVEN:**
- Use impacket's built-in `even.ElfrOpenBELW`

**MS-WSP:**
- Source all structures from `wspcoerce/` repo. Do not guess — WSP has a
  distinct connect/query/disconnect sequence unlike all other protocols.

### 3.3 Protocol/Method Registry

Define a structured registry so the main loop can iterate cleanly without
protocol-specific branching. Each entry contains:

```python
METHODS = [
    {
        "protocol": "MS-EFSR",
        "name": "EfsRpcOpenFileRaw",
        "pipe": "lsarpc",           # default pipe
        "all_pipes": ["lsarpc", "efsr", "samr", "lsass", "netlogon"],
        "uuid": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
        "uuid_by_pipe": {
            "efsr": ("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0"),
            # all other pipes use the default uuid above
        },
        "trigger": trigger_efsr_open_file_raw,
        "requires_efs_activation": True,
        "http_capable": True,
        "notes": "Patched opnum (EfsRpcOpenFileRaw) — try last in EFSR sequence"
    },
    ...
]
```

### 3.4 EFS Auto-Activation

Implement as standalone function. Call once per target before first EFSR attempt,
not once per method call. Source logic from `coerce_plus.py`
→ `get_dynamic_endpoint()` and the silent EPM call in
`PetitPotamtTrigger.connect()`:

```python
def activate_efs(target, timeout=2):
    """
    Poke EPM on port 135 to trigger on-demand EFS service start.
    Expects to fail - the exception is the success condition.
    Based on rpc2efs.py technique. Silently ignored if port 135 filtered.
    """
    EFS_UUID = uuidtup_to_bin(("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0"))
    try:
        string_binding = f"ncacn_ip_tcp:{target}[135]"
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_connect_timeout(timeout)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        epm.hept_map(target, EFS_UUID, protocol="ncacn_ip_tcp", dce=dce)
    except Exception:
        pass  # expected - service activation is the side effect
```

### 3.5 Connection Helper

Single `connect()` function handling all protocols:

```python
def connect(target, target_ip, pipe, uuid, port, username, password,
            domain, lmhash, nthash, do_kerberos, dc_host, use_epm=False):
```

- Named pipe: `ncacn_np:{target}[\PIPE\{pipe}]`
- EPM/TCP (PrinterBug `[dcerpc]` mode): call `epm.hept_map()` for dynamic binding
- Auth level: `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`
- Kerberos: `RPC_C_AUTHN_GSS_NEGOTIATE`
- Returns `dce` session or `None` on failure — never raises, always handles
  connection errors gracefully

### 3.6 Trigger Functions

One trigger function per method. Follow ly4k's pattern of checking specific
error codes. Success conditions vary by method — source from `coerce_plus.py`'s
`handle_exception()` and ly4k's helper functions:

- **EFSR methods**: `ERROR_BAD_NETPATH`, `ERROR_INVALID_NAME`
- **DFSNM methods**: `rpc_s_access_denied`, `ERROR_BAD_NETPATH`,
  `RPC_S_INVALID_NET_ADDR`
- **FSRVP methods**: `rpc_s_access_denied`
- **RPRN methods**: `rpc_s_access_denied`, `RPC_S_SERVER_UNAVAILABLE`
- **EVEN**: `ERROR_BAD_NETPATH`, `STATUS_OBJECT_PATH_NOT_FOUND`,
  `STATUS_CONNECTION_DISCONNECTED`
- **WSP**: read from `wspcoerce/` — has its own error handling logic
- **PAR**: read from p0dalirius repo PoC

### 3.7 Path Format Per Protocol

Each protocol uses a different UNC/path format for the listener argument.
Get these exactly right — wrong formats silently fail:

| Protocol | Path Format | Example |
|---|---|---|
| MS-EFSR | `\\{listener}\test\Settings.ini` | `\\10.0.0.1\test\Settings.ini` |
| MS-RPRN | `\\{listener}` | `\\10.0.0.1` |
| MS-RPRN (HTTP) | `\\{listener}@{port}/{random}` | `\\attacker@80/abc` |
| MS-FSRVP | `\\{listener}` | `\\10.0.0.1` |
| MS-DFSNM | `\\{listener}{port}\{random}\file.txt` | `\\10.0.0.1\abcdef\file.txt` |
| MS-DFSNM (HTTP) | `\\{listener}{port}/{random}\share\file.txt` | as above |
| MS-EVEN | `\\??\UNC\{listener}{port}\{random}\aa` | `\\??\UNC\10.0.0.1\abcdefgh\aa` |
| MS-WSP | `file:////{listener}/share` | `file:////10.0.0.1/share` |
| DCOM (UpdateSession) | `\\{listener}\{random}\{random}.txt` | `\\10.0.0.1\abcd\efgh.txt` |
| MS-PAR | Read from p0dalirius repo | — |

### 3.8 Main Execution Loop

```python
def run(target, listener, listener_port, args):
    # Attempt EFS activation before any EFSR work
    activate_efs(target)

    for method in METHODS:
        # Filter by --method or --protocol if specified
        if args.method and args.method != method["name"]:
            continue
        if args.protocol and args.protocol != method["protocol"]:
            continue

        # For EFSR: try all pipes or just default
        pipes_to_try = method.get("all_pipes", [method["pipe"]]) \
                       if args.all_pipes else [method["pipe"]]

        for pipe in pipes_to_try:
            dce = connect(target, args.target_ip, pipe,
                          method["uuid_by_pipe"].get(pipe, method["uuid"]),
                          args.port, ...)
            if dce is None:
                continue

            success = method["trigger"](dce, listener, listener_port)

            if success:
                print(f"[+] {method['protocol']} / {method['name']} via {pipe}")
                if not args.all:
                    return  # stop on first success
            dce.disconnect()
```

---

## Step 4: CLI Arguments

```
positional:
  target              [[domain/]username[:password]@]<host>
  listener            IP or hostname for auth callback

optional:
  -listener-port      Listener port (default: 445, use 80 for WebDAV)
  -method             Specific method name (e.g. EfsRpcOpenFileRaw)
  -protocol           Limit to one protocol (MS-EFSR, MS-RPRN, MS-PAR,
                      MS-FSRVP, MS-DFSNM, MS-EVEN, MS-WSP)
  -all                Try all methods even after success
  -all-pipes          Try all EFSR named pipes per method (not just lsarpc)
  -hashes             LMHASH:NTHASH
  -no-pass            Skip password prompt
  -k                  Kerberos auth
  -dc-ip              DC IP for Kerberos
  -target-ip          Target IP if different from hostname
  -port               SMB port (139 or 445, default 445)
  -timeout            Connection timeout seconds (default 5)
  -debug              Verbose output
```

---

## Step 5: Method Execution Order

When `--all` is not set (stop on first success), try in this order —
most reliable/universal first:

1. MS-EFSR via lsarpc (most universally accessible pipe, try all 11 functions)
2. MS-RPRN via spoolss (both opnum 62 and 65)
3. MS-RPRN via EPM/TCP dynamic endpoint
4. MS-PAR RpcAsyncOpenPrinter
5. MS-DFSNM NetrDfsAddStdRoot
6. MS-DFSNM NetrDfsAddStdRootForced
7. MS-DFSNM NetrDfsAddRootTarget
8. MS-DFSNM NetrDfsRemoveRootTarget
9. MS-DFSNM NetrDfsRemoveStdRoot
10. MS-DFSNM NetrDfsManagerInitialize
11. MS-FSRVP IsPathSupported
12. MS-FSRVP IsPathShadowCopied
13. MS-EVEN ElfrOpenBELW
14. MS-WSP (last — workstations only, service rarely available on servers)
15. DCOM UpdateSession (last — requires DCOM accessible on port 135, uses
    completely different connection mechanism)

When running MS-EFSR, iterate all 11 functions per pipe before moving to the
next pipe (unless `--all` is not set and one succeeds).

---

## Step 6: Testing Checklist

- [ ] EFS activation fires before EFSR and does not crash if port 135 filtered
- [ ] `lsarpc` pipe works against a patched target (EfsRpcOpenFileRaw blocked,
      others work)
- [ ] `efsr` pipe works independently with its distinct UUID
- [ ] PrinterBug via `spoolss` pipe works (requires hRpcOpenPrinter first)
- [ ] PrinterBug via EPM dynamic endpoint works when spoolss pipe is blocked
- [ ] MS-PAR trigger works — read PoC from p0dalirius repo for expected behaviour
- [ ] MS-DFSNM methods fire correctly — `ServerName` argument is the listener,
      not the target
- [ ] MS-EVEN uses `\\??\UNC\` path format exactly as shown in coerce_poc.py
- [ ] MS-WSP uses `file:////` path format and WSP connect/query/disconnect
      sequence
- [ ] DCOM UpdateSession connects via port 135 using DCOMConnection, not a
      named pipe — connection logic is entirely separate from all RPC methods
- [ ] DCOM UpdateSession UNC path uses random 4-char share and filename per
      attempt (match RemoteMonologue's AuthenticationCoercer.execute_remote())
- [ ] `--all` flag tries every method and reports all successes
- [ ] Default mode stops after first confirmed success
- [ ] Kerberos auth works alongside NTLM
- [ ] Tool exits cleanly when target unreachable (no hanging on timeout)
- [ ] `-listener-port 80` correctly formats WebDAV paths for capable methods

---

## Key Pitfalls to Avoid

**MS-EVEN path format** — do not use `\\{listener}\share` format. Must be
`\\??\UNC\{listener}\{random}\aa`. This is a device path, not a UNC path.

**MS-WSP path format** — must be `file:////{listener}/share` with forward
slashes. Do not use backslash UNC format.

**DCOM UpdateSession connection** — this method does NOT use named pipes or
`ncacn_np`. It connects via `DCOMConnection` over port 135/dynamic DCOM ports.
The connection helper used for all other methods does not apply here. Source
the entire connection and invocation flow from
`RemoteMonologue/RemoteMonologue.py` → `dcom_coerce()` → UpdateSession branch.
The key impacket classes are `DCOMConnection`, `IDispatch`, `DISPPARAMS`, and
`VARIANT` from `impacket.dcerpc.v5.dcom.oaut` and `impacket.dcerpc.v5.dcomrt`.

**DCOM UpdateSession UNC path** — must be `\\{listener}\{random4}\{random4}.txt`
with randomised share and filename per attempt. Source from
`AuthenticationCoercer.execute_remote()` in RemoteMonologue.

**MS-RPRN handle requirement** — you cannot call notification functions directly.
Must call `rprn.hRpcOpenPrinter(dce, "\\{target}\x00")` first and pass the
returned handle. Missing this step causes silent failure.

**EFSR UUID varies by pipe** — `\PIPE\efsrpc` uses UUID
`df1941c5-fe89-4e79-bf10-463657acf44d`. All other pipes (`lsarpc`, `samr`,
`lsass`, `netlogon`) use `c681d488-d850-11d0-8c52-00c04fd90f7e`. This is a
very common mistake.

**ENCRYPTION_CERTIFICATE_LIST** — use `NDRPOINTERNULL` for the Users field
(ly4k's approach), not a raw `:` type as in topotam's version. The raw type
causes marshalling errors on some targets.

**EFS activation** — call once per target before EFSR attempts, not once per
method call. Suppress all exceptions silently.

**Success detection** — do not catch all exceptions and call it success. Check
specific error codes per method as documented in `coerce_plus.py`'s
`handle_exception()` and ly4k's helper functions.

**MS-WSP server applicability** — Windows Search Service is disabled by default
on Windows Server since Server 2016. Warn the user if they explicitly target
MS-WSP against what appears to be a server. Only reliable against workstations.

**MS-PAR structures** — do not guess the pipe name or UUID. Read them directly
from the p0dalirius PoC at:
`windows-coerced-authentication-methods/methods/MS-PAR - Print System
Asynchronous Remote Protocol/00. Remote call to RpcAsyncOpenPrinter
(opnum 0)/coerce_poc.py`

---

## Out of Scope: DCOM Interactive User Coercion

RemoteMonologue implements three additional DCOM objects that coerce
**interactive user session** auth rather than machine account auth:

| DCOM Object | CLSID | Mechanism | Auth Type |
|---|---|---|---|
| ServerDataCollectorSet | `03837546-098b-11d8-9414-505054503030` | `DataManager.Extract(CabFilename=\\listener\...)` | Interactive user |
| FileSystemImage | `2C941FC5-975B-59BE-A960-9A2A262853A5` | Set `WorkingDirectory = \\listener\...` | Interactive user |
| MSTSWebProxy | `B43A0C1E-B63F-4691-B68F-CD807A45DA01` | `StartRemoteDesktop(\\listener\...)` | Interactive user |

These are explicitly out of scope for this tool because:
- They require modifying the AppID `RunAs` registry key via Remote Registry
  to `Interactive User` — a separate prerequisite beyond just having local admin
- They capture a specific logged-on user's credentials, not the machine account
- This is a different goal from authentication coercion for relay purposes

These belong in RemoteMonologue as a separate tool. If an operator has local
admin and wants to coerce a specific logged-on user (e.g. a DA with an active
session), they should use RemoteMonologue directly rather than this tool.

---

The `windows-coerced-authentication-methods/possible-working-calls/` directory
contains unconfirmed/situational methods across many additional protocols:

| Protocol | Notable Functions | Condition |
|---|---|---|
| MS-NRPC | Multiple Netlogon functions | DC only |
| MS-SRVS | Many Server Service functions | Requires file server role |
| MS-DNSP | DNS Server Management functions | DNS server only |
| MS-FAX | Fax service functions | Fax server only |
| MS-TSCH | Task Scheduler functions | Task Scheduler running |
| MS-SWN | WitnessrRegisterEx | Cluster witness service |
| MS-DHCPM | Database backup/restore | DHCP server only |
| MS-CMRP | Cluster API functions | Failover cluster only |

These are not worth implementing initially — they are situational, require
specific server roles, and are largely untested. Flag as future work with a
`--experimental` flag once the confirmed methods are solid.

