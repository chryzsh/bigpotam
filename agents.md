# BigPotam — Agent Working Guidelines

## Project Overview

BigPotam is a unified NTLM authentication coercion tool written in Python. It consolidates coercion primitives across 8 protocols (MS-EFSR, MS-RPRN, MS-PAR, MS-DFSNM, MS-FSRVP, MS-EVEN, MS-WSP, DCOM) into a single tool.

## Repository Structure

```
bigpotam.py                  # CLI entry point (argparse, main loop, banner)
bigpotam/
  __init__.py
  logger.py                  # Colored output with -ts timestamp support
  connection.py              # connect_rpc(), connect_smb(), activate_efs()
  paths.py                   # Per-protocol path formatting (SMB + WebDAV)
  structures.py              # All NDR structure definitions
  registry.py                # Ordered METHODS list (26 entries)
  wsp.py                     # MS-WSP binary protocol packets + trigger
  methods/
    efsr.py                  # 11 MS-EFSR trigger functions
    rprn.py                  # MS-RPRN opnum 62/65 + MS-PAR trigger
    dfsnm.py                 # 6 MS-DFSNM trigger functions
    fsrvp.py                 # 2 MS-FSRVP trigger functions
    even.py                  # MS-EVEN ElfrOpenBELW trigger
    dcom.py                  # DCOM UpdateSession trigger
plan.md                      # Original design plan with full method table
ref/                         # Reference repos (gitignored, not committed)
```

## Key Dependency

The only external dependency is `impacket`. All RPC structures, triggers, and connection logic use impacket's DCE/RPC stack.

## Commit Policy

**Commit every change.** Every modification — bug fix, feature addition, refactor, documentation update — gets its own commit immediately after the change is made. Do not batch multiple unrelated changes into a single commit.

## How to Add a New Coercion Method

1. Add NDR structures to `bigpotam/structures.py` if not already present
2. Add a path formatter to `bigpotam/paths.py` if the protocol needs a unique format
3. Create a trigger function in the appropriate `bigpotam/methods/<protocol>.py` file
4. Register the method in `bigpotam/registry.py` in the correct position in the `METHODS` list
5. Update `README.md` method count and table if needed

## How Trigger Functions Work

Every trigger function follows this signature:

```python
def trigger_<name>(dce, listener, listener_port=445, **kw):
```

- `dce`: bound DCE/RPC session (from `connect_rpc()`)
- `listener`: attacker IP/hostname
- `listener_port`: 445 for SMB, 80 for WebDAV — controls path format
- `**kw`: may contain `target` (needed by RPRN for RpcOpenPrinter handle)
- Returns `True` on success, `False` on failure
- Checks protocol-specific error codes for success (e.g. ERROR_BAD_NETPATH means coercion fired)

WSP and DCOM have their own connection flows and don't use the standard `connect_rpc()` path.

## Protocol-Specific Gotchas

- **EFSR UUID varies by pipe**: `efsrpc` pipe uses `df1941c5-...`, all others use `c681d488-...`
- **RPRN requires RpcOpenPrinter** handle before calling notification functions
- **MS-EVEN** uses `\\??\UNC\` device path, not standard UNC
- **MS-WSP** uses `file:////` URI with forward slashes, binary protocol (not DCE/RPC)
- **DCOM UpdateSession** connects via port 135/DCOM, entirely separate from named pipe logic
- **ENCRYPTION_CERTIFICATE_LIST** uses `NDRPOINTERNULL` for Users field (ly4k's approach)

## Testing

No automated tests yet. Test against a Windows target with:

```bash
# Quick smoke test — should show all 26 methods registered
python3 -c "from bigpotam.registry import METHODS; print(len(METHODS))"

# Help output
python3 bigpotam.py -h

# Live test against a target
python3 bigpotam.py domain/user:password@target 10.0.0.5 -debug
```
