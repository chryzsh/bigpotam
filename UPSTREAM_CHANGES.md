# Upstream Tool Changes to Integrate

Changes found during a review on 2026-03-18 in third-party tools that may be
worth integrating into bigpotam.

**Source repos are local working copies** — delete them once changes
have been integrated. The repos there have local-only modifications that are NOT
pushed anywhere.

## petitpotam (topotam/PetitPotam) — tools/petitpotam [done]

- Added TCP RPC transport support (`ncacn_ip_tcp`) via `-pipe tcp_lsarpc` / `-pipe tcp_efsr`
- New `-tcp-port` argument for specifying RPC TCP port (from rpcdump output)
- Switched default coercion from `EfsRpcOpenFileRaw` to `EfsRpcEncryptFileSrv` (bypasses patch)
- Added standalone `PetitPotam_encrypt_only.py` script
- These changes allow coercion through direct RPC TCP instead of only named pipes over SMB
- Result: integrated direct TCP EFSRPC support in `bigpotam` via commit `1bc26ca`
- Notes: `bigpotam` already defaulted to `EfsRpcEncryptFileSrv`; no standalone helper script was added

## PetitPotam (ly4k/PetitPotam) — tools/PetitPotam [done]

- Same TCP RPC transport addition as above (`tcp_lsarpc`, `tcp_efsr` pipe options)
- Removed port restriction to 139/445, now accepts any port for TCP RPC
- Conditional logic: named pipe transports use SMB port, tcp_* transports use the specified port directly
- Result: reviewed, no additional code changes needed after `1bc26ca`
- Notes: `bigpotam` now applies the same transport split by keeping SMB on `-port` and direct EFSRPC on `-tcp-port`

## rpc2efs (Hypnoze57/rpc2efs) — tools/rpc2efs [done]

- Rewrote to use named pipes (`ncacn_np`) over SMB instead of `ncacn_ip_tcp`
- Reason: TCP RPC gets empty responses through proxychains/SOCKS proxies
- Tries both `\efsrpc` and `\lsarpc` named pipes
- Removed dependency on `impacket.dcerpc.v5.epm` and `dcomrt`
- Result: integrated named-pipe-first EFS auto-activation fallback in commit `436d5e1`

## wspcoerce (RedTeamPentesting/wspcoerce) — tools/wspcoerce [done]

- Added fallback import logic so the tool runs both as an installed package and standalone
- `try/except ModuleNotFoundError` for relative vs absolute imports in cli.py and packets.py
- Result: reviewed, no `bigpotam` code changes needed
- Notes: the local diff only affects package/standalone import behavior in `wspcoerce`; `bigpotam` embeds the WSP logic directly
