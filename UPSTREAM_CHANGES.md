# Upstream Tool Changes to Integrate

Changes found during a review on 2026-03-18 in third-party tools that may be
worth integrating into bigpotam.

**Source repos are local working copies** — delete them once changes
have been integrated. The repos there have local-only modifications that are NOT
pushed anywhere.

## petitpotam (topotam/PetitPotam) — tools/petitpotam

- Added TCP RPC transport support (`ncacn_ip_tcp`) via `-pipe tcp_lsarpc` / `-pipe tcp_efsr`
- New `-tcp-port` argument for specifying RPC TCP port (from rpcdump output)
- Switched default coercion from `EfsRpcOpenFileRaw` to `EfsRpcEncryptFileSrv` (bypasses patch)
- Added standalone `PetitPotam_encrypt_only.py` script
- These changes allow coercion through direct RPC TCP instead of only named pipes over SMB

## PetitPotam (ly4k/PetitPotam) — tools/PetitPotam

- Same TCP RPC transport addition as above (`tcp_lsarpc`, `tcp_efsr` pipe options)
- Removed port restriction to 139/445, now accepts any port for TCP RPC
- Conditional logic: named pipe transports use SMB port, tcp_* transports use the specified port directly

## rpc2efs (Hypnoze57/rpc2efs) — tools/rpc2efs

- Rewrote to use named pipes (`ncacn_np`) over SMB instead of `ncacn_ip_tcp`
- Reason: TCP RPC gets empty responses through proxychains/SOCKS proxies
- Tries both `\efsrpc` and `\lsarpc` named pipes
- Removed dependency on `impacket.dcerpc.v5.epm` and `dcomrt`

## wspcoerce (RedTeamPentesting/wspcoerce) — tools/wspcoerce

- Added fallback import logic so the tool runs both as an installed package and standalone
- `try/except ModuleNotFoundError` for relative vs absolute imports in cli.py and packets.py
