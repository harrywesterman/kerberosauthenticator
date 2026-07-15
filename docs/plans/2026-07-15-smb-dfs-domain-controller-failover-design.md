# SMB DFS domain controller failover

## Goal

Restore access to managed domain-based DFS shares when the first Kerberos server returned by DNS
cannot authenticate SMB, while keeping Kerberos-only SMB, signing, encryption policy, managed paths,
and existing credentials unchanged.

## Root cause

All managed drives use the Active Directory realm itself as their DFS namespace host. The current
SMB bootstrap replaces that namespace with only the first host from Kerberos KDC discovery. SMBJ then
requests `cifs/<selected-host>`. If that host has no matching CIFS service principal, the KDC returns
`KDC_ERR_S_PRINCIPAL_UNKNOWN` (KRB 7) and the app stops even though other domain controllers could
serve the namespace.

## Considered approaches

1. **Discover AD domain controllers and fail over between candidates (selected).** Query the existing
   AD LDAP DC-locator records, try each concrete domain controller with a fresh SMB client, and retain
   the current KDC list as a fallback. This uses servers intended to be domain controllers and removes
   the single-host failure point.
2. **Retry only the existing KDC list.** This is smaller, but a Kerberos server is not necessarily a
   suitable SMB/DFS bootstrap server and may not have a CIFS SPN.
3. **Add a managed bootstrap-host setting.** This gives administrators exact control, but requires a
   UEM schema and policy rollout for information that AD already publishes through DNS.

## Design

`DnsKdcDiscovery` exposes domain-controller discovery based on
`_ldap._tcp.dc._msdcs.<realm>` with `_ldap._tcp.<realm>` as its existing fallback. Results remain
priority ordered and deduplicated. `KerberosSmbClient` uses these candidates only when the managed
share host equals the Kerberos realm; ordinary share hosts retain their current single-host behavior.

Each candidate gets a new `SMBClient` and `Connection`. A failure before SMB authentication completes
may advance to the next candidate when the host is unreachable or when a nested Kerberos error is
KRB 7. Other Kerberos errors stop immediately so account, clock, and policy failures are not hidden.
After authentication succeeds, share and DFS errors are returned directly rather than replayed across
other controllers.

If AD DC-locator discovery yields no candidates, the app falls back to the configured or discovered
KDC hosts already returned by `KerberosEnvironment.configure`. If every candidate fails, the last safe
mapped error is shown. Candidate selection and failover logs contain only server/SPN names and numeric
failure categories; no credentials, tickets, tokens, paths, or file names are logged.

## Testing

Pure unit tests cover candidate normalization and deduplication, domain-namespace versus ordinary-host
selection, KRB 7 detection, retry classification, fallback to KDC candidates, and stopping on other
Kerberos failures. Existing SMB configuration and managed-path tests remain unchanged.

Managed-device verification uses JDK 17 for local tests and assembly, publishes from `main`, installs
only the signed GitHub release APK in place, opens each managed drive, and confirms that existing app
data and credentials remain present. Chrome is then force-stopped, logcat is cleared, and the managed
URL is reproduced to confirm HTTP SPNEGO still requests and selects the expected SPN candidate.
