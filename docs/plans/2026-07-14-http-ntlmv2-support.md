# HTTP Negotiate with NTLMv2 Implementation Plan

> **For Codex:** REQUIRED SUB-SKILL: Use `executing-plans` and implement each task test-first.

**Goal:** Extend the existing Chrome/Android SPNEGO authenticator so Kerberos remains preferred while managed deployments can opt in to NTLMv2 when a server explicitly selects NTLMSSP inside `WWW-Authenticate: Negotiate`.

**Architecture:** Keep the existing Android account type and Chrome AccountManager contract. Add a versioned, host-bound negotiation state and an HTTP SPNEGO coordinator that routes each round to the existing Kerberos GSS implementation or a new HTTP-specific NTLMv2 engine built on the SMBJ protocol primitives already present in the APK. Direct `WWW-Authenticate: NTLM`, NTLMv1, anonymous/guest authentication, proxy NTLM, and SMB NTLM remain unsupported.

**Tech stack:** Android/Java 17, Android AccountManager, vendored OpenJDK Kerberos GSS, SMBJ SPNEGO/NTLM message primitives, Robolectric/JUnit/Truth.

---

## Task 1: Managed NTLM policy and status

- Add `enable_http_ntlm` (default `false`) and required `ntlm_domain` managed restrictions.
- Validate and normalize the NetBIOS domain without making incomplete NTLM configuration fatal to Kerberos.
- Report disabled, ready, or unavailable NTLM status without exposing identity or credential data.
- Generalize the last HTTP authentication status to include mechanism and safe result category while reading old preferences tolerantly.
- Cover defaults, invalid and valid domains, and vault-unavailable behavior with tests first.

## Task 2: Versioned SPNEGO negotiation state

- Add immutable `HttpSpnegoResult`, `SpnegoNegotiationState`, and `SpnegoStateCodec` types.
- Bind state version 1 to the normalized request host and validate mechanism and phase transitions.
- Store only mechanism/phase, selected Kerberos SPN, exported GSS context, and raw NTLM Type-1 bytes; never store credentials, hashes, session keys, Type-2 challenges, or Type-3 responses.
- Define Chrome SPNEGO result codes 0 and 4-9 and cover round trips, corrupt state, host mismatches, and independent parallel contexts.

## Task 3: Kerberos-first SPNEGO offer

- Wrap the existing Kerberos ticket task behind the coordinator.
- Preserve the existing optimistic Kerberos token and Kerberos OIDs, appending NTLMSSP OID `1.3.6.1.4.1.311.2.2.10` only when policy, domain, and hardware-backed credentials are available.
- Keep Kerberos first and never switch to NTLM because Kerberos failed.
- Carry the selected SPN in request-local state rather than using the global last-service preference for continuation.
- Add regression tests for Kerberos-only output, mechanism ordering, continuation, SPN overrides, and parallel hosts.

## Task 4: HTTP NTLMv2 engine

- Add `NtlmIdentity`, `NtlmCredentialProvider`, and `HttpNtlmV2Engine` with injectable clock and secure randomness.
- Use SMBJ ASN.1/SPNEGO and NTLM message primitives, but do not use its SMB-specific `NtlmAuthenticator`.
- Support server selection of NTLM with or without an immediate Type-2 token, strict Type-2 parsing, a Type-1 response when needed, and a Type-3 NTLMv2 response.
- Require Unicode, NTLM, extended-session-security, and 128-bit flags; do not send workstation or OS version; never produce NTLMv1, LM, guest, or anonymous responses.
- Add `MsvAvTargetName=HTTP/<original-host>`, zero channel bindings when Chrome provides none, and the required MIC.
- Load the password only for Type 3, clear controllable buffers, and never log or persist sensitive protocol material.
- Treat another challenge after Type 3 as invalid credentials without deleting the vault.
- Verify with deterministic Microsoft NTLMv2 vectors and malformed-message tests.

## Task 5: Authenticator integration

- Route `KerberosAuthenticator.getAuthToken()` through `HttpSpnegoCoordinator` after existing Chrome caller and account checks.
- Read and write the existing Chrome `incomingAuthToken` and `spnegoContext` bundle keys.
- Return account name/type, Base64 token, Chrome `spnegoResult`, and continuation state on success; map protocol errors to Chrome result codes.
- Preserve TGT renewal and interactive Kerberos reauthentication. NTLM never prompts for a transient password.
- Record and log only host, phase, selected mechanism, and safe result code.
- Add authenticator tests for successful and failed rounds, malformed identity, host binding, no downgrade, credential retention, and concurrent hosts.

## Task 6: Documentation and verification

- Document managed keys, Chrome policy, Kerberos-first behavior, credential requirements, troubleshooting, and limitations for direct NTLM and Extended Protection requiring non-zero TLS channel binding.
- Verify locally on `main` with JDK 17:

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
export PATH="$JAVA_HOME/bin:$PATH"
./gradlew testDebugUnitTest
./gradlew lintDebug
./gradlew assembleDebug assembleRelease
```

- Make local commits on `main`, push once after verification, wait for `Build and Publish Release`, download `kerberosauthenticator-<version>.apk`, install it with `adb install -r`, and validate Kerberos, Negotiate/NTLMv2, disabled/vault-unavailable, rejected credentials, direct NTLM, and Extended Protection scenarios from non-sensitive logs.

## Assumptions

- NTLMv2 is opt-in and available only inside HTTP Negotiate.
- Chrome's `AuthServerAllowlist` remains the only host allowlist.
- MDM supplies the NetBIOS `ntlm_domain`; it is never inferred.
- SMB remains Kerberos-only and NTLM rejection never automatically deletes credentials.
- Chrome does not pass TLS channel-binding data to the Android authenticator, so servers requiring non-zero CBT remain unsupported.
