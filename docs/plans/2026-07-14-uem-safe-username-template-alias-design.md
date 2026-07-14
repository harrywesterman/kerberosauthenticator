# UEM-safe username template alias

## Problem

Some UEM products interpret `{username}` as their own lookup value before Android application restrictions are delivered. As a result, the existing `${username}` placeholder can arrive as only `$`, while the colon-containing `${username:last:1}` placeholder remains intact.

## Design

Add `${username:full}` as an explicit alias for `${username}` in managed share starting-folder templates. Both placeholders resolve to the authenticated Kerberos account name. `${username:last:1}` remains unchanged and continues to require a username ending in an ASCII digit.

The template language remains deliberately small: all other placeholders are rejected. Existing static paths and `${username}` configurations remain backward compatible.

For UEM deployments that consume `{username}`, document this safe form:

```text
users/${username:last:1}/${username:full}
```

Forward slashes are accepted because managed paths normalize them to SMB separators.

## Verification

Add a focused unit test that first fails because `${username:full}` is unsupported, then implement the alias and rerun the focused and complete test suites. Build the release APK with JDK 17, publish it through the existing signed-release workflow, install it in place on the managed device, and verify the delivered restriction and the H-share directory load.
