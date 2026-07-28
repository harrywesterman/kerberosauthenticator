# Managed Username Prefill Design

## Goal

Restore the UEM-managed `username` application restriction as an editable default throughout
the app, and take users without an existing Kerberos account directly to sign-in when the app is
opened.

## Managed configuration

Add `username` back to `app_restrictions.xml` as an optional string restriction. UEM can populate
it with the enrolled user's Active Directory username. `AccountConfiguration` reads and trims the
value while continuing to require only the managed AD realm for a valid deployment. A missing,
blank, or whitespace-only username remains valid and produces an empty editable field.

The managed username is a convenience value, not an enforced identity. The password remains
user-entered and is never added to the managed enterprise configuration.

## Login behavior

Both login presentations use the same username precedence:

1. an existing Kerberos account name;
2. the managed `username` value;
3. an empty field.

This applies to the Material account sign-in destination and the legacy authenticator prompt used
by Android or Chrome authentication flows. In both cases the user may edit the prefilled value
before submitting credentials.

When the launcher activity is opened without an existing Kerberos account and a managed realm is
available, it starts the account sign-in destination once for that launcher-activity instance.
Going back remains possible and reveals the files overview. A later cold app start without an
account offers sign-in again. If the managed realm is missing, the existing configuration-required
state remains visible instead of opening an unusable sign-in form.

## Data flow and safety

`RestrictionsManager` remains the single source for managed identity defaults.
`AccountConfiguration` owns normalization and exposes the optional username through the existing
`KerberosAccountDetails`. Login activities only render that value and continue to authenticate
with the final text entered by the user.

No username is logged as part of the new flow, and no credential-storage behavior changes. A
managed configuration update is picked up through the existing application-restrictions broadcast
receiver.

## Testing

Robolectric and resource tests cover:

- the `username` restriction being present in the published managed-configuration schema;
- reading and trimming a managed username;
- treating blank managed values as absent without invalidating the managed realm;
- prefilling both account and authenticator login fields;
- preferring an existing account name over the managed default;
- keeping prefilled fields editable and authenticating with the user's final value;
- automatically opening account sign-in from the launcher when no account exists;
- not redirecting when an account exists or the managed realm is missing.

Run the focused tests and complete unit-test suite with JDK 17, then assemble the APK locally. As
this behavior needs verification on a managed Android device, commit and push the verified
implementation to `main`, wait for the signed GitHub release, install its release APK in place, and
verify the UEM-delivered username and Chrome SPNEGO flow using non-sensitive logs.
