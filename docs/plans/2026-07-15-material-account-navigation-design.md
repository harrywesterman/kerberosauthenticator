# Material Account Navigation Design

## Goal

Move account access out of the file-browser action row into a Material 3 overflow menu, provide a focused account sign-in and status experience, and make the managed AD realm the only source of domain configuration.

## Navigation

The enterprise files screen uses a compact Material 3 top app bar. Its trailing overflow button opens a popup menu containing an `Account` item. The existing `Sign in` / `Account` button is removed from the file-browser action row so that row remains dedicated to contextual file actions.

Selecting `Account` opens the account destination regardless of authentication state. Android back navigation returns to the files screen.

## Account states

When signed out, the account destination shows:

- an empty `Username` field;
- an empty password field;
- a primary `Sign in` action.

The user supplies both username and password. The AD realm is read from the `ad_realm` managed app restriction and is never shown as an editable field.

When signed in, the same destination shows the account name, Kerberos ticket status, last automatic refresh, HTTP authentication readiness where applicable, and actions to refresh or sign out.

Signing out removes the Android account, Kerberos tickets, securely stored credentials, remembered user configuration, and local enterprise-file cache. Returning to the signed-out state therefore presents empty username and password fields.

## Managed configuration and errors

The app no longer offers local domain configuration. If the MDM-provided realm is absent or invalid, sign-in is unavailable and the account destination explains that managed account configuration is missing. The user is directed to their administrator rather than offered a domain field.

Credentials continue through the existing Kerberos authentication and hardware-backed credential-vault paths. Chrome SPNEGO and SMB/DFS code paths are not otherwise changed.

## Material presentation

Both the files and account destinations use the existing Material 3 application theme, consistent top app bars, surface colors, typography, spacing, text fields, and buttons. The oversized decorative files header is replaced by the compact app bar so content receives more vertical space. File actions remain visible only while browsing a share.

The overflow control uses the conventional vertical-three-dots affordance at the top right. A navigation drawer is deliberately avoided because a single menu destination does not justify the extra hierarchy.

## Testing

Robolectric tests cover:

- opening the overflow menu and navigating to `Account`;
- the signed-out account state with empty username and password fields;
- validation that username and password are required;
- use of the managed realm without an editable domain field;
- the missing-managed-realm error state;
- the signed-in status state;
- sign-out clearing all user-entered identity data.

The complete unit-test suite and a JDK 17 APK build verify regressions. Because the change must be tested on the managed device, the verified commit is pushed to `main`, the signed release asset is installed in place, and account navigation, sign-in, all managed shares, and Chrome SPNEGO are validated on-device.
