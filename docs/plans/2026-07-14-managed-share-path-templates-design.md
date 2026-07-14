# Managed share path templates

## Goal

Allow one Android Enterprise managed configuration to open a user-specific directory without embedding organization-specific naming rules in the application.

For an authenticated Kerberos username such as `user12342`, this configuration:

```text
users\${username:last:1}\${username}
```

resolves to:

```text
users\2\user12342
```

The server and SMB share remain fully controlled by the administrator.

## Considered approaches

1. **Inline `start_path` template (selected).** Add a small, deliberately limited template language to the existing managed field. This keeps one UEM assignment for all users and does not make the application aware of any organization's directory names.
2. **Separate prefix and bucketing fields.** Add fields such as `path_prefix` and `username_bucket`. This is easier to validate but hard-codes one directory-layout concept into the schema and becomes awkward for future layouts.
3. **Per-user UEM lookup values or profiles.** Let UEM render the complete path for every enrolled user. This couples the feature to vendor-specific lookup syntax and risks a mismatch between enrollment identity and the Kerberos identity used for SMB.

## Configuration syntax

Templates are supported only in `start_path`:

- `${username}` expands to the complete authenticated Kerberos account name.
- `${username:last:1}` expands to its last character.

No substitutions are allowed in `host` or `share_name`. Literal paths without placeholders retain their current behavior.

## Data flow

Managed configuration continues to parse shares as immutable templates. When a user opens a share, the application obtains the existing Kerberos account name and resolves the share's `start_path`. The resolved path is then passed through the existing path normalization and traversal validation before the SMB client receives it.

The template is resolved at share-open time rather than managed-configuration parse time because the authenticated account may not exist yet when UEM delivers the configuration.

## Validation and errors

- An unknown or malformed placeholder is rejected.
- `${username:last:1}` requires a non-empty username whose final character is an ASCII digit.
- A missing Kerberos account prevents the templated share from opening.
- Expansion cannot bypass the existing `..` path traversal protection.
- User-facing errors describe the invalid managed path without logging or displaying credentials.

## Compatibility

Existing static `start_path` values behave exactly as before. UEM administrators opt in by placing a supported placeholder in the field. The feature contains no domain, server, share, directory-prefix, or username-format constant specific to an organization; only the administrator-supplied literal `users` appears in the example configuration.

## Testing

Unit tests cover:

- expansion of both supported placeholders;
- unchanged static paths;
- rejection of unknown or malformed placeholders;
- rejection of a non-numeric final username character for `username:last:1`;
- normalization and traversal validation after expansion;
- activity/client integration using the resolved path rather than the template.

Managed-device verification uses a generic UEM template, installs the signed GitHub release in place, and confirms that the expected share opens while stored credentials remain intact.
