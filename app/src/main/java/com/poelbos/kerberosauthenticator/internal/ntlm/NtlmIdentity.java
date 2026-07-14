package com.poelbos.kerberosauthenticator.internal.ntlm;

/** Validated NTLM username and NetBIOS domain derived from the signed-in AD identity. */
public final class NtlmIdentity {
  private final String username;
  private final String domain;

  private NtlmIdentity(String username, String domain) {
    this.username = username;
    this.domain = domain;
  }

  public static NtlmIdentity parse(String accountName, String realm, String ntlmDomain) {
    if (accountName == null || realm == null || ntlmDomain == null) {
      throw new IllegalArgumentException("Missing NTLM identity");
    }
    String value = accountName.trim();
    String username = value;
    int slash = value.indexOf('\\');
    int at = value.indexOf('@');
    if (slash >= 0 && at >= 0) throw new IllegalArgumentException("Malformed NTLM identity");
    if (slash >= 0) {
      if (slash != value.lastIndexOf('\\')
          || !value.substring(0, slash).equalsIgnoreCase(ntlmDomain)) {
        throw new IllegalArgumentException("NTLM domain mismatch");
      }
      username = value.substring(slash + 1);
    } else if (at >= 0) {
      if (at != value.lastIndexOf('@')
          || !value.substring(at + 1).equalsIgnoreCase(realm)) {
        throw new IllegalArgumentException("NTLM realm mismatch");
      }
      username = value.substring(0, at);
    }
    if (username.isEmpty() || username.indexOf('\\') >= 0 || username.indexOf('@') >= 0) {
      throw new IllegalArgumentException("Malformed NTLM username");
    }
    return new NtlmIdentity(username, ntlmDomain);
  }

  public String getUsername() { return username; }

  public String getDomain() { return domain; }
}
