package com.poelbos.kerberosauthenticator.internal.ntlm;

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;

public final class NtlmCredentialProviderTest {
  @Test
  public void availabilityCheckClearsLoadedCredential() {
    char[] secret = "Password".toCharArray();
    NtlmCredentialProvider provider = new NtlmCredentialProvider((username, realm) -> secret);

    assertThat(provider.isAvailable("alex", "EXAMPLE.COM")).isTrue();
    assertThat(secret).asList().containsExactly('\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0');
  }

  @Test
  public void missingVaultCredentialIsUnavailable() {
    NtlmCredentialProvider provider = new NtlmCredentialProvider((username, realm) -> null);

    assertThat(provider.isAvailable("alex", "EXAMPLE.COM")).isFalse();
    assertThat(provider.load("alex", "EXAMPLE.COM")).isNull();
  }
}
