package com.poelbos.kerberosauthenticator.internal.ntlm;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import org.junit.Test;

public final class NtlmIdentityTest {
  @Test
  public void acceptsPlainSamAccountName() {
    NtlmIdentity identity = NtlmIdentity.parse("alex", "EXAMPLE.COM", "EXAMPLE");

    assertThat(identity.getUsername()).isEqualTo("alex");
    assertThat(identity.getDomain()).isEqualTo("EXAMPLE");
  }

  @Test
  public void acceptsMatchingDownLevelIdentity() {
    NtlmIdentity identity = NtlmIdentity.parse("example\\alex", "EXAMPLE.COM", "EXAMPLE");

    assertThat(identity.getUsername()).isEqualTo("alex");
    assertThat(identity.getDomain()).isEqualTo("EXAMPLE");
  }

  @Test
  public void acceptsUpnForConfiguredRealm() {
    NtlmIdentity identity =
        NtlmIdentity.parse("alex@example.com", "EXAMPLE.COM", "EXAMPLE");

    assertThat(identity.getUsername()).isEqualTo("alex");
  }

  @Test
  public void rejectsConflictingDomainOrRealm() {
    assertThrows(
        IllegalArgumentException.class,
        () -> NtlmIdentity.parse("OTHER\\alex", "EXAMPLE.COM", "EXAMPLE"));
    assertThrows(
        IllegalArgumentException.class,
        () -> NtlmIdentity.parse("alex@other.example", "EXAMPLE.COM", "EXAMPLE"));
  }

  @Test
  public void rejectsMalformedIdentity() {
    assertThrows(
        IllegalArgumentException.class,
        () -> NtlmIdentity.parse("EXAMPLE\\", "EXAMPLE.COM", "EXAMPLE"));
    assertThrows(
        IllegalArgumentException.class,
        () -> NtlmIdentity.parse("a@b@c", "EXAMPLE.COM", "EXAMPLE"));
  }
}
