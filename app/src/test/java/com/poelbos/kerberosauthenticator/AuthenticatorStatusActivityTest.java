package com.poelbos.kerberosauthenticator;

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;

public final class AuthenticatorStatusActivityTest {
  @Test
  public void httpNtlmStatusExplainsPolicyAndCredentialReadiness() {
    assertThat(AuthenticatorStatusActivity.httpNtlmStatus(false, false, false))
        .isEqualTo("HTTP NTLMv2: disabled by policy");
    assertThat(AuthenticatorStatusActivity.httpNtlmStatus(true, false, false))
        .isEqualTo("HTTP NTLMv2: unavailable (invalid NTLM domain)");
    assertThat(AuthenticatorStatusActivity.httpNtlmStatus(true, true, false))
        .isEqualTo("HTTP NTLMv2: unavailable (secure credentials missing)");
    assertThat(AuthenticatorStatusActivity.httpNtlmStatus(true, true, true))
        .isEqualTo(
            "HTTP NTLMv2: ready; TLS channel binding unavailable (Extended Protection unsupported)");
  }
}
