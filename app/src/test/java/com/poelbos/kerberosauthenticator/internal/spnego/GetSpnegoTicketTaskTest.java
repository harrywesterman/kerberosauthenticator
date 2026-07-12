/*
 * Copyright 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package com.poelbos.kerberosauthenticator.internal.spnego;

import static com.google.common.truth.Truth.assertThat;

import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;
import org.ietf.jgss.GSSException;

public final class GetSpnegoTicketTaskTest {
  @Test
  public void continuationCandidatesResumeAfterPreviousFallback() {
    assertThat(
            GetSpnegoTicketTask.resumeCandidatesAfter(
                Arrays.asList("requested.example", "backend01.example", "backend02.example"),
                "backend01.example"))
        .containsExactly("backend02.example", "requested.example", "backend01.example")
        .inOrder();
  }

  @Test
  public void onlyUnknownPrincipalErrorsPermitAnotherCandidate() {
    GSSException unknown = new GSSException(GSSException.FAILURE);
    unknown.initCause(new Exception("KDC_ERR_S_PRINCIPAL_UNKNOWN"));
    GSSException wrongKey = new GSSException(GSSException.FAILURE);
    wrongKey.initCause(new Exception("Checksum failed"));

    assertThat(GetSpnegoTicketTask.isUnknownPrincipal(unknown)).isTrue();
    assertThat(GetSpnegoTicketTask.isUnknownPrincipal(wrongKey)).isFalse();
  }

  @Test
  public void removesDirectCandidatesFromLdapFallback() {
    assertThat(
            GetSpnegoTicketTask.untriedCandidates(
                Arrays.asList("alias.example.test", "canonical.example.test", "ldap.example.test"),
                Arrays.asList("alias.example.test", "canonical.example.test")))
        .containsExactly("ldap.example.test")
        .inOrder();
  }

  @Test
  public void acceptsEmptyAttemptedSetForLdapFallback() {
    assertThat(
            GetSpnegoTicketTask.untriedCandidates(
                Arrays.asList("canonical.example.test"), Collections.<String>emptyList()))
        .containsExactly("canonical.example.test");
  }
}
