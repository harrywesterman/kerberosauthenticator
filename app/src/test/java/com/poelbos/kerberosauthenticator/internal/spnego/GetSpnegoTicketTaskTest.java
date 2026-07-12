/*
 * Copyright 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package com.poelbos.kerberosauthenticator.internal.spnego;

import static com.google.common.truth.Truth.assertThat;

import java.util.Arrays;
import org.junit.Test;
import org.ietf.jgss.GSSException;

public final class GetSpnegoTicketTaskTest {
  @Test
  public void continuationKeepsPreviouslySelectedCandidate() {
    assertThat(
            GetSpnegoTicketTask.candidatesForRound(
                Arrays.asList("requested.example", "backend01.example", "backend02.example"),
                "backend01.example",
                true))
        .containsExactly("backend01.example");
  }

  @Test
  public void firstRoundRetainsCandidateOrder() {
    assertThat(
            GetSpnegoTicketTask.candidatesForRound(
                Arrays.asList("requested.example", "backend01.example"),
                "backend01.example",
                false))
        .containsExactly("requested.example", "backend01.example")
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
}
