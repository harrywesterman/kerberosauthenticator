/*
 * Copyright 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package com.poelbos.kerberosauthenticator.internal.spnego;

import static com.google.common.truth.Truth.assertThat;

import java.util.Arrays;
import org.junit.Test;

public final class GetSpnegoTicketTaskTest {
  @Test
  public void serviceTicketCandidatesIncludePoliceCanonicalNames() {
    assertThat(GetSpnegoTicketTask.serviceTicketCandidates("Mobiel.Int.Example."))
        .containsExactly(
            "mobiel.int.example",
            "mobiel.example.local",
            "mobiel.int.example.local",
            "mobiel.int.example.nl",
            "mobiel.example.nl",
            "mobiel")
        .inOrder();
  }

  @Test
  public void serviceTicketCandidatesKeepIpAddressExact() {
    assertThat(GetSpnegoTicketTask.serviceTicketCandidates("10.151.17.27"))
        .containsExactly("10.151.17.27");
  }

  @Test
  public void serviceTicketCandidatesUseCertificateDnsNamesBeforeGenericAliases() {
    assertThat(
            GetSpnegoTicketTask.serviceTicketCandidates(
                "bvcm-np.example.local",
                Arrays.asList(
                    "bvcm-np.example.local",
                    "ELAVSW3520.example.local",
                    "ELAVSW3521.example.local")))
        .containsExactly(
            "bvcm-np.example.local",
            "blue.example.local",
            "elavsw3520.example.local",
            "elavsw3521.example.local",
            "bvcm-np")
        .inOrder();
  }

  @Test
  public void serviceTicketCandidatesIncludeKnownBvcmAlias() {
    assertThat(GetSpnegoTicketTask.serviceTicketCandidates("BVCM-NP.Example.Local"))
        .containsExactly("bvcm-np.example.local", "blue.example.local", "bvcm-np")
        .inOrder();
  }
}
