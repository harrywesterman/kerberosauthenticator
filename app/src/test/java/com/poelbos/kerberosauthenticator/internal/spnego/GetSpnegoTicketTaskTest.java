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
    assertThat(GetSpnegoTicketTask.serviceTicketCandidates("Mobiel.Int.Politie."))
        .containsExactly(
            "mobiel.int.politie",
            "mobiel.politie.local",
            "mobiel.int.politie.local",
            "mobiel.int.politie.nl",
            "mobiel.politie.nl",
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
                "bvcm-np.politie.local",
                Arrays.asList(
                    "bvcm-np.politie.local",
                    "ELAVSW3520.politie.local",
                    "ELAVSW3521.politie.local")))
        .containsExactly(
            "bvcm-np.politie.local",
            "blue.politie.local",
            "elavsw3520.politie.local",
            "elavsw3521.politie.local",
            "bvcm-np")
        .inOrder();
  }

  @Test
  public void serviceTicketCandidatesIncludeKnownBvcmAlias() {
    assertThat(GetSpnegoTicketTask.serviceTicketCandidates("BVCM-NP.Politie.Local"))
        .containsExactly("bvcm-np.politie.local", "blue.politie.local", "bvcm-np")
        .inOrder();
  }
}
