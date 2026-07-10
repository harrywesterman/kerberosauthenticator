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
  public void serviceTicketCandidatesKeepOnlyTheRequestedHostWithoutDiscoveryData() {
    assertThat(GetSpnegoTicketTask.serviceTicketCandidates("Service.Example.Internal."))
        .containsExactly("service.example.internal")
        .inOrder();
  }

  @Test
  public void serviceTicketCandidatesKeepIpAddressExact() {
    assertThat(GetSpnegoTicketTask.serviceTicketCandidates("10.151.17.27"))
        .containsExactly("10.151.17.27");
  }

  @Test
  public void serviceTicketCandidatesUseDnsAliasesBeforeCertificateDnsNames() {
    assertThat(
            GetSpnegoTicketTask.serviceTicketCandidates(
                "app.example.internal",
                Arrays.asList("alias.example.local"),
                Arrays.asList(
                    "app.example.internal",
                    "web01.example.local",
                    "web02.example.local")))
        .containsExactly(
            "app.example.internal",
            "alias.example.local",
            "web01.example.local",
            "web02.example.local")
        .inOrder();
  }

  @Test
  public void serviceTicketCandidatesUseLdapDnsNamesAfterDnsAndCertificateCandidates() {
    assertThat(
            GetSpnegoTicketTask.serviceTicketCandidates(
                "app.example.internal",
                Arrays.asList("alias.example.local"),
                Arrays.asList("app.example.internal"),
                Arrays.asList("auth01.example.local", "auth02.example.local")))
        .containsExactly(
            "app.example.internal",
            "alias.example.local",
            "auth01.example.local",
            "auth02.example.local")
        .inOrder();
  }

  @Test
  public void continuationCandidatesResumeAfterPreviousFallback() {
    assertThat(
            GetSpnegoTicketTask.resumeCandidatesAfter(
                Arrays.asList("requested.example", "backend01.example", "backend02.example"),
                "backend01.example"))
        .containsExactly("backend02.example", "requested.example", "backend01.example")
        .inOrder();
  }
}
