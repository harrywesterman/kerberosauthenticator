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
  public void serviceTicketCandidatesIncludeGenericCanonicalNames() {
    assertThat(GetSpnegoTicketTask.serviceTicketCandidates("Service.Example.Internal."))
        .containsExactly(
            "service.example.internal",
            "service.example.internal.local",
            "service")
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
            "web02.example.local",
            "app.example.internal.local",
            "app")
        .inOrder();
  }

  @Test
  public void serviceTicketCandidatesUseLdapDnsNamesBeforeGenericAliases() {
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
            "auth02.example.local",
            "app.example.internal.local",
            "app")
        .inOrder();
  }
}
