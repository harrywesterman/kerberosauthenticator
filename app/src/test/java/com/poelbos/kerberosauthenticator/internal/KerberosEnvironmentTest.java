/*
 * Copyright 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package com.poelbos.kerberosauthenticator.internal;

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;

public final class KerberosEnvironmentTest {
  @Test
  public void inferRealmFromServiceHostUsesDnsDomain() {
    assertThat(
            KerberosEnvironment.inferRealmFromServiceHost(
                "portal.int.example", "EXAMPLE.LOCAL"))
        .isEqualTo("INT.EXAMPLE");
  }

  @Test
  public void inferRealmFromServiceHostUsesLongerDnsSuffix() {
    assertThat(
            KerberosEnvironment.inferRealmFromServiceHost(
                "portal.int.example.local", "EXAMPLE.LOCAL"))
        .isEqualTo("INT.EXAMPLE.LOCAL");
  }

  @Test
  public void inferRealmFromServiceHostUsesExampleInternalDomain() {
    assertThat(
            KerberosEnvironment.inferRealmFromServiceHost(
                "portal.int.example", "EXAMPLE.LOCAL"))
        .isEqualTo("INT.EXAMPLE");
  }

  @Test
  public void preferDiscoveredServiceRealmUsesDnsResultWhenDifferentFromDefault() {
    assertThat(
            KerberosEnvironment.preferDiscoveredServiceRealm(
                "INT.EXAMPLE", "EXAMPLE.LOCAL"))
        .isEqualTo("INT.EXAMPLE");
    assertThat(
            KerberosEnvironment.preferDiscoveredServiceRealm(
                "EXAMPLE.LOCAL", "EXAMPLE.LOCAL"))
        .isNull();
    assertThat(KerberosEnvironment.preferDiscoveredServiceRealm(null, "EXAMPLE.LOCAL"))
        .isNull();
  }

  @Test
  public void inferRealmFromServiceHostSkipsDefaultRealmAndIpAddresses() {
    assertThat(
            KerberosEnvironment.inferRealmFromServiceHost(
                "intranet.example.local", "EXAMPLE.LOCAL"))
        .isNull();
    assertThat(KerberosEnvironment.inferRealmFromServiceHost("10.151.17.27", "EXAMPLE.LOCAL"))
        .isNull();
  }

  @Test
  public void buildKrb5ConfigAddsServiceDomainRealmMapping() {
    String config =
        KerberosEnvironment.buildKrb5Config(
            "EXAMPLE.LOCAL",
            "dc01.example.local dc02.example.local",
            "portal.int.example",
            "INT.EXAMPLE",
            "dc01.int.example");

    assertThat(config).contains("default_realm = EXAMPLE.LOCAL");
    assertThat(config).contains("EXAMPLE.LOCAL = {");
    assertThat(config).contains("kdc = dc01.example.local");
    assertThat(config).contains("kdc = dc02.example.local");
    assertThat(config).contains("INT.EXAMPLE = {");
    assertThat(config).contains("kdc = dc01.int.example");
    assertThat(config).contains(".int.example = INT.EXAMPLE");
    assertThat(config).contains("int.example = INT.EXAMPLE");
  }
}
