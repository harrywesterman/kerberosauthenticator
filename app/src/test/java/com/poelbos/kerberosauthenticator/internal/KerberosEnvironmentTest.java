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
                "mobiel.int.politie", "POLITIE.LOCAL"))
        .isEqualTo("INT.POLITIE");
  }

  @Test
  public void inferRealmFromServiceHostSkipsDefaultRealmAndIpAddresses() {
    assertThat(
            KerberosEnvironment.inferRealmFromServiceHost(
                "intranet.politie.local", "POLITIE.LOCAL"))
        .isNull();
    assertThat(KerberosEnvironment.inferRealmFromServiceHost("10.151.17.27", "POLITIE.LOCAL"))
        .isNull();
  }

  @Test
  public void buildKrb5ConfigAddsServiceDomainRealmMapping() {
    String config =
        KerberosEnvironment.buildKrb5Config(
            "POLITIE.LOCAL",
            "dc01.politie.local dc02.politie.local",
            "mobiel.int.politie",
            "INT.POLITIE",
            "dc01.int.politie");

    assertThat(config).contains("default_realm = POLITIE.LOCAL");
    assertThat(config).contains("POLITIE.LOCAL = {");
    assertThat(config).contains("kdc = dc01.politie.local");
    assertThat(config).contains("kdc = dc02.politie.local");
    assertThat(config).contains("INT.POLITIE = {");
    assertThat(config).contains("kdc = dc01.int.politie");
    assertThat(config).contains(".int.politie = INT.POLITIE");
    assertThat(config).contains("int.politie = INT.POLITIE");
  }
}
