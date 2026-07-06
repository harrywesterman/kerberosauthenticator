/*
 * Copyright 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package com.poelbos.kerberosauthenticator.internal;

import static com.google.common.truth.Truth.assertThat;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

public final class LdapSpnDiscoveryTest {
  @Test
  public void baseDnForRealmUsesDomainComponents() {
    assertThat(LdapSpnDiscovery.baseDnForRealm("POLITIE.LOCAL"))
        .isEqualTo("DC=POLITIE,DC=LOCAL");
  }

  @Test
  public void ldapHostsStripsKerberosPorts() {
    assertThat(LdapSpnDiscovery.ldapHosts("dc01.politie.local:88 dc02.politie.local"))
        .containsExactly("dc01.politie.local", "dc02.politie.local")
        .inOrder();
  }

  @Test
  public void searchTermsIncludeHostAndFirstLabel() {
    assertThat(LdapSpnDiscovery.searchTerms("Mobiel.Int.Politie."))
        .containsExactly("mobiel.int.politie", "mobiel")
        .inOrder();
  }

  @Test
  public void bindNamesIncludeUpnDownLevelAndShortForms() {
    assertThat(LdapSpnDiscovery.bindNames("ISC75972", "POLITIE.LOCAL"))
        .containsExactly("ISC75972@POLITIE.LOCAL", "POLITIE\\ISC75972", "ISC75972")
        .inOrder();
  }

  @Test
  public void bindRequestIsLdapBindMessage() throws Exception {
    byte[] request = LdapSpnDiscovery.buildBindRequest(7, "ISC75972@POLITIE.LOCAL", "secret");

    LdapSpnDiscovery.LdapMessage message = LdapSpnDiscovery.parseMessage(request);

    assertThat(message.messageId).isEqualTo(7);
    assertThat(message.protocolOpTag).isEqualTo(0x60);
    assertThat(asLatin1(request)).contains("ISC75972@POLITIE.LOCAL");
    assertThat(asLatin1(request)).contains("secret");
  }

  @Test
  public void searchRequestContainsSpnFiltersAndAttributes() throws Exception {
    byte[] request =
        LdapSpnDiscovery.buildSearchRequest(8, "DC=POLITIE,DC=LOCAL", "Mobiel.Int.Politie.");

    LdapSpnDiscovery.LdapMessage message = LdapSpnDiscovery.parseMessage(request);

    assertThat(message.messageId).isEqualTo(8);
    assertThat(message.protocolOpTag).isEqualTo(0x63);
    String requestText = asLatin1(request);
    assertThat(requestText).contains("DC=POLITIE,DC=LOCAL");
    assertThat(requestText).contains("HTTP/mobiel.int.politie");
    assertThat(requestText).contains("servicePrincipalName");
    assertThat(requestText).contains("sAMAccountName");
  }

  @Test
  public void rootDseRequestContainsDiscoveryAttributes() throws Exception {
    byte[] request = LdapSpnDiscovery.buildRootDseRequest(9);

    LdapSpnDiscovery.LdapMessage message = LdapSpnDiscovery.parseMessage(request);

    assertThat(message.messageId).isEqualTo(9);
    assertThat(message.protocolOpTag).isEqualTo(0x63);
    String requestText = asLatin1(request);
    assertThat(requestText).contains("objectClass");
    assertThat(requestText).contains("defaultNamingContext");
    assertThat(requestText).contains("supportedSASLMechanisms");
  }

  @Test
  public void parseLdapResultCodeReadsBindSuccess() throws Exception {
    LdapSpnDiscovery.LdapMessage message =
        LdapSpnDiscovery.parseMessage(
            ldapMessage(1, element(0x61, concat(enumerated(0), octet(""), octet("")))));

    assertThat(LdapSpnDiscovery.parseLdapResultCode(message.protocolOpValue)).isEqualTo(0);
  }

  @Test
  public void parseSearchResultEntryReadsSpnAttributes() throws Exception {
    byte[] entry =
        ldapMessage(
            2,
            element(
                0x64,
                concat(
                    octet("CN=web,CN=Users,DC=POLITIE,DC=LOCAL"),
                    sequence(
                        attribute("sAMAccountName", "svc-web"),
                        attribute("dNSHostName", "web01.politie.local"),
                        attribute(
                            "servicePrincipalName",
                            "HTTP/mobiel.int.politie",
                            "HTTP/web01.politie.local")))));

    LdapSpnDiscovery.LdapMessage message = LdapSpnDiscovery.parseMessage(entry);
    LdapSpnDiscovery.SearchResult result =
        LdapSpnDiscovery.parseSearchResultEntry(message.protocolOpValue);

    assertThat(result.getDistinguishedName()).isEqualTo("CN=web,CN=Users,DC=POLITIE,DC=LOCAL");
    assertThat(result.getAccountName()).isEqualTo("svc-web");
    assertThat(result.getDnsHostName()).isEqualTo("web01.politie.local");
    assertThat(result.getServicePrincipalNames())
        .containsExactly("HTTP/mobiel.int.politie", "HTTP/web01.politie.local")
        .inOrder();
  }

  private static String asLatin1(byte[] bytes) {
    return new String(bytes, StandardCharsets.ISO_8859_1);
  }

  private static byte[] ldapMessage(int messageId, byte[] protocolOp) {
    return sequence(integer(messageId), protocolOp);
  }

  private static byte[] attribute(String name, String... values) {
    ByteArrayOutputStream valueSet = new ByteArrayOutputStream();
    for (String value : values) {
      byte[] encoded = octet(value);
      valueSet.write(encoded, 0, encoded.length);
    }
    return sequence(octet(name), element(0x31, valueSet.toByteArray()));
  }

  private static byte[] sequence(byte[]... values) {
    return element(0x30, concat(values));
  }

  private static byte[] integer(int value) {
    return element(0x02, new byte[] {(byte) value});
  }

  private static byte[] enumerated(int value) {
    return element(0x0a, new byte[] {(byte) value});
  }

  private static byte[] octet(String value) {
    return element(0x04, value.getBytes(StandardCharsets.UTF_8));
  }

  private static byte[] element(int tag, byte[] value) {
    return LdapSpnDiscovery.element(tag, value);
  }

  private static byte[] concat(byte[]... values) {
    return LdapSpnDiscovery.concat(values);
  }
}
