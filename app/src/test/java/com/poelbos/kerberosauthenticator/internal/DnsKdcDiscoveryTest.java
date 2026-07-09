/*
 * Copyright 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package com.poelbos.kerberosauthenticator.internal;

import static com.google.common.truth.Truth.assertThat;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 26)
public class DnsKdcDiscoveryTest {
  @Test
  public void testParseSrvResponseReturnsHostsInPriorityOrder() throws Exception {
    byte[] response = buildResponse();

    List<String> hosts = DnsKdcDiscovery.parseSrvResponse(response, 0x1234);

    assertThat(hosts).containsExactly("dc01.example.com", "dc02.example.com").inOrder();
  }

  @Test
  public void testParseSrvResponseAcceptsConfiguredSrvPort() throws Exception {
    byte[] response = buildLdapResponse();

    List<String> hosts = DnsKdcDiscovery.parseSrvResponse(response, 0x1234, 389);

    assertThat(hosts).containsExactly("ldap01.example.com", "ldap02.example.com").inOrder();
  }

  @Test
  public void testParseTxtResponseReturnsRealmStrings() throws Exception {
    byte[] response = buildTxtResponse("INT.EXAMPLE");

    List<String> realms = DnsKdcDiscovery.parseTxtResponse(response, 0x1234);

    assertThat(realms).containsExactly("INT.EXAMPLE");
  }

  @Test
  public void testKerberosRealmLookupNamesUseHostSuffixes() {
    List<String> lookupNames = DnsKdcDiscovery.kerberosRealmLookupNames("portal.int.example");

    assertThat(lookupNames)
        .containsExactly(
            "_kerberos.portal.int.example", "_kerberos.int.example", "_kerberos.example")
        .inOrder();
  }

  @Test
  public void testParseCnameResponseReturnsAliases() throws Exception {
    byte[] response = buildCnameResponse("web01.example.local");

    List<String> aliases = DnsKdcDiscovery.parseCnameResponse(response, 0x1234);

    assertThat(aliases).containsExactly("web01.example.local");
  }

  @Test
  public void testParsePtrResponseReturnsHostNames() throws Exception {
    byte[] response = buildPtrResponse("web01.example.local");

    List<String> hosts = DnsKdcDiscovery.parsePtrResponse(response, 0x1234);

    assertThat(hosts).containsExactly("web01.example.local");
  }

  private static byte[] buildResponse() throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeShort(out, 0x1234);
    writeShort(out, 0x8180);
    writeShort(out, 1);
    writeShort(out, 2);
    writeShort(out, 0);
    writeShort(out, 0);
    writeName(out, "_kerberos._udp.example.com");
    writeShort(out, 33);
    writeShort(out, 1);
    writeSrvAnswer(out, 0, 0, "dc01.example.com");
    writeSrvAnswer(out, 1, 0, "dc02.example.com");
    return out.toByteArray();
  }

  private static byte[] buildLdapResponse() throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeShort(out, 0x1234);
    writeShort(out, 0x8180);
    writeShort(out, 1);
    writeShort(out, 2);
    writeShort(out, 0);
    writeShort(out, 0);
    writeName(out, "_ldap._tcp.example.com");
    writeShort(out, 33);
    writeShort(out, 1);
    writeSrvAnswer(out, 0, 0, 389, "ldap01.example.com");
    writeSrvAnswer(out, 1, 0, 389, "ldap02.example.com");
    return out.toByteArray();
  }

  private static byte[] buildTxtResponse(String realm) throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeShort(out, 0x1234);
    writeShort(out, 0x8180);
    writeShort(out, 1);
    writeShort(out, 1);
    writeShort(out, 0);
    writeShort(out, 0);
    writeName(out, "_kerberos.int.example");
    writeShort(out, 16);
    writeShort(out, 1);
    writeTxtAnswer(out, realm);
    return out.toByteArray();
  }

  private static byte[] buildCnameResponse(String alias) throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeShort(out, 0x1234);
    writeShort(out, 0x8180);
    writeShort(out, 1);
    writeShort(out, 1);
    writeShort(out, 0);
    writeShort(out, 0);
    writeName(out, "portal.int.example");
    writeShort(out, 1);
    writeShort(out, 1);
    writeCnameAnswer(out, alias);
    return out.toByteArray();
  }

  private static byte[] buildPtrResponse(String hostName) throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeShort(out, 0x1234);
    writeShort(out, 0x8180);
    writeShort(out, 1);
    writeShort(out, 1);
    writeShort(out, 0);
    writeShort(out, 0);
    writeName(out, "27.17.151.10.in-addr.arpa");
    writeShort(out, 12);
    writeShort(out, 1);
    writePtrAnswer(out, hostName);
    return out.toByteArray();
  }

  private static void writeSrvAnswer(ByteArrayOutputStream out, int priority, int weight,
      String target) throws Exception {
    writeSrvAnswer(out, priority, weight, 88, target);
  }

  private static void writeSrvAnswer(
      ByteArrayOutputStream out, int priority, int weight, int port, String target)
      throws Exception {
    out.write(0xc0);
    out.write(0x0c);
    writeShort(out, 33);
    writeShort(out, 1);
    writeInt(out, 60);

    ByteArrayOutputStream data = new ByteArrayOutputStream();
    writeShort(data, priority);
    writeShort(data, weight);
    writeShort(data, port);
    writeName(data, target);

    byte[] bytes = data.toByteArray();
    writeShort(out, bytes.length);
    out.write(bytes);
  }

  private static void writeTxtAnswer(ByteArrayOutputStream out, String text) throws Exception {
    out.write(0xc0);
    out.write(0x0c);
    writeShort(out, 16);
    writeShort(out, 1);
    writeInt(out, 60);
    byte[] textBytes = text.getBytes(StandardCharsets.US_ASCII);
    writeShort(out, textBytes.length + 1);
    out.write(textBytes.length);
    out.write(textBytes);
  }

  private static void writeCnameAnswer(ByteArrayOutputStream out, String alias) throws Exception {
    out.write(0xc0);
    out.write(0x0c);
    writeShort(out, 5);
    writeShort(out, 1);
    writeInt(out, 60);

    ByteArrayOutputStream data = new ByteArrayOutputStream();
    writeName(data, alias);

    byte[] bytes = data.toByteArray();
    writeShort(out, bytes.length);
    out.write(bytes);
  }

  private static void writePtrAnswer(ByteArrayOutputStream out, String hostName) throws Exception {
    out.write(0xc0);
    out.write(0x0c);
    writeShort(out, 12);
    writeShort(out, 1);
    writeInt(out, 60);

    ByteArrayOutputStream data = new ByteArrayOutputStream();
    writeName(data, hostName);

    byte[] bytes = data.toByteArray();
    writeShort(out, bytes.length);
    out.write(bytes);
  }

  private static void writeName(ByteArrayOutputStream out, String name) throws Exception {
    for (String label : name.split("\\.")) {
      out.write(label.length());
      out.write(label.getBytes(StandardCharsets.US_ASCII));
    }
    out.write(0);
  }

  private static void writeShort(ByteArrayOutputStream out, int value) {
    out.write((value >>> 8) & 0xff);
    out.write(value & 0xff);
  }

  private static void writeInt(ByteArrayOutputStream out, int value) {
    out.write((value >>> 24) & 0xff);
    out.write((value >>> 16) & 0xff);
    out.write((value >>> 8) & 0xff);
    out.write(value & 0xff);
  }
}
