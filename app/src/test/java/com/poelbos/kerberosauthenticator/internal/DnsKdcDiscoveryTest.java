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

  private static void writeSrvAnswer(ByteArrayOutputStream out, int priority, int weight,
      String target) throws Exception {
    out.write(0xc0);
    out.write(0x0c);
    writeShort(out, 33);
    writeShort(out, 1);
    writeInt(out, 60);

    ByteArrayOutputStream data = new ByteArrayOutputStream();
    writeShort(data, priority);
    writeShort(data, weight);
    writeShort(data, 88);
    writeName(data, target);

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
