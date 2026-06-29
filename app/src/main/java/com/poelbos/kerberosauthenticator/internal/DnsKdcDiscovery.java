/*
 * Copyright 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package com.poelbos.kerberosauthenticator.internal;

import static com.poelbos.kerberosauthenticator.Constants.TAG;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Discovers Kerberos KDC hosts from DNS SRV records on the active Android network. */
public final class DnsKdcDiscovery {
  private static final int DNS_PORT = 53;
  private static final int DNS_TIMEOUT_MILLIS = 2000;
  private static final int DNS_MAX_PACKET_SIZE = 1500;
  private static final int DNS_TYPE_SRV = 33;
  private static final int DNS_CLASS_IN = 1;
  private static final SecureRandom RANDOM = new SecureRandom();

  private DnsKdcDiscovery() {}

  public static String discover(Context context, String realm) {
    List<InetAddress> dnsServers = getDnsServers(context);
    if (dnsServers.isEmpty()) {
      Log.w(TAG, "Cannot discover KDC because the active network has no DNS servers.");
      return null;
    }

    String normalizedRealm = normalizeRealm(realm);
    for (String protocol : new String[] {"_udp", "_tcp"}) {
      String queryName = "_kerberos." + protocol + "." + normalizedRealm;
      List<String> kdcs = queryDnsServers(dnsServers, queryName);
      if (!kdcs.isEmpty()) {
        return joinHosts(kdcs);
      }
    }
    return null;
  }

  private static List<InetAddress> getDnsServers(Context context) {
    ConnectivityManager connectivityManager =
        (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    if (connectivityManager == null) {
      return Collections.emptyList();
    }
    Network network = connectivityManager.getActiveNetwork();
    if (network == null) {
      return Collections.emptyList();
    }
    LinkProperties linkProperties = connectivityManager.getLinkProperties(network);
    if (linkProperties == null) {
      return Collections.emptyList();
    }
    return linkProperties.getDnsServers();
  }

  private static List<String> queryDnsServers(List<InetAddress> dnsServers, String queryName) {
    for (InetAddress dnsServer : dnsServers) {
      try {
        List<String> hosts = querySrv(dnsServer, queryName);
        if (!hosts.isEmpty()) {
          return hosts;
        }
      } catch (SocketTimeoutException e) {
        Log.w(TAG, String.format("DNS SRV lookup timed out at %s for %s.", dnsServer, queryName));
      } catch (IOException e) {
        Log.w(TAG, String.format("DNS SRV lookup failed at %s for %s.", dnsServer, queryName), e);
      }
    }
    return Collections.emptyList();
  }

  static List<String> querySrv(InetAddress dnsServer, String queryName) throws IOException {
    int queryId = RANDOM.nextInt(0x10000);
    byte[] query = buildSrvQuery(queryId, queryName);
    byte[] response = new byte[DNS_MAX_PACKET_SIZE];

    try (DatagramSocket socket = new DatagramSocket()) {
      socket.setSoTimeout(DNS_TIMEOUT_MILLIS);
      socket.send(new DatagramPacket(query, query.length, new InetSocketAddress(dnsServer, DNS_PORT)));
      DatagramPacket packet = new DatagramPacket(response, response.length);
      socket.receive(packet);
      byte[] message = new byte[packet.getLength()];
      System.arraycopy(packet.getData(), 0, message, 0, packet.getLength());
      return parseSrvResponse(message, queryId);
    }
  }

  static byte[] buildSrvQuery(int queryId, String queryName) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeShort(out, queryId);
    writeShort(out, 0x0100); // Standard query with recursion desired.
    writeShort(out, 1);
    writeShort(out, 0);
    writeShort(out, 0);
    writeShort(out, 0);
    writeDnsName(out, queryName);
    writeShort(out, DNS_TYPE_SRV);
    writeShort(out, DNS_CLASS_IN);
    return out.toByteArray();
  }

  static List<String> parseSrvResponse(byte[] message, int expectedQueryId) throws IOException {
    if (message.length < 12) {
      throw new IOException("DNS response is too short.");
    }
    int responseId = readUnsignedShort(message, 0);
    if (responseId != expectedQueryId) {
      throw new IOException("DNS response ID does not match the query.");
    }

    int questionCount = readUnsignedShort(message, 4);
    int answerCount = readUnsignedShort(message, 6);
    int offset = 12;
    for (int i = 0; i < questionCount; i++) {
      offset = readName(message, offset).nextOffset + 4;
      ensureAvailable(message, offset, 0);
    }

    List<SrvRecord> records = new ArrayList<>();
    for (int i = 0; i < answerCount; i++) {
      NameReadResult ignoredName = readName(message, offset);
      offset = ignoredName.nextOffset;
      ensureAvailable(message, offset, 10);
      int type = readUnsignedShort(message, offset);
      int dnsClass = readUnsignedShort(message, offset + 2);
      int dataLength = readUnsignedShort(message, offset + 8);
      offset += 10;
      ensureAvailable(message, offset, dataLength);
      if (type == DNS_TYPE_SRV && dnsClass == DNS_CLASS_IN && dataLength >= 7) {
        int priority = readUnsignedShort(message, offset);
        int weight = readUnsignedShort(message, offset + 2);
        int port = readUnsignedShort(message, offset + 4);
        NameReadResult target = readName(message, offset + 6);
        if (!target.name.isEmpty() && port == 88) {
          records.add(new SrvRecord(priority, weight, target.name));
        } else if (port != 88) {
          Log.w(TAG, String.format("Ignoring Kerberos SRV record on unsupported port %d.", port));
        }
      }
      offset += dataLength;
    }

    Collections.sort(records);
    Set<String> hosts = new LinkedHashSet<>();
    for (SrvRecord record : records) {
      hosts.add(record.host);
    }
    return new ArrayList<>(hosts);
  }

  private static void writeDnsName(ByteArrayOutputStream out, String name) throws IOException {
    String normalizedName = normalizeRealm(name);
    for (String label : normalizedName.split("\\.")) {
      if (label.isEmpty() || label.length() > 63) {
        throw new IOException("Invalid DNS label in " + name);
      }
      out.write(label.length());
      out.write(label.getBytes("US-ASCII"));
    }
    out.write(0);
  }

  private static NameReadResult readName(byte[] message, int offset) throws IOException {
    StringBuilder name = new StringBuilder();
    int currentOffset = offset;
    int nextOffset = -1;
    int jumps = 0;

    while (true) {
      ensureAvailable(message, currentOffset, 1);
      int length = message[currentOffset] & 0xff;
      if (length == 0) {
        currentOffset++;
        if (nextOffset == -1) {
          nextOffset = currentOffset;
        }
        break;
      }
      if ((length & 0xc0) == 0xc0) {
        ensureAvailable(message, currentOffset, 2);
        int pointer = ((length & 0x3f) << 8) | (message[currentOffset + 1] & 0xff);
        if (nextOffset == -1) {
          nextOffset = currentOffset + 2;
        }
        currentOffset = pointer;
        jumps++;
        if (jumps > 16) {
          throw new IOException("DNS name contains too many compression jumps.");
        }
        continue;
      }
      if ((length & 0xc0) != 0) {
        throw new IOException("Unsupported DNS label type.");
      }
      currentOffset++;
      ensureAvailable(message, currentOffset, length);
      if (name.length() > 0) {
        name.append('.');
      }
      name.append(new String(message, currentOffset, length, "US-ASCII"));
      currentOffset += length;
    }

    return new NameReadResult(name.toString(), nextOffset);
  }

  private static void ensureAvailable(byte[] message, int offset, int length) throws IOException {
    if (offset < 0 || length < 0 || offset + length > message.length) {
      throw new IOException("DNS response is truncated.");
    }
  }

  private static int readUnsignedShort(byte[] message, int offset) {
    return ((message[offset] & 0xff) << 8) | (message[offset + 1] & 0xff);
  }

  private static void writeShort(ByteArrayOutputStream out, int value) {
    out.write((value >>> 8) & 0xff);
    out.write(value & 0xff);
  }

  private static String normalizeRealm(String value) {
    String normalized = value.trim();
    while (normalized.endsWith(".")) {
      normalized = normalized.substring(0, normalized.length() - 1);
    }
    return normalized.toLowerCase(Locale.US);
  }

  private static String joinHosts(List<String> hosts) {
    StringBuilder builder = new StringBuilder();
    for (String host : hosts) {
      if (builder.length() > 0) {
        builder.append(' ');
      }
      builder.append(host);
    }
    return builder.toString();
  }

  private static final class NameReadResult {
    final String name;
    final int nextOffset;

    NameReadResult(String name, int nextOffset) {
      this.name = name;
      this.nextOffset = nextOffset;
    }
  }

  private static final class SrvRecord implements Comparable<SrvRecord> {
    final int priority;
    final int weight;
    final String host;

    SrvRecord(int priority, int weight, String host) {
      this.priority = priority;
      this.weight = weight;
      this.host = host;
    }

    @Override
    public int compareTo(SrvRecord other) {
      int priorityComparison = Integer.compare(priority, other.priority);
      if (priorityComparison != 0) {
        return priorityComparison;
      }
      return Integer.compare(other.weight, weight);
    }
  }
}
