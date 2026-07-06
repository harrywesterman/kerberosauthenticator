/*
 * Copyright 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package com.poelbos.kerberosauthenticator.internal;

import static com.poelbos.kerberosauthenticator.Constants.TAG;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Looks up HTTP service principal names in Active Directory over LDAP. */
public final class LdapSpnDiscovery {
  private static final int LDAP_PORT = 389;
  private static final int LDAPS_PORT = 636;
  private static final int CONNECT_TIMEOUT_MILLIS = 6000;
  private static final int READ_TIMEOUT_MILLIS = 15000;
  private static final int MAX_SEARCH_RESULTS = 25;

  private LdapSpnDiscovery() {}

  public static List<SearchResult> findHttpServicePrincipalNames(
      Context context,
      String realm,
      String domainControllers,
      String username,
      String password,
      String serviceHost) {
    if (isEmpty(realm) || isEmpty(username) || isEmpty(password) || isEmpty(serviceHost)) {
      return Collections.emptyList();
    }

    String baseDn = baseDnForRealm(realm);
    List<String> bindNames = bindNames(username, realm);
    List<String> hosts = ldapHosts(DnsKdcDiscovery.discoverLdap(context, realm));
    if (hosts.isEmpty()) {
      hosts = ldapHosts(domainControllers);
    }
    Log.i(TAG, "LDAP SPN lookup will try " + hosts.size() + " host(s): " + hosts);

    boolean probedRootDse = false;
    for (String host : hosts) {
      if (!probedRootDse) {
        probedRootDse = true;
        logRootDseProbe(context, host);
      }
      for (String bindName : bindNames) {
        try {
          List<SearchResult> results =
              queryHost(context, host, true, bindName, password, baseDn, serviceHost);
          Log.i(
              TAG,
              String.format("LDAP SPN lookup succeeded over LDAPS at %s as %s.", host, bindName));
          return results;
        } catch (Exception e) {
          Log.w(
              TAG,
              String.format("LDAP SPN lookup over LDAPS failed at %s as %s.", host, bindName),
              e);
        }
        try {
          List<SearchResult> results =
              queryHost(context, host, false, bindName, password, baseDn, serviceHost);
          Log.i(
              TAG,
              String.format("LDAP SPN lookup succeeded over LDAP at %s as %s.", host, bindName));
          return results;
        } catch (Exception e) {
          Log.w(
              TAG,
              String.format("LDAP SPN lookup over LDAP failed at %s as %s.", host, bindName),
              e);
        }
      }
    }
    return Collections.emptyList();
  }

  static String baseDnForRealm(String realm) {
    StringBuilder builder = new StringBuilder();
    for (String label : realm.split("\\.")) {
      if (label.isEmpty()) {
        continue;
      }
      if (builder.length() > 0) {
        builder.append(',');
      }
      builder.append("DC=").append(label);
    }
    return builder.toString();
  }

  static List<String> ldapHosts(String domainControllers) {
    if (isEmpty(domainControllers)) {
      return Collections.emptyList();
    }
    Set<String> hosts = new LinkedHashSet<>();
    for (String part : domainControllers.trim().split("\\s+")) {
      if (part.isEmpty()) {
        continue;
      }
      String host = part;
      int colon = host.indexOf(':');
      if (colon > 0 && host.indexOf(':', colon + 1) < 0) {
        host = host.substring(0, colon);
      }
      if (!host.isEmpty()) {
        hosts.add(host);
      }
    }
    return new ArrayList<>(hosts);
  }

  static List<String> bindNames(String username, String realm) {
    String trimmedUsername = username.trim();
    String trimmedRealm = realm.trim();
    String shortUsername = trimmedUsername;
    int at = shortUsername.indexOf('@');
    if (at > 0) {
      shortUsername = shortUsername.substring(0, at);
    }
    int slash = shortUsername.indexOf('\\');
    if (slash >= 0 && slash < shortUsername.length() - 1) {
      shortUsername = shortUsername.substring(slash + 1);
    }

    Set<String> names = new LinkedHashSet<>();
    if (trimmedUsername.contains("@") || trimmedUsername.contains("\\")) {
      names.add(trimmedUsername);
    } else {
      names.add(trimmedUsername + "@" + trimmedRealm);
    }
    String netbiosDomain = netbiosDomain(trimmedRealm);
    if (!isEmpty(netbiosDomain) && !isEmpty(shortUsername)) {
      names.add(netbiosDomain + "\\" + shortUsername);
    }
    if (!isEmpty(shortUsername)) {
      names.add(shortUsername);
    }
    return new ArrayList<>(names);
  }

  static List<String> searchTerms(String serviceHost) {
    String normalized = normalizeHost(serviceHost);
    if (normalized == null) {
      return Collections.emptyList();
    }
    Set<String> terms = new LinkedHashSet<>();
    terms.add(normalized);
    int dot = normalized.indexOf('.');
    if (dot > 0) {
      terms.add(normalized.substring(0, dot));
    }
    return new ArrayList<>(terms);
  }

  static byte[] buildBindRequest(int messageId, String bindName, String password) {
    return ldapMessage(
        messageId,
        element(
            0x60,
            concat(
                integer(3),
                octetString(bindName),
                element(0x80, password.getBytes(StandardCharsets.UTF_8)))));
  }

  static byte[] buildSearchRequest(int messageId, String baseDn, String serviceHost) {
    return ldapMessage(
        messageId,
        element(
            0x63,
            concat(
                octetString(baseDn),
                enumerated(2),
                enumerated(0),
                integer(MAX_SEARCH_RESULTS),
                integer(20),
                bool(false),
                buildSpnFilter(serviceHost),
                sequence(
                    octetString("distinguishedName"),
                    octetString("sAMAccountName"),
                    octetString("dNSHostName"),
                    octetString("servicePrincipalName")))));
  }

  static byte[] buildRootDseRequest(int messageId) {
    return ldapMessage(
        messageId,
        element(
            0x63,
            concat(
                octetString(""),
                enumerated(0),
                enumerated(0),
                integer(1),
                integer(5),
                bool(false),
                presentFilter("objectClass"),
                sequence(
                    octetString("defaultNamingContext"),
                    octetString("rootDomainNamingContext"),
                    octetString("supportedLDAPVersion"),
                    octetString("supportedSASLMechanisms")))));
  }

  static byte[] buildUnbindRequest(int messageId) {
    return ldapMessage(messageId, element(0x42, new byte[0]));
  }

  static LdapMessage parseMessage(byte[] message) throws IOException {
    BerElement root = BerElement.parse(message, 0);
    if (root.tag != 0x30) {
      throw new IOException("LDAP message is not a sequence.");
    }
    BerReader reader = new BerReader(root.value);
    int messageId = reader.readIntegerElement();
    BerElement protocolOp = reader.readElement();
    return new LdapMessage(messageId, protocolOp.tag, protocolOp.value);
  }

  static int parseLdapResultCode(byte[] protocolOpValue) throws IOException {
    BerReader reader = new BerReader(protocolOpValue);
    return reader.readEnumeratedElement();
  }

  static SearchResult parseSearchResultEntry(byte[] protocolOpValue) throws IOException {
    BerReader reader = new BerReader(protocolOpValue);
    String objectName = reader.readStringElement();
    BerElement attributes = reader.readElement(0x30);
    BerReader attributesReader = new BerReader(attributes.value);
    SearchResult result = new SearchResult(objectName);
    while (attributesReader.hasRemaining()) {
      BerElement attribute = attributesReader.readElement(0x30);
      BerReader attributeReader = new BerReader(attribute.value);
      String attributeName = attributeReader.readStringElement();
      BerElement values = attributeReader.readElement(0x31);
      BerReader valuesReader = new BerReader(values.value);
      while (valuesReader.hasRemaining()) {
        String value = valuesReader.readStringElement();
        result.addAttribute(attributeName, value);
      }
    }
    return result;
  }

  private static List<SearchResult> queryHost(
      Context context,
      String host,
      boolean ssl,
      String bindName,
      String password,
      String baseDn,
      String serviceHost)
      throws IOException, GeneralSecurityException {
    try (Socket socket = openSocket(context, host, ssl)) {
      OutputStream out = socket.getOutputStream();
      InputStream in = socket.getInputStream();

      int messageId = 1;
      out.write(buildBindRequest(messageId, bindName, password));
      out.flush();
      LdapMessage bindResponse = parseMessage(readMessage(in));
      if (bindResponse.messageId != messageId || bindResponse.protocolOpTag != 0x61) {
        throw new IOException("Unexpected LDAP bind response.");
      }
      int bindResult = parseLdapResultCode(bindResponse.protocolOpValue);
      if (bindResult != 0) {
        throw new IOException("LDAP bind failed with result code " + bindResult + ".");
      }

      messageId++;
      out.write(buildSearchRequest(messageId, baseDn, serviceHost));
      out.flush();

      List<SearchResult> results = new ArrayList<>();
      while (true) {
        LdapMessage message = parseMessage(readMessage(in));
        if (message.messageId != messageId) {
          continue;
        }
        if (message.protocolOpTag == 0x64) {
          results.add(parseSearchResultEntry(message.protocolOpValue));
        } else if (message.protocolOpTag == 0x65) {
          int searchResult = parseLdapResultCode(message.protocolOpValue);
          if (searchResult != 0 && searchResult != 4) {
            throw new IOException("LDAP search failed with result code " + searchResult + ".");
          }
          break;
        }
      }

      out.write(buildUnbindRequest(++messageId));
      out.flush();
      return results;
    }
  }

  private static void logRootDseProbe(Context context, String host) {
    try {
      queryRootDse(context, host, true);
      Log.i(TAG, String.format("LDAP RootDSE probe succeeded over LDAPS at %s.", host));
      return;
    } catch (Exception e) {
      Log.w(TAG, String.format("LDAP RootDSE probe over LDAPS failed at %s.", host), e);
    }
    try {
      queryRootDse(context, host, false);
      Log.i(TAG, String.format("LDAP RootDSE probe succeeded over LDAP at %s.", host));
    } catch (Exception e) {
      Log.w(TAG, String.format("LDAP RootDSE probe over LDAP failed at %s.", host), e);
    }
  }

  private static void queryRootDse(Context context, String host, boolean ssl)
      throws IOException, GeneralSecurityException {
    try (Socket socket = openSocket(context, host, ssl)) {
      OutputStream out = socket.getOutputStream();
      InputStream in = socket.getInputStream();
      int messageId = 1;
      out.write(buildRootDseRequest(messageId));
      out.flush();
      while (true) {
        LdapMessage message = parseMessage(readMessage(in));
        if (message.messageId != messageId) {
          continue;
        }
        if (message.protocolOpTag == 0x64) {
          Log.i(TAG, "LDAP RootDSE returned entry " + parseSearchResultEntry(message.protocolOpValue));
        } else if (message.protocolOpTag == 0x65) {
          int searchResult = parseLdapResultCode(message.protocolOpValue);
          if (searchResult != 0) {
            throw new IOException("LDAP RootDSE search failed with result code " + searchResult + ".");
          }
          return;
        }
      }
    }
  }

  private static Socket openSocket(Context context, String host, boolean ssl)
      throws IOException, GeneralSecurityException {
    SocketFactory socketFactory = SocketFactory.getDefault();
    ConnectivityManager connectivityManager =
        (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    Network activeNetwork =
        connectivityManager == null ? null : connectivityManager.getActiveNetwork();
    if (activeNetwork != null) {
      socketFactory = activeNetwork.getSocketFactory();
    }

    int port = ssl ? LDAPS_PORT : LDAP_PORT;
    IOException lastIOException = null;
    GeneralSecurityException lastSecurityException = null;
    InetAddress[] addresses =
        activeNetwork == null ? InetAddress.getAllByName(host) : activeNetwork.getAllByName(host);
    for (InetAddress address : addresses) {
      Socket socket = socketFactory.createSocket();
      try {
        socket.connect(new InetSocketAddress(address, port), CONNECT_TIMEOUT_MILLIS);
        socket.setSoTimeout(READ_TIMEOUT_MILLIS);
        Log.i(
            TAG,
            String.format(
                "LDAP SPN lookup connected to %s/%s:%d.",
                host, address.getHostAddress(), port));
        if (!ssl) {
          return socket;
        }

        SSLSocket sslSocket =
            (SSLSocket) trustAllSocketFactory().createSocket(socket, host, port, true);
        sslSocket.setSoTimeout(READ_TIMEOUT_MILLIS);
        sslSocket.startHandshake();
        return sslSocket;
      } catch (IOException e) {
        lastIOException = e;
        closeQuietly(socket);
      } catch (GeneralSecurityException e) {
        lastSecurityException = e;
        closeQuietly(socket);
      }
    }
    if (lastSecurityException != null) {
      throw lastSecurityException;
    }
    if (lastIOException != null) {
      throw lastIOException;
    }
    throw new IOException("No addresses resolved for " + host + ".");
  }

  private static void closeQuietly(Socket socket) {
    try {
      socket.close();
    } catch (IOException ignored) {
    }
  }

  private static SSLSocketFactory trustAllSocketFactory() throws GeneralSecurityException {
    TrustManager[] trustManagers =
        new TrustManager[] {
          new X509TrustManager() {
            @Override
            public void checkClientTrusted(
                java.security.cert.X509Certificate[] chain, String authType) {}

            @Override
            public void checkServerTrusted(
                java.security.cert.X509Certificate[] chain, String authType) {}

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
              return new java.security.cert.X509Certificate[0];
            }
          }
        };
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, trustManagers, new SecureRandom());
    return sslContext.getSocketFactory();
  }

  private static byte[] readMessage(InputStream in) throws IOException {
    int tag = in.read();
    if (tag < 0) {
      throw new EOFException("No LDAP response available.");
    }
    int length = readLength(in);
    byte[] value = readFully(in, length);
    return element(tag, value);
  }

  private static int readLength(InputStream in) throws IOException {
    int first = in.read();
    if (first < 0) {
      throw new EOFException("Missing BER length.");
    }
    if ((first & 0x80) == 0) {
      return first;
    }
    int count = first & 0x7f;
    if (count == 0 || count > 4) {
      throw new IOException("Unsupported BER length.");
    }
    int length = 0;
    for (int i = 0; i < count; i++) {
      int value = in.read();
      if (value < 0) {
        throw new EOFException("Truncated BER length.");
      }
      length = (length << 8) | value;
    }
    return length;
  }

  private static byte[] readFully(InputStream in, int length) throws IOException {
    byte[] data = new byte[length];
    int offset = 0;
    while (offset < length) {
      int read = in.read(data, offset, length - offset);
      if (read < 0) {
        throw new EOFException("Truncated BER value.");
      }
      offset += read;
    }
    return data;
  }

  private static byte[] buildSpnFilter(String serviceHost) {
    List<byte[]> filters = new ArrayList<>();
    String normalizedHost = normalizeHost(serviceHost);
    if (normalizedHost != null) {
      filters.add(equalityFilter("servicePrincipalName", "HTTP/" + normalizedHost));
    }
    for (String term : searchTerms(serviceHost)) {
      filters.add(substringFilter("servicePrincipalName", "HTTP/", term, null));
    }
    if (filters.size() == 1) {
      return filters.get(0);
    }
    return element(0xa1, concat(filters.toArray(new byte[0][])));
  }

  private static String normalizeHost(String serviceHost) {
    if (isEmpty(serviceHost)) {
      return null;
    }
    String normalized = serviceHost.trim().toLowerCase(Locale.US);
    while (normalized.endsWith(".")) {
      normalized = normalized.substring(0, normalized.length() - 1);
    }
    return normalized.isEmpty() ? null : normalized;
  }

  private static String netbiosDomain(String realm) {
    String normalizedRealm = realm.trim();
    int dot = normalizedRealm.indexOf('.');
    if (dot > 0) {
      normalizedRealm = normalizedRealm.substring(0, dot);
    }
    return normalizedRealm.toUpperCase(Locale.US);
  }

  private static byte[] equalityFilter(String attribute, String value) {
    return element(0xa3, sequence(octetString(attribute), octetString(value)));
  }

  private static byte[] presentFilter(String attribute) {
    return element(0x87, attribute.getBytes(StandardCharsets.UTF_8));
  }

  private static byte[] substringFilter(
      String attribute, String initial, String any, String fin) {
    List<byte[]> substrings = new ArrayList<>();
    if (initial != null) {
      substrings.add(element(0x80, initial.getBytes(StandardCharsets.UTF_8)));
    }
    if (any != null) {
      substrings.add(element(0x81, any.getBytes(StandardCharsets.UTF_8)));
    }
    if (fin != null) {
      substrings.add(element(0x82, fin.getBytes(StandardCharsets.UTF_8)));
    }
    return element(0xa4, concat(octetString(attribute), sequence(concat(substrings.toArray(new byte[0][])))));
  }

  private static byte[] ldapMessage(int messageId, byte[] protocolOp) {
    return sequence(integer(messageId), protocolOp);
  }

  private static byte[] sequence(byte[]... values) {
    return element(0x30, concat(values));
  }

  private static byte[] integer(int value) {
    return element(0x02, intValue(value));
  }

  private static byte[] enumerated(int value) {
    return element(0x0a, intValue(value));
  }

  private static byte[] bool(boolean value) {
    return element(0x01, new byte[] {(byte) (value ? 0xff : 0x00)});
  }

  private static byte[] octetString(String value) {
    return element(0x04, value.getBytes(StandardCharsets.UTF_8));
  }

  private static byte[] intValue(int value) {
    if (value == 0) {
      return new byte[] {0};
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    boolean started = false;
    for (int shift = 24; shift >= 0; shift -= 8) {
      int b = (value >>> shift) & 0xff;
      if (b != 0 || started) {
        out.write(b);
        started = true;
      }
    }
    byte[] data = out.toByteArray();
    if ((data[0] & 0x80) != 0) {
      return concat(new byte[] {0}, data);
    }
    return data;
  }

  static byte[] element(int tag, byte[] value) {
    return concat(new byte[] {(byte) tag}, length(value.length), value);
  }

  private static byte[] length(int length) {
    if (length < 0x80) {
      return new byte[] {(byte) length};
    }
    ByteArrayOutputStream valueBytes = new ByteArrayOutputStream();
    int temp = length;
    while (temp > 0) {
      valueBytes.write(temp & 0xff);
      temp >>>= 8;
    }
    byte[] littleEndian = valueBytes.toByteArray();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x80 | littleEndian.length);
    for (int i = littleEndian.length - 1; i >= 0; i--) {
      out.write(littleEndian[i]);
    }
    return out.toByteArray();
  }

  static byte[] concat(byte[]... values) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] value : values) {
      out.write(value, 0, value.length);
    }
    return out.toByteArray();
  }

  private static boolean isEmpty(String value) {
    return value == null || value.isEmpty();
  }

  static final class LdapMessage {
    final int messageId;
    final int protocolOpTag;
    final byte[] protocolOpValue;

    LdapMessage(int messageId, int protocolOpTag, byte[] protocolOpValue) {
      this.messageId = messageId;
      this.protocolOpTag = protocolOpTag;
      this.protocolOpValue = protocolOpValue;
    }
  }

  public static final class SearchResult {
    private final String distinguishedName;
    private String accountName;
    private String dnsHostName;
    private final List<String> servicePrincipalNames = new ArrayList<>();

    SearchResult(String distinguishedName) {
      this.distinguishedName = distinguishedName;
    }

    void addAttribute(String name, String value) {
      if ("distinguishedName".equalsIgnoreCase(name)) {
        return;
      }
      if ("sAMAccountName".equalsIgnoreCase(name)) {
        accountName = value;
      } else if ("dNSHostName".equalsIgnoreCase(name)) {
        dnsHostName = value;
      } else if ("servicePrincipalName".equalsIgnoreCase(name)) {
        servicePrincipalNames.add(value);
      }
    }

    public String getDistinguishedName() {
      return distinguishedName;
    }

    public String getAccountName() {
      return accountName;
    }

    public String getDnsHostName() {
      return dnsHostName;
    }

    public List<String> getServicePrincipalNames() {
      return Collections.unmodifiableList(servicePrincipalNames);
    }

    @Override
    public String toString() {
      return "SearchResult{"
          + "distinguishedName='"
          + distinguishedName
          + '\''
          + ", accountName='"
          + accountName
          + '\''
          + ", dnsHostName='"
          + dnsHostName
          + '\''
          + ", servicePrincipalNames="
          + servicePrincipalNames
          + '}';
    }
  }

  private static final class BerReader {
    private final byte[] data;
    private int offset;

    BerReader(byte[] data) {
      this.data = data;
    }

    boolean hasRemaining() {
      return offset < data.length;
    }

    BerElement readElement() throws IOException {
      BerElement element = BerElement.parse(data, offset);
      offset = element.nextOffset;
      return element;
    }

    BerElement readElement(int expectedTag) throws IOException {
      BerElement element = readElement();
      if (element.tag != expectedTag) {
        throw new IOException(
            String.format("Expected BER tag 0x%02x but got 0x%02x.", expectedTag, element.tag));
      }
      return element;
    }

    int readIntegerElement() throws IOException {
      return intFromBytes(readElement(0x02).value);
    }

    int readEnumeratedElement() throws IOException {
      return intFromBytes(readElement(0x0a).value);
    }

    String readStringElement() throws IOException {
      return new String(readElement(0x04).value, StandardCharsets.UTF_8);
    }
  }

  private static int intFromBytes(byte[] bytes) {
    int value = 0;
    for (byte b : bytes) {
      value = (value << 8) | (b & 0xff);
    }
    return value;
  }

  private static final class BerElement {
    final int tag;
    final byte[] value;
    final int nextOffset;

    private BerElement(int tag, byte[] value, int nextOffset) {
      this.tag = tag;
      this.value = value;
      this.nextOffset = nextOffset;
    }

    static BerElement parse(byte[] data, int offset) throws IOException {
      if (offset >= data.length) {
        throw new EOFException("Missing BER tag.");
      }
      int tag = data[offset++] & 0xff;
      if (offset >= data.length) {
        throw new EOFException("Missing BER length.");
      }
      int firstLengthByte = data[offset++] & 0xff;
      int length;
      if ((firstLengthByte & 0x80) == 0) {
        length = firstLengthByte;
      } else {
        int count = firstLengthByte & 0x7f;
        if (count == 0 || count > 4 || offset + count > data.length) {
          throw new IOException("Unsupported BER length.");
        }
        length = 0;
        for (int i = 0; i < count; i++) {
          length = (length << 8) | (data[offset++] & 0xff);
        }
      }
      if (offset + length > data.length) {
        throw new EOFException("Truncated BER value.");
      }
      byte[] value = new byte[length];
      System.arraycopy(data, offset, value, 0, length);
      return new BerElement(tag, value, offset + length);
    }
  }
}
