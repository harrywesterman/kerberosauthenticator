/*
 * Copyright 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package com.poelbos.kerberosauthenticator.internal;

import static com.poelbos.kerberosauthenticator.Constants.TAG;

import android.content.Context;
import android.text.TextUtils;
import android.util.Log;
import com.google.common.base.Ascii;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import sun.security.krb5.Config;
import sun.security.krb5.KrbException;

/** Configures the Kerberos system properties required by the OpenJDK Kerberos port. */
public final class KerberosEnvironment {
  private KerberosEnvironment() {}

  public static String configure(
      Context context, String adDomain, String configuredDomainController)
      throws IOException {
    return configure(context, adDomain, configuredDomainController, null);
  }

  public static String configure(
      Context context,
      String adDomain,
      String configuredDomainController,
      String serviceHost)
      throws IOException {
    disableSensitiveDebug();
    String realm = Ascii.toUpperCase(adDomain);
    String domainController = trimToNull(configuredDomainController);
    if (domainController == null) {
      Log.i(TAG, String.format("Discovering KDC for realm %s from DNS SRV records.", realm));
      domainController = DnsKdcDiscovery.discover(context, realm);
    }
    if (TextUtils.isEmpty(domainController)) {
      throw new IOException("No domain controller configured and DNS SRV lookup found no KDC.");
    }

    String serviceRealm =
        preferDiscoveredServiceRealm(
            DnsKdcDiscovery.discoverRealmForHost(context, serviceHost), realm);
    String serviceRealmKdc = null;
    if (serviceRealm != null) {
      Log.i(TAG, String.format("Inferring service realm %s for host %s.", serviceRealm, serviceHost));
      serviceRealmKdc = DnsKdcDiscovery.discover(context, serviceRealm);
      if (TextUtils.isEmpty(serviceRealmKdc)) {
        Log.w(TAG, String.format("DNS SRV lookup found no KDC for inferred service realm %s.", serviceRealm));
        serviceRealmKdc = null;
      }
    }

    File krb5ConfigFile = new File(context.getCacheDir(), "krb5.conf");
    writeKrb5Config(
        krb5ConfigFile,
        buildKrb5Config(realm, domainController, serviceHost, serviceRealm, serviceRealmKdc));

    System.setProperty("java.security.krb5.conf", krb5ConfigFile.getAbsolutePath());
    System.setProperty("java.security.krb5.kdc", domainController);
    System.setProperty("java.security.krb5.realm", realm);
    try {
      Config.refresh();
    } catch (KrbException e) {
      throw new IOException("Failure refreshing Kerberos configuration.", e);
    }
    return domainController;
  }

  static void disableSensitiveDebug() {
    System.setProperty("sun.security.jgss.debug", "false");
    System.setProperty("sun.security.krb5.debug", "false");
  }

  static String inferRealmFromServiceHost(String serviceHost, String defaultRealm) {
    String serviceDomain = getServiceDomain(serviceHost);
    if (serviceDomain == null) {
      return null;
    }
    String inferredRealm = Ascii.toUpperCase(serviceDomain);
    if (inferredRealm.equalsIgnoreCase(defaultRealm)) {
      return null;
    }
    return inferredRealm;
  }

  static String preferDiscoveredServiceRealm(String discoveredRealm, String defaultRealm) {
    String normalizedRealm = trimToNull(discoveredRealm);
    if (normalizedRealm == null || normalizedRealm.equalsIgnoreCase(defaultRealm)) {
      return null;
    }
    return Ascii.toUpperCase(normalizedRealm);
  }

  static String buildKrb5Config(
      String defaultRealm,
      String defaultKdcs,
      String serviceHost,
      String serviceRealm,
      String serviceRealmKdcs) {
    StringBuilder builder = new StringBuilder();
    builder.append("[libdefaults]\n");
    builder.append(" default_realm = ").append(defaultRealm).append('\n');
    builder.append(" dns_lookup_kdc = true\n");
    builder.append(" dns_lookup_realm = false\n\n");

    builder.append("[realms]\n");
    appendRealm(builder, defaultRealm, defaultKdcs);
    if (serviceRealm != null && trimToNull(serviceRealmKdcs) != null) {
      appendRealm(builder, serviceRealm, serviceRealmKdcs);
    }

    String serviceDomain = getServiceDomain(serviceHost);
    if (serviceRealm != null && serviceDomain != null) {
      builder.append('\n');
      builder.append("[domain_realm]\n");
      builder.append(" .").append(serviceDomain).append(" = ").append(serviceRealm).append('\n');
      builder.append(" ").append(serviceDomain).append(" = ").append(serviceRealm).append('\n');
    }

    return builder.toString();
  }

  private static void appendRealm(StringBuilder builder, String realm, String kdcs) {
    builder.append(' ').append(realm).append(" = {\n");
    for (String kdc : kdcs.trim().split("\\s+")) {
      if (!kdc.isEmpty()) {
        builder.append("  kdc = ").append(kdc).append('\n');
      }
    }
    builder.append(" }\n");
  }

  private static void writeKrb5Config(File file, String config) throws IOException {
    try (OutputStreamWriter writer =
        new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
      writer.write(config);
    }
  }

  private static String getServiceDomain(String serviceHost) {
    String normalizedHost = trimToNull(serviceHost);
    if (normalizedHost == null || isIpv4Address(normalizedHost)) {
      return null;
    }
    normalizedHost = normalizedHost.toLowerCase(Locale.US);
    while (normalizedHost.endsWith(".")) {
      normalizedHost = normalizedHost.substring(0, normalizedHost.length() - 1);
    }
    int dot = normalizedHost.indexOf('.');
    if (dot < 0 || dot == normalizedHost.length() - 1) {
      return null;
    }
    return normalizedHost.substring(dot + 1);
  }

  private static boolean isIpv4Address(String value) {
    return value.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");
  }

  private static String trimToNull(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }
}
