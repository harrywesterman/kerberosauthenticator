/*
 * Copyright 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package com.poelbos.kerberosauthenticator.internal;

import static com.poelbos.kerberosauthenticator.Constants.TAG;

import android.content.Context;
import android.content.RestrictionsManager;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Log;
import java.net.IDN;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Resolves safe HTTP Kerberos target hosts in deterministic priority order. */
public final class SpnResolver {
  public static final String MAPPINGS_KEY = "http_spn_mappings";
  public static final String REQUEST_HOST_KEY = "request_host";
  public static final String SPN_HOST_KEY = "spn_host";

  private SpnResolver() {}

  public static List<String> resolve(
      Context context,
      String realm,
      String requestedHost,
      List<String> cnameChain,
      List<String> ldapHosts) {
    String requested = normalizeHost(requestedHost, realm);
    if (requested == null) {
      Log.w(TAG, "SPN_RESOLUTION rejected requested host=" + requestedHost);
      return Collections.emptyList();
    }

    Set<String> candidates = new LinkedHashSet<>();
    String override = managedMappings(context, realm).get(requested);
    addCandidate(candidates, override, realm, "mdm");
    addCandidate(candidates, requested, realm, "requested");
    for (String cname : safeList(cnameChain)) {
      addCandidate(candidates, cname, realm, "cname");
    }
    for (String ldapHost : safeList(ldapHosts)) {
      addCandidate(candidates, ldapHost, realm, "ldap");
    }
    List<String> result = new ArrayList<>(candidates);
    Log.i(TAG, "SPN_RESOLUTION requested=" + requested + " candidates=" + result);
    return result;
  }

  static Map<String, String> managedMappings(Context context, String realm) {
    if (context == null) {
      return Collections.emptyMap();
    }
    RestrictionsManager manager =
        (RestrictionsManager) context.getSystemService(Context.RESTRICTIONS_SERVICE);
    Bundle restrictions = manager == null ? null : manager.getApplicationRestrictions();
    Parcelable[] configured = restrictions == null ? null : restrictions.getParcelableArray(MAPPINGS_KEY);
    if (configured == null) {
      return Collections.emptyMap();
    }

    Map<String, String> mappings = new LinkedHashMap<>();
    Set<String> duplicates = new LinkedHashSet<>();
    for (Parcelable value : configured) {
      if (!(value instanceof Bundle)) {
        Log.w(TAG, "SPN_MAPPING ignored non-bundle entry");
        continue;
      }
      Bundle entry = (Bundle) value;
      String request = normalizeHost(entry.getString(REQUEST_HOST_KEY), realm);
      String target = normalizeHost(entry.getString(SPN_HOST_KEY), realm);
      if (request == null || target == null) {
        Log.w(TAG, "SPN_MAPPING ignored invalid or out-of-realm entry");
        continue;
      }
      if (mappings.containsKey(request)) {
        duplicates.add(request);
      } else {
        mappings.put(request, target);
      }
    }
    for (String duplicate : duplicates) {
      mappings.remove(duplicate);
      Log.w(TAG, "SPN_MAPPING ignored duplicate request_host=" + duplicate);
    }
    return mappings;
  }

  public static String normalizeHost(String value, String realm) {
    if (value == null || realm == null) {
      return null;
    }
    String host = value.trim().toLowerCase(Locale.US);
    while (host.endsWith(".")) {
      host = host.substring(0, host.length() - 1);
    }
    String normalizedRealm = realm.trim().toLowerCase(Locale.US);
    while (normalizedRealm.endsWith(".")) {
      normalizedRealm = normalizedRealm.substring(0, normalizedRealm.length() - 1);
    }
    if (host.isEmpty()
        || normalizedRealm.isEmpty()
        || host.startsWith("*.")
        || host.contains(":")
        || host.contains("/")
        || host.contains("\\")
        || host.contains("@")
        || host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
      return null;
    }
    try {
      host = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.US);
      normalizedRealm =
          IDN.toASCII(normalizedRealm, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.US);
    } catch (IllegalArgumentException e) {
      return null;
    }
    // An AD Kerberos realm is not necessarily the DNS suffix used by web services. The KDC
    // remains fixed by the account configuration, so accepting another valid FQDN here does not
    // permit cross-realm authentication.
    if (!host.contains(".")) {
      return null;
    }
    return host;
  }

  private static void addCandidate(
      Set<String> candidates, String candidate, String realm, String source) {
    String normalized = normalizeHost(candidate, realm);
    if (normalized == null) {
      if (candidate != null) {
        Log.w(TAG, "SPN_RESOLUTION ignored source=" + source + " host=" + candidate);
      }
      return;
    }
    if (candidates.add(normalized)) {
      Log.i(TAG, "SPN_RESOLUTION candidate source=" + source + " host=" + normalized);
    }
  }

  private static List<String> safeList(List<String> values) {
    return values == null ? Collections.emptyList() : values;
  }
}
