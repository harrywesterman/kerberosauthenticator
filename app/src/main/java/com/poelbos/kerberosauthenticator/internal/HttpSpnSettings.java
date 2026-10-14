package com.poelbos.kerberosauthenticator.internal;

import android.content.Context;
import android.content.RestrictionsManager;
import android.os.Bundle;
import android.os.Parcelable;
import java.util.Locale;

/** Exact administrator-approved targets. Managed settings always take precedence over shell settings. */
public final class HttpSpnSettings {
  public static final String ALTERNATES_KEY = "alternate_spn_hosts";
  public static final String TLS_BINDING_KEY = "tls_channel_binding";
  private static final String PREFS = "shell_http_spn_mappings";
  private HttpSpnSettings() {}
  public static final class Mapping {
    public final String host;
    public final boolean tlsBinding;
    public final String source;
    public final java.util.Set<String> approvedHosts;
    Mapping(String realm, String origin, String host, boolean tlsBinding, String source, String alternatives) {
      this.approvedHosts = approvedHosts(realm, host, alternatives);
      this.host = tlsBinding ? HttpSpnRetryPolicy.INSTANCE.preferred(realm, origin, host, approvedHosts) : host;
      this.tlsBinding = tlsBinding; this.source = source;
    }
  }
  public static Mapping get(Context context, String realm, String requested) {
    if (context == null) return null;
    String origin = SpnResolver.normalizeHost(requested, realm);
    if (origin == null) return null;
    RestrictionsManager manager = (RestrictionsManager) context.getSystemService(Context.RESTRICTIONS_SERVICE);
    Bundle restrictions = manager == null ? null : manager.getApplicationRestrictions();
    Parcelable[] entries = restrictions == null ? null : restrictions.getParcelableArray(SpnResolver.MAPPINGS_KEY);
    if (entries != null) {
      boolean configured = false;
      boolean binding = false;
      String alternatives = null;
      for (Parcelable item : entries) if (item instanceof Bundle) {
        Bundle entry = (Bundle) item;
        if (origin.equals(SpnResolver.normalizeHost(entry.getString(SpnResolver.REQUEST_HOST_KEY), realm))) {
          configured = true;
          binding = entry.getBoolean(TLS_BINDING_KEY, false);
          alternatives = entry.getString(ALTERNATES_KEY);
        }
      }
      if (configured) {
        String target = SpnResolver.managedMappings(context, realm).get(origin);
        try { return target == null ? null : new Mapping(realm, origin, target, binding, "mdm", alternatives); }
        catch (IllegalArgumentException invalid) { return null; }
      }
    }
    String key = key(realm, origin);
    android.content.SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    String target = SpnResolver.normalizeHost(prefs.getString(key, null), realm);
    if (target == null) return null;
    try { return new Mapping(realm, origin, target, prefs.getBoolean(key + ".tls", false),
        "shell_admin", prefs.getString(key + ".alternates", null)); }
    catch (IllegalArgumentException invalid) { return null; }
  }
  public static void setForShell(Context context, String realm, String requested, String target, boolean binding) {
    setForShell(context, realm, requested, target, binding, null);
  }
  public static void setForShell(Context context, String realm, String requested, String target, boolean binding, String alternatives) {
    String origin = SpnResolver.normalizeHost(requested, realm);
    String spn = SpnResolver.normalizeHost(target, realm);
    String suffix = "." + realm.toLowerCase(Locale.ROOT);
    if (origin == null || spn == null || !origin.endsWith(suffix) || !spn.endsWith(suffix))
      throw new IllegalArgumentException("Invalid in-realm HTTP mapping");
    approvedHosts(realm, spn, alternatives);
    HttpSpnRetryPolicy.INSTANCE.clear(realm, origin);
    if (!context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
        .putString(key(realm, origin), spn).putString(key(realm, origin) + ".alternates", alternatives).putBoolean(key(realm, origin) + ".tls", binding).commit())
      throw new IllegalStateException("Mapping could not be saved");
  }
  public static void clearForShell(Context context, String realm, String requested) {
    String origin = SpnResolver.normalizeHost(requested, realm);
    if (origin == null) throw new IllegalArgumentException();
    HttpSpnRetryPolicy.INSTANCE.clear(realm, origin);
    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
        .remove(key(realm, origin)).remove(key(realm, origin) + ".tls").remove(key(realm, origin) + ".alternates").apply();
  }
  private static java.util.Set<String> approvedHosts(String realm, String target, String alternatives) {
    java.util.Set<String> hosts = new java.util.LinkedHashSet<>();
    hosts.add(target);
    if (alternatives != null && !alternatives.trim().isEmpty()) {
      for (String value : alternatives.split(",", -1)) {
        String host = SpnResolver.normalizeHost(value.trim(), realm);
        if (host == null || !host.endsWith("." + realm.toLowerCase(Locale.ROOT)))
          throw new IllegalArgumentException("Invalid approved HTTP SPN");
        hosts.add(host);
      }
    }
    if (hosts.size() > 4) throw new IllegalArgumentException("At most four approved SPNs");
    return java.util.Collections.unmodifiableSet(hosts);
  }
  private static String key(String realm, String origin) { return realm.toUpperCase(Locale.ROOT) + "|" + origin; }
}
