package com.poelbos.kerberosauthenticator.internal;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

/** Bounded re-selection among administrator-approved SPNs. Peer names never extend the allowlist. */
public final class HttpSpnRetryPolicy {
  public static final HttpSpnRetryPolicy INSTANCE = new HttpSpnRetryPolicy(System::nanoTime);
  private static final long TTL = 120_000_000_000L;
  private final LongSupplier clock;
  private final Map<String, Entry> entries = new LinkedHashMap<>();
  HttpSpnRetryPolicy(LongSupplier clock) { this.clock = clock; }

  public synchronized String preferred(String realm, String origin, String fallback, Set<String> approved) {
    prune();
    Entry entry = entries.get(key(realm, origin));
    return entry != null && approved.contains(entry.target) ? entry.target : fallback;
  }

  public synchronized String retry(String realm, String origin, HttpSpnSettings.Mapping mapping,
      int errorCode, String reportedPrincipal) {
    prune();
    if (mapping == null || !mapping.tlsBinding || mapping.approvedHosts.size() < 2 || errorCode != 41)
      return null;
    // Accept only an exact in-realm computer-account hint that matches an approved DNS SPN.
    String suffix = "$@" + realm.toUpperCase(Locale.ROOT);
    if (reportedPrincipal == null || !reportedPrincipal.toUpperCase(Locale.ROOT).endsWith(suffix)) return null;
    String computer = reportedPrincipal.substring(0, reportedPrincipal.length() - suffix.length());
    if (!computer.matches("[a-zA-Z0-9-]{1,63}")) return null;
    String target = computer.toLowerCase(Locale.ROOT) + "." + realm.toLowerCase(Locale.ROOT);
    if (!mapping.approvedHosts.contains(target) || target.equals(mapping.host)) return null;
    String key = key(realm, origin);
    Entry previous = entries.get(key);
    if (previous != null && previous.retries >= 4) return null;
    entries.put(key, new Entry(target, previous == null ? 1 : previous.retries + 1,
        previous == null ? clock.getAsLong() : previous.created));
    while (entries.size() > 32) entries.remove(entries.keySet().iterator().next());
    return target;
  }

  public synchronized void clear(String realm, String origin) { entries.remove(key(realm, origin)); }
  private void prune() { long now = clock.getAsLong(); entries.values().removeIf(e -> now - e.created >= TTL); }
  private static String key(String realm, String origin) { return realm.toUpperCase(Locale.ROOT) + "|" + origin.toLowerCase(Locale.ROOT); }
  private static final class Entry {
    final String target; final int retries; final long created;
    Entry(String target, int retries, long created) { this.target = target; this.retries = retries; this.created = created; }
  }
}
