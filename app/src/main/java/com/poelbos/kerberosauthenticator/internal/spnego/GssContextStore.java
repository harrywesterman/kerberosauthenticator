package com.poelbos.kerberosauthenticator.internal.spnego;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.LongSupplier;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;

/** Keeps live Java GSS contexts in-process; Chrome receives only a random single-use handle. */
final class GssContextStore {
  static final GssContextStore INSTANCE = new GssContextStore(System::nanoTime);
  private static final long TTL_NANOS = 120_000_000_000L;
  private static final int LIMIT = 32;
  private final LongSupplier clock;
  private final SecureRandom random = new SecureRandom();
  private final Map<String, Entry> entries = new LinkedHashMap<>();

  GssContextStore(LongSupplier clock) { this.clock = clock; }

  synchronized byte[] put(String host, GSSContext context) {
    prune();
    while (entries.size() >= LIMIT) {
      Iterator<Entry> iterator = entries.values().iterator();
      dispose(iterator.next().context);
      iterator.remove();
    }
    byte[] handle = new byte[32];
    String key;
    do { random.nextBytes(handle); key = key(handle); } while (entries.containsKey(key));
    entries.put(key, new Entry(host, context, clock.getAsLong()));
    return handle;
  }

  synchronized GSSContext take(String host, byte[] handle) throws GSSException {
    prune();
    if (handle == null || handle.length != 32) throw missing();
    Entry entry = entries.get(key(handle));
    if (entry == null || !entry.host.equals(host)) throw missing();
    entries.remove(key(handle));
    return entry.context;
  }

  private void prune() {
    long now = clock.getAsLong();
    Iterator<Entry> iterator = entries.values().iterator();
    while (iterator.hasNext()) {
      Entry entry = iterator.next();
      if (now - entry.created >= TTL_NANOS) {
        dispose(entry.context);
        iterator.remove();
      }
    }
  }

  private static String key(byte[] handle) { return Arrays.toString(handle); }
  private static GSSException missing() {
    return new GSSException(GSSException.NO_CONTEXT, -1, "Kerberos negotiation expired or unavailable");
  }
  private static void dispose(GSSContext context) {
    try { context.dispose(); } catch (GSSException ignored) { }
  }
  private static final class Entry {
    final String host;
    final GSSContext context;
    final long created;
    Entry(String host, GSSContext context, long created) {
      this.host = host; this.context = context; this.created = created;
    }
  }
}
