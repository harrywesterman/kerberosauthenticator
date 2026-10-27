package com.poelbos.kerberosauthenticator.internal.spnego;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.LongSupplier;

/** Recovers a dropped Chrome bundle only when one negotiation is pending for the exact identity. */
public final class PendingSpnegoStateStore {
  private static final long TTL = 120_000_000_000L;
  private final LongSupplier clock;
  private final Map<String, Entry> pending = new LinkedHashMap<>();

  public PendingSpnegoStateStore() { this(System::nanoTime); }
  PendingSpnegoStateStore(LongSupplier clock) { this.clock = clock; }

  public synchronized void remember(String identity, SpnegoNegotiationState state) {
    prune();
    Entry previous = pending.get(identity);
    // Ambiguity is sticky until expiry or an explicitly supplied context clears it.
    pending.put(identity, new Entry(previous == null ? state : null, clock.getAsLong()));
    while (pending.size() > 32) pending.remove(pending.keySet().iterator().next());
  }

  public synchronized SpnegoNegotiationState recover(String identity) {
    prune();
    Entry entry = pending.remove(identity);
    return entry == null ? null : entry.state;
  }

  public synchronized boolean hasPending(String identity) { prune(); return pending.containsKey(identity); }

  public synchronized void clear(String identity) { pending.remove(identity); }

  public synchronized void clearAll() { pending.clear(); }

  private void prune() {
    long now = clock.getAsLong();
    Iterator<Entry> entries = pending.values().iterator();
    while (entries.hasNext()) if (now - entries.next().created >= TTL) entries.remove();
  }

  private static final class Entry {
    final SpnegoNegotiationState state;
    final long created;
    Entry(SpnegoNegotiationState state, long created) { this.state = state; this.created = created; }
  }
}
