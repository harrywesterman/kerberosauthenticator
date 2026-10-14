package com.poelbos.kerberosauthenticator.internal.spnego;

import static org.junit.Assert.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Test;

public class PendingSpnegoStateStoreTest {
 @Test public void exactIdentityRecoveredOnce() {
  PendingSpnegoStateStore store = new PendingSpnegoStateStore(() -> 0);
  SpnegoNegotiationState state = SpnegoNegotiationState.offered("blue.example", "blue.example", new byte[]{1});
  store.remember("accountA@realm|blue.example",state);
  assertNull(store.recover("accountB@realm|blue.example"));
  assertNull(store.recover("accountA@realm|other.example"));
  assertSame(state,store.recover("accountA@realm|blue.example"));
  assertNull(store.recover("accountA@realm|blue.example"));
 }
 @Test public void concurrentNegotiationsAreNeverGuessed() {
  PendingSpnegoStateStore store = new PendingSpnegoStateStore(() -> 0);
  store.remember("identity",SpnegoNegotiationState.offered("blue.example"));
  store.remember("identity",SpnegoNegotiationState.offered("blue.example"));
  assertNull(store.recover("identity"));
 }
 @Test public void expiresAndStaysBounded() {
  AtomicLong clock = new AtomicLong();
  PendingSpnegoStateStore store = new PendingSpnegoStateStore(clock::get);
  store.remember("expired",SpnegoNegotiationState.offered("blue.example"));
  clock.set(120_000_000_000L);
  assertNull(store.recover("expired"));
  for(int i=0;i<33;i++) store.remember("identity"+i,SpnegoNegotiationState.offered("blue.example"));
  assertNull(store.recover("identity0"));
  assertNotNull(store.recover("identity32"));
 }
}
