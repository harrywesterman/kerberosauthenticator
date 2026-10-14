package com.poelbos.kerberosauthenticator.internal.spnego;

import static org.junit.Assert.*;
import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicLong;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.junit.Test;

public class GssContextStoreTest {
  private GSSContext context() {
    return (GSSContext) Proxy.newProxyInstance(GSSContext.class.getClassLoader(),
        new Class<?>[] {GSSContext.class}, (proxy, method, args) -> null);
  }
  @Test public void continuationUsesSameContextExactlyOnce() throws Exception {
    GssContextStore store = new GssContextStore(() -> 0);
    GSSContext context = context();
    byte[] handle = store.put("blue.example", context);
    assertEquals(32, handle.length);
    assertThrows(GSSException.class, () -> store.take("other.example", handle));
    assertSame(context, store.take("blue.example", handle));
    assertThrows(GSSException.class, () -> store.take("blue.example", handle));
  }
  @Test public void expiredAndEvictedContextsCannotBeResumed() throws Exception {
    AtomicLong time = new AtomicLong();
    GssContextStore store = new GssContextStore(time::get);
    byte[] expired = store.put("blue.example", context());
    time.set(120_000_000_000L);
    assertThrows(GSSException.class, () -> store.take("blue.example", expired));
    byte[] oldest = store.put("blue.example", context());
    for (int i = 0; i < 32; i++) store.put("blue.example", context());
    assertThrows(GSSException.class, () -> store.take("blue.example", oldest));
  }
}
