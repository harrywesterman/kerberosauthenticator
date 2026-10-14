package com.poelbos.kerberosauthenticator.internal;

import static org.junit.Assert.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Test;

public class HttpSpnRetryPolicyTest {
  private HttpSpnSettings.Mapping mapping(boolean binding) {
    return new HttpSpnSettings.Mapping("EXAMPLE.COM", "portal.example.com", "web1.example.com",
        binding, "test", "web2.example.com,web3.example.com");
  }
  @Test public void onlyExplicitInRealmAlternativesWithBindingCanBeSelected() {
    HttpSpnRetryPolicy policy = new HttpSpnRetryPolicy(() -> 0);
    assertNull(policy.retry("EXAMPLE.COM", "portal.example.com", mapping(false), 41, "web2$@EXAMPLE.COM"));
    assertNull(policy.retry("EXAMPLE.COM", "portal.example.com", mapping(true), 37, "web2$@EXAMPLE.COM"));
    assertNull(policy.retry("EXAMPLE.COM", "portal.example.com", mapping(true), 41, "evil$@EXAMPLE.COM"));
    assertNull(policy.retry("EXAMPLE.COM", "portal.example.com", mapping(true), 41, "web2$@OTHER.COM"));
    assertNull(policy.retry("EXAMPLE.COM", "portal.example.com", mapping(true), 41, "HTTP/web2.example.com@EXAMPLE.COM"));
    assertNull(policy.retry("EXAMPLE.COM", "portal.example.com", mapping(true), 41, "web1$@EXAMPLE.COM"));
    assertEquals("web2.example.com", policy.retry("EXAMPLE.COM", "portal.example.com", mapping(true), 41, "web2$@EXAMPLE.COM"));
    assertEquals("web2.example.com", policy.preferred("EXAMPLE.COM", "portal.example.com", "web1.example.com", mapping(true).approvedHosts));
    assertEquals("web1.example.com", policy.preferred("EXAMPLE.COM", "other.example.com", "web1.example.com", mapping(true).approvedHosts));
    assertEquals("web1.example.com", policy.preferred("OTHER.COM", "portal.example.com", "web1.example.com", mapping(true).approvedHosts));
  }
  @Test public void retriesAreBoundedExpireAndRespectPolicyChanges() {
    AtomicLong clock = new AtomicLong();
    HttpSpnRetryPolicy policy = new HttpSpnRetryPolicy(clock::get);
    for (int i = 0; i < 4; i++) assertNotNull(policy.retry("EXAMPLE.COM", "portal.example.com", mapping(true), 41,
        (i % 2 == 0 ? "web2" : "web3") + "$@EXAMPLE.COM"));
    assertNull(policy.retry("EXAMPLE.COM", "portal.example.com", mapping(true), 41, "web2$@EXAMPLE.COM"));
    assertEquals("web1.example.com", policy.preferred("EXAMPLE.COM", "portal.example.com", "web1.example.com",
        java.util.Collections.singleton("web1.example.com")));
    clock.set(120_000_000_000L);
    assertEquals("web1.example.com", policy.preferred("EXAMPLE.COM", "portal.example.com", "web1.example.com", mapping(true).approvedHosts));
    assertNotNull(policy.retry("EXAMPLE.COM", "portal.example.com", mapping(true), 41, "web2$@EXAMPLE.COM"));
  }
  @Test public void invalidOrOversizedAllowlistsAreRejected() {
    assertThrows(IllegalArgumentException.class, () -> new HttpSpnSettings.Mapping("EXAMPLE.COM", "portal.example.com",
        "web1.example.com", true, "test", "evil.other.com"));
    assertThrows(IllegalArgumentException.class, () -> new HttpSpnSettings.Mapping("EXAMPLE.COM", "portal.example.com",
        "web1.example.com", true, "test", "web2.example.com,web3.example.com,web4.example.com,web5.example.com"));
  }
}
