package com.poelbos.kerberosauthenticator.files;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;

public final class ManagedShareTest {
  @Test public void buildsCanonicalCifsSpnFromDnsHost() {
    ManagedShare share = new ManagedShare(
        "finance", "Finance", "FILES.EXAMPLE.COM", 445, "Finance$", "Team/2026");
    assertEquals("files.example.com", share.getHost());
    assertEquals("cifs/files.example.com", share.getSpn());
    assertEquals("Team\\2026", share.getStartPath());
  }

  @Test public void rejectsIpAddressBecauseItCannotProduceReliableSpn() {
    assertThrows(IllegalArgumentException.class, () ->
        new ManagedShare("finance", "Finance", "10.0.0.8", 445, "Finance$", ""));
  }

  @Test public void rejectsPathTraversal() {
    assertThrows(IllegalArgumentException.class, () ->
        new ManagedShare("finance", "Finance", "files.example.com", 445, "Finance$", "../HR"));
  }
}
