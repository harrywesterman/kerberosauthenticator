package com.poelbos.kerberosauthenticator.files;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import org.junit.Test;

public final class ManagedDocumentIdTest {
  private static final String EPOCH = "11111111-1111-4111-8111-111111111111";
  private static final ManagedShare SHARE = new ManagedShare(
      "docs", "Documents", "files.example.com", 445, "Documents", "users\\alice");

  @Test public void encodesAndDecodesNestedPaths() {
    String id = ManagedDocumentId.encode(EPOCH, "alice", "EXAMPLE.COM", SHARE, true,
        "reports\\quarter 1.pdf");
    ManagedDocumentId decoded = ManagedDocumentId.decode(id);
    assertThat(decoded.epoch).isEqualTo(EPOCH);
    assertThat(decoded.shareId).isEqualTo("docs");
    assertThat(decoded.path).isEqualTo("reports\\quarter 1.pdf");
  }

  @Test public void identityShareAndEncryptionChangeIds() {
    String original = ManagedDocumentId.encode(EPOCH, "alice", "EXAMPLE.COM", SHARE, true, "");
    assertThat(ManagedDocumentId.encode(EPOCH, "bob", "EXAMPLE.COM", SHARE, true, ""))
        .isNotEqualTo(original);
    assertThat(ManagedDocumentId.encode(EPOCH, "alice", "EXAMPLE.COM",
        new ManagedShare("docs", "Documents", "other.example.com", 445, "Documents", ""),
        true, "")).isNotEqualTo(original);
    assertThat(ManagedDocumentId.encode(EPOCH, "alice", "EXAMPLE.COM", SHARE, false, ""))
        .isNotEqualTo(original);
  }

  @Test public void rejectsEscapingAndMalformedPaths() {
    for (String path : new String[] {"..", "a\\..\\b", "a\\\\b", "a/b", "\\a", "a\\"}) {
      assertThrows(IllegalArgumentException.class,
          () -> ManagedDocumentId.encode(EPOCH, "alice", "EXAMPLE.COM", SHARE, true, path));
    }
    assertThrows(IllegalArgumentException.class, () -> ManagedDocumentId.decode("v1.invalid"));
    assertThrows(IllegalArgumentException.class,
        () -> ManagedDocumentId.childPath("", ".."));
  }
}
