package com.poelbos.kerberosauthenticator.files;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** Opaque document IDs, bound to one account record and one managed share definition. */
final class ManagedDocumentId {
  final String epoch;
  final String fingerprint;
  final String shareId;
  final String path;

  private ManagedDocumentId(String epoch, String fingerprint, String shareId, String path) {
    this.epoch = epoch;
    this.fingerprint = fingerprint;
    this.shareId = shareId;
    this.path = path;
  }

  static String encode(String epoch, String account, String realm, ManagedShare share,
      boolean encryption, String path) {
    validatePath(path);
    return "v1." + epoch + "." + fingerprint(account, realm, share, encryption)
        + "." + base64(share.getId()) + "." + base64(path);
  }

  static ManagedDocumentId decode(String id) {
    if (id == null) throw new IllegalArgumentException("Invalid document ID");
    String[] parts = id.split("\\.", -1);
    if (parts.length != 5 || !parts[0].equals("v1")
        || !parts[1].matches("[0-9a-fA-F-]{36}")
        || !parts[2].matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException("Invalid document ID");
    }
    String shareId = unbase64(parts[3]);
    String path = unbase64(parts[4]);
    if (shareId.isEmpty()) throw new IllegalArgumentException("Invalid share ID");
    validatePath(path);
    return new ManagedDocumentId(parts[1], parts[2], shareId, path);
  }

  static void validatePath(String path) {
    if (path == null || path.startsWith("\\") || path.endsWith("\\")
        || path.indexOf('/') >= 0 || path.indexOf('\0') >= 0) {
      throw new IllegalArgumentException("Invalid document path");
    }
    if (path.isEmpty()) return;
    for (String part : path.split("\\\\", -1)) {
      if (part.isEmpty() || part.equals(".") || part.equals("..")
          || part.contains(":")) throw new IllegalArgumentException("Invalid document path");
    }
  }

  static String childPath(String parent, String name) {
    validatePath(parent);
    if (name == null || name.isEmpty() || name.indexOf('\\') >= 0
        || name.indexOf('/') >= 0 || name.equals(".") || name.equals("..")
        || name.indexOf(':') >= 0 || name.indexOf('\0') >= 0) {
      throw new IllegalArgumentException("Invalid document name");
    }
    return parent.isEmpty() ? name : parent + "\\" + name;
  }

  private static String fingerprint(String account, String realm, ManagedShare share,
      boolean encryption) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      String value = account + "\0" + realm + "\0" + share.getId() + "\0"
          + share.getDisplayName() + "\0" + share.getHost() + "\0"
          + share.getPort() + "\0" + share.getShareName()
          + "\0" + share.getStartPath() + "\0" + encryption;
      byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
      StringBuilder hex = new StringBuilder(hash.length * 2);
      for (byte b : hash) hex.append(String.format("%02x", b & 0xff));
      return hex.toString();
    } catch (NoSuchAlgorithmException impossible) {
      throw new AssertionError(impossible);
    }
  }

  private static String base64(String value) {
    return Base64.getUrlEncoder().withoutPadding()
        .encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  private static String unbase64(String value) {
    try {
      return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException exception) {
      throw new IllegalArgumentException("Invalid document ID", exception);
    }
  }
}
