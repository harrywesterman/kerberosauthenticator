package com.poelbos.kerberosauthenticator.files;

import java.util.Objects;

/** Immutable, administrator-provisioned SMB location. */
public final class ManagedShare {
  private final String id;
  private final String displayName;
  private final String host;
  private final int port;
  private final String shareName;
  private final String startPath;

  public ManagedShare(
      String id, String displayName, String host, int port, String shareName, String startPath) {
    this.id = requireValue(id, "id");
    this.displayName = requireValue(displayName, "display_name");
    this.host = validateHost(host);
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("port must be between 1 and 65535");
    }
    this.port = port;
    this.shareName = requireValue(shareName, "share_name");
    this.startPath = normalizePath(startPath);
  }

  private static String requireValue(String value, String field) {
    if (value == null || value.trim().isEmpty()) {
      throw new IllegalArgumentException(field + " is required");
    }
    return value.trim();
  }

  private static String validateHost(String host) {
    String value = requireValue(host, "host");
    if (value.matches("^\\d{1,3}(\\.\\d{1,3}){3}$") || value.contains(":")) {
      throw new IllegalArgumentException("host must be a DNS name for Kerberos SPN validation");
    }
    return value.toLowerCase();
  }

  public static String normalizePath(String value) {
    if (value == null) return "";
    String path = value.trim().replace('/', '\\');
    while (path.startsWith("\\")) path = path.substring(1);
    while (path.endsWith("\\")) path = path.substring(0, path.length() - 1);
    for (String segment : path.split("\\\\", -1)) {
      if (segment.equals("..")) {
        throw new IllegalArgumentException("start_path may not escape the managed share");
      }
    }
    return path;
  }

  public String getId() { return id; }
  public String getDisplayName() { return displayName; }
  public String getHost() { return host; }
  public int getPort() { return port; }
  public String getShareName() { return shareName; }
  public String getStartPath() { return startPath; }
  public String getSpn() { return "cifs/" + host; }

  public ManagedShare resolveForUsername(String username) {
    return new ManagedShare(
        id, displayName, host, port, shareName,
        ManagedPathTemplate.resolve(startPath, username));
  }

  @Override public boolean equals(Object other) {
    if (!(other instanceof ManagedShare)) return false;
    ManagedShare share = (ManagedShare) other;
    return id.equals(share.id) && displayName.equals(share.displayName)
        && host.equals(share.host) && port == share.port && shareName.equals(share.shareName)
        && startPath.equals(share.startPath);
  }

  @Override public int hashCode() {
    return Objects.hash(id, displayName, host, port, shareName, startPath);
  }
}
