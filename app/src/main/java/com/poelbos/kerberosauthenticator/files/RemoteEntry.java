package com.poelbos.kerberosauthenticator.files;

/** File metadata safe to expose to the UI. */
public final class RemoteEntry {
  private final String name;
  private final boolean directory;
  private final long size;
  private final long modifiedMillis;

  public RemoteEntry(String name, boolean directory, long size, long modifiedMillis) {
    this.name = name;
    this.directory = directory;
    this.size = size;
    this.modifiedMillis = modifiedMillis;
  }

  public String getName() { return name; }
  public boolean isDirectory() { return directory; }
  public long getSize() { return size; }
  public long getModifiedMillis() { return modifiedMillis; }
}
