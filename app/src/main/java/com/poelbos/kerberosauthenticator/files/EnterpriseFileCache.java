package com.poelbos.kerberosauthenticator.files;

import android.content.Context;
import java.io.File;
import java.io.IOException;
import java.util.UUID;

/** Owns short-lived app-private files shared with external document viewers. */
public final class EnterpriseFileCache {
  private static final String DIRECTORY = "opened";
  private final File directory;

  public EnterpriseFileCache(Context context) {
    directory = new File(context.getCacheDir(), DIRECTORY);
  }

  public File create(String shareId, String originalName) throws IOException {
    if (!directory.exists() && !directory.mkdirs()) {
      throw new IOException("Unable to create the temporary folder");
    }
    String safeShare = safeName(shareId);
    String safeOriginal = safeName(originalName);
    return new File(directory, safeShare + "-" + UUID.randomUUID() + "-" + safeOriginal);
  }

  public void cleanup() {
    File[] files = directory.listFiles();
    if (files != null) {
      for (File file : files) delete(file);
    }
    if (directory.isDirectory()) directory.delete();
  }

  public void delete(File file) {
    if (file != null && file.isFile()) file.delete();
  }

  static String safeName(String name) {
    String value = name == null ? "file" : name.replaceAll("[^A-Za-z0-9._ -]", "_");
    return value.isEmpty() ? "file" : value;
  }
}
