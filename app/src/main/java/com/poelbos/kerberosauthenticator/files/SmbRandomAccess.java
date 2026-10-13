package com.poelbos.kerberosauthenticator.files;

import java.io.IOException;

/** Offset-based SMB file access used by Android proxy file descriptors. */
interface SmbRandomAccess extends AutoCloseable {
  long size();
  int read(byte[] buffer, long fileOffset, int bufferOffset, int length);
  int write(byte[] buffer, long fileOffset, int bufferOffset, int length) throws IOException;
  void flush();
  @Override void close();
}
