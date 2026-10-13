package com.poelbos.kerberosauthenticator.files;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.robolectric.Shadows.shadowOf;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.Context;
import android.content.RestrictionsManager;
import android.database.Cursor;
import android.os.Bundle;
import android.os.Parcelable;
import android.os.CancellationSignal;
import android.provider.DocumentsContract;
import android.system.ErrnoException;
import android.system.OsConstants;
import androidx.test.core.app.ApplicationProvider;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 35)
public final class EnterpriseDocumentsProviderTest {
  private Context context;
  private RestrictionsManager restrictions;
  private AccountManager accounts;
  private EnterpriseDocumentsProvider provider;

  @Before public void setUp() {
    context = ApplicationProvider.getApplicationContext();
    restrictions = (RestrictionsManager) context.getSystemService(Context.RESTRICTIONS_SERVICE);
    accounts = AccountManager.get(context);
    shadowOf(accounts).removeAllAccounts();
    managed(true, "files.example.com");
    provider = Robolectric.buildContentProvider(EnterpriseDocumentsProvider.class).create().get();
  }

  private void managed(boolean enabled, String host) {
    Bundle share = new Bundle();
    share.putString("id", "docs");
    share.putString("display_name", "Documents");
    share.putString("host", host);
    share.putString("share_name", "Documents");
    share.putString("start_path", "users\\${username}");
    Bundle config = new Bundle();
    config.putString("ad_realm", "EXAMPLE.COM");
    config.putBoolean("enable_shares", enabled);
    config.putParcelableArray("shares", new Parcelable[] {share});
    shadowOf(restrictions).setApplicationRestrictions(config);
  }

  private void signIn(String name) {
    Bundle data = new Bundle();
    data.putString("ad_domain", "EXAMPLE.COM");
    data.putString("ticket_granting_ticket", "");
    assertThat(accounts.addAccountExplicitly(
        new Account(name, "AndroidEnterpriseKerberos"), null, data)).isTrue();
  }

  private String firstRoot() {
    try (Cursor cursor = provider.queryRoots(null)) {
      assertThat(cursor.moveToFirst()).isTrue();
      return cursor.getString(cursor.getColumnIndexOrThrow(
          DocumentsContract.Root.COLUMN_DOCUMENT_ID));
    }
  }

  @Test public void signedOutRootOffersAccountSettings() throws Exception {
    assertThat(firstRoot()).isEqualTo("sign-in");
    try (Cursor cursor = provider.queryDocument("sign-in", null)) {
      assertThat(cursor.moveToFirst()).isTrue();
      int flags = cursor.getInt(cursor.getColumnIndexOrThrow(
          DocumentsContract.Document.COLUMN_FLAGS));
      assertThat(flags & DocumentsContract.Document.FLAG_SUPPORTS_SETTINGS).isNotEqualTo(0);
    }
    assertThrows(FileNotFoundException.class,
        () -> provider.openDocument("sign-in", "r", null));
  }

  @Test public void signedInRootsUseManagedSharesAndBecomeInvalidOnPolicyChange()
      throws Exception {
    signIn("alice");
    String id = firstRoot();
    try (Cursor cursor = provider.queryDocument(id, null)) {
      assertThat(cursor.moveToFirst()).isTrue();
      assertThat(cursor.getString(cursor.getColumnIndexOrThrow(
          DocumentsContract.Document.COLUMN_DISPLAY_NAME))).isEqualTo("Documents");
    }
    managed(true, "new-files.example.com");
    assertThrows(FileNotFoundException.class, () -> provider.queryDocument(id, null));
    managed(false, "new-files.example.com");
    try (Cursor cursor = provider.queryRoots(null)) { assertThat(cursor.getCount()).isEqualTo(0); }
    assertThrows(FileNotFoundException.class, () -> provider.queryDocument(id, null));
  }

  @Test public void oldAccountDocumentCannotBeReusedAfterSameUserSignsInAgain()
      throws Exception {
    signIn("alice");
    String id = firstRoot();
    accounts.removeAccountExplicitly(accounts.getAccountsByType("AndroidEnterpriseKerberos")[0]);
    signIn("alice");
    assertThrows(FileNotFoundException.class, () -> provider.queryDocument(id, null));
    assertThat(firstRoot()).isNotEqualTo(id);
  }

  @Test public void proxyReadsWritesAtOffsetsAndFlushes() throws Exception {
    signIn("alice");
    String documentId = child(firstRoot(), "file.txt");
    FakeFile file = new FakeFile("hello".getBytes());
    EnterpriseDocumentsProvider.ProxyHandle handle =
        provider.new ProxyHandle(documentId, null, file, null, null, false);
    byte[] read = new byte[5];
    assertThat(handle.onGetSize()).isEqualTo(5);
    assertThat(handle.onRead(0, 5, read)).isEqualTo(5);
    assertThat(new String(read)).isEqualTo("hello");
    assertThat(handle.onWrite(1, 2, "XY".getBytes())).isEqualTo(2);
    assertThat(new String(file.bytes)).isEqualTo("hXYlo");
    handle.onFsync();
    assertThat(file.flushed).isTrue();
    handle.onRelease();
    assertThat(file.closed).isTrue();
  }

  @Test public void proxyAppendCancellationAndPolicyRevocation() throws Exception {
    signIn("alice");
    String documentId = child(firstRoot(), "file.txt");
    FakeFile file = new FakeFile("a".getBytes());
    CancellationSignal signal = new CancellationSignal();
    EnterpriseDocumentsProvider.ProxyHandle handle =
        provider.new ProxyHandle(documentId, null, file, null, signal, true);
    handle.onWrite(0, 1, "b".getBytes());
    assertThat(new String(file.bytes)).isEqualTo("ab");
    signal.cancel();
    ErrnoException canceled = assertThrows(ErrnoException.class, handle::onGetSize);
    assertThat(canceled.errno).isEqualTo(OsConstants.ECANCELED);
    handle.onRelease();

    FakeFile revokedFile = new FakeFile("private".getBytes());
    EnterpriseDocumentsProvider.ProxyHandle revoked =
        provider.new ProxyHandle(documentId, null, revokedFile, null, null, false);
    managed(false, "files.example.com");
    ErrnoException denied = assertThrows(ErrnoException.class, revoked::onGetSize);
    assertThat(denied.errno).isEqualTo(OsConstants.EACCES);
    assertThat(revokedFile.closed).isTrue();
  }

  @Test public void proxyTurnsNetworkFailuresIntoIoErrors() throws Exception {
    signIn("alice");
    String documentId = child(firstRoot(), "file.txt");
    FakeFile file = new FakeFile(new byte[0]);
    file.fail = true;
    EnterpriseDocumentsProvider.ProxyHandle handle =
        provider.new ProxyHandle(documentId, null, file, null, null, false);
    ErrnoException failure = assertThrows(ErrnoException.class,
        () -> handle.onRead(0, 1, new byte[1]));
    assertThat(failure.errno).isEqualTo(OsConstants.EIO);
    handle.onRelease();
  }

  private String child(String root, String name) {
    ManagedDocumentId parsed = ManagedDocumentId.decode(root);
    ManagedShare share = EnterpriseConfiguration.from(context).getShares().get(0)
        .resolveForUsername("alice");
    return ManagedDocumentId.encode(parsed.epoch, "alice", "EXAMPLE.COM", share, true, name);
  }

  private static final class FakeFile implements SmbRandomAccess {
    byte[] bytes;
    boolean closed;
    boolean flushed;
    boolean fail;
    FakeFile(byte[] bytes) { this.bytes = bytes; }
    @Override public long size() { return bytes.length; }
    @Override public int read(byte[] target, long position, int offset, int length) {
      if (fail) throw new IllegalStateException("network lost");
      if (position >= bytes.length) return -1;
      int count = Math.min(length, bytes.length - (int) position);
      System.arraycopy(bytes, (int) position, target, offset, count);
      return count;
    }
    @Override public int write(byte[] source, long position, int offset, int length)
        throws IOException {
      if (fail) throw new IOException("network lost");
      bytes = Arrays.copyOf(bytes, Math.max(bytes.length, (int) position + length));
      System.arraycopy(source, offset, bytes, (int) position, length);
      return length;
    }
    @Override public void flush() { flushed = true; }
    @Override public void close() { closed = true; }
  }
}
