package com.poelbos.kerberosauthenticator.files;

import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.ParcelFileDescriptor;
import android.os.ProxyFileDescriptorCallback;
import android.os.storage.StorageManager;
import android.provider.DocumentsContract;
import android.provider.DocumentsProvider;
import android.system.ErrnoException;
import android.system.OsConstants;
import com.poelbos.kerberosauthenticator.KerberosAccount;
import com.poelbos.kerberosauthenticator.R;
import java.io.FileNotFoundException;
import java.io.File;
import java.io.IOException;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/** Android Files integration for managed, Kerberos-only SMB shares. */
public final class EnterpriseDocumentsProvider extends DocumentsProvider {
  public static final String AUTHORITY = "com.poelbos.kerberosauthenticator.documents";
  private static final String SIGN_IN_ID = "sign-in";
  private static final String[] ROOT_COLUMNS = {
      DocumentsContract.Root.COLUMN_ROOT_ID, DocumentsContract.Root.COLUMN_DOCUMENT_ID,
      DocumentsContract.Root.COLUMN_TITLE, DocumentsContract.Root.COLUMN_SUMMARY,
      DocumentsContract.Root.COLUMN_FLAGS, DocumentsContract.Root.COLUMN_ICON,
      DocumentsContract.Root.COLUMN_MIME_TYPES};
  private static final String[] DOCUMENT_COLUMNS = {
      DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME,
      DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.COLUMN_SIZE,
      DocumentsContract.Document.COLUMN_LAST_MODIFIED, DocumentsContract.Document.COLUMN_FLAGS};
  private static final Set<ProxyHandle> HANDLES =
      Collections.synchronizedSet(new HashSet<>());

  @Override public boolean onCreate() {
    // Remove temporary viewer copies left by versions with a built-in browser.
    File legacy = new File(context().getCacheDir(), "opened");
    File[] copies = legacy.listFiles();
    if (copies != null) for (File copy : copies) if (copy.isFile()) copy.delete();
    if (legacy.isDirectory()) legacy.delete();
    return true;
  }

  /** Called by account and MDM changes; the next access also independently checks policy. */
  public static void invalidate(Context context) {
    List<ProxyHandle> handles;
    synchronized (HANDLES) { handles = new ArrayList<>(HANDLES); }
    for (ProxyHandle handle : handles) handle.close();
    context.revokeUriPermission(Uri.parse("content://" + AUTHORITY),
        Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
    notifyRoots(context);
  }

  public static void notifyRoots(Context context) {
    context.getContentResolver().notifyChange(DocumentsContract.buildRootsUri(AUTHORITY), null);
  }

  /** Refresh roots and visible directories after a new ticket is stored. */
  public static void notifyTicketChanged(Context context) {
    notifyRoots(context);
    EnterpriseConfiguration config = EnterpriseConfiguration.from(context);
    KerberosAccount account = KerberosAccount.getAccount(context);
    if (!available(config) || account == null || !account.hasUsableTicket()
        || !config.getRealm().equalsIgnoreCase(account.getDomain())) return;
    String epoch = KerberosAccount.getDocumentEpoch(context);
    for (ManagedShare share : config.getShares()) {
      String rootId = ManagedDocumentId.encode(epoch, account.getName(), config.getRealm(),
          share.resolveForUsername(account.getName()), config.isRequireEncryption(), "");
      context.getContentResolver().notifyChange(
          DocumentsContract.buildChildDocumentsUri(AUTHORITY, rootId), null);
    }
  }

  private Context context() { return getContext(); }

  private EnterpriseConfiguration configuration() {
    return EnterpriseConfiguration.from(context());
  }

  private static boolean available(EnterpriseConfiguration config) {
    return config.isValid() && config.isSharesEnabled();
  }

  private String id(ManagedShare share, String path, EnterpriseConfiguration config,
      KerberosAccount account) {
    return ManagedDocumentId.encode(KerberosAccount.getDocumentEpoch(context()),
        account.getName(), config.getRealm(), share.resolveForUsername(account.getName()),
        config.isRequireEncryption(), path);
  }

  private Resolved resolve(String documentId) throws FileNotFoundException {
    try {
      ManagedDocumentId parsed = ManagedDocumentId.decode(documentId);
      EnterpriseConfiguration config = configuration();
      KerberosAccount account = KerberosAccount.getAccount(context());
      if (!available(config) || account == null
          || !config.getRealm().equalsIgnoreCase(account.getDomain())
          || !parsed.epoch.equals(KerberosAccount.getDocumentEpoch(context()))) {
        throw new FileNotFoundException("Enterprise share is unavailable");
      }
      for (ManagedShare share : config.getShares()) {
        if (!share.getId().equals(parsed.shareId)) continue;
        String expected = id(share, parsed.path, config, account);
        if (!expected.equals(documentId)) break;
        return new Resolved(config, account, share, parsed.path);
      }
      throw new FileNotFoundException("Enterprise document is no longer available");
    } catch (IllegalArgumentException exception) {
      throw notFound(exception);
    }
  }

  @Override public Cursor queryRoots(String[] projection) {
    MatrixCursor cursor = new MatrixCursor(projection == null ? ROOT_COLUMNS : projection);
    cursor.setNotificationUri(context().getContentResolver(),
        DocumentsContract.buildRootsUri(AUTHORITY));
    EnterpriseConfiguration config = configuration();
    if (!available(config)) return cursor;
    KerberosAccount account = KerberosAccount.getAccount(context());
    if (account == null || !config.getRealm().equalsIgnoreCase(account.getDomain())
        || !account.hasUsableTicket()) {
      add(cursor, DocumentsContract.Root.COLUMN_ROOT_ID, SIGN_IN_ID,
          DocumentsContract.Root.COLUMN_DOCUMENT_ID, SIGN_IN_ID,
          DocumentsContract.Root.COLUMN_TITLE, context().getString(R.string.enterprise_files),
          DocumentsContract.Root.COLUMN_SUMMARY, "Sign in to see enterprise shares",
          DocumentsContract.Root.COLUMN_FLAGS, 0,
          DocumentsContract.Root.COLUMN_ICON, R.mipmap.ic_launcher,
          DocumentsContract.Root.COLUMN_MIME_TYPES, "*/*");
      return cursor;
    }
    for (ManagedShare share : config.getShares()) {
      String documentId = id(share, "", config, account);
      add(cursor, DocumentsContract.Root.COLUMN_ROOT_ID, documentId,
          DocumentsContract.Root.COLUMN_DOCUMENT_ID, documentId,
          DocumentsContract.Root.COLUMN_TITLE, share.getDisplayName(),
          DocumentsContract.Root.COLUMN_SUMMARY, share.getHost(),
          DocumentsContract.Root.COLUMN_FLAGS,
              DocumentsContract.Root.FLAG_SUPPORTS_CREATE | DocumentsContract.Root.FLAG_SUPPORTS_IS_CHILD,
          DocumentsContract.Root.COLUMN_ICON, R.mipmap.ic_launcher,
          DocumentsContract.Root.COLUMN_MIME_TYPES, "*/*");
    }
    return cursor;
  }

  @Override public Cursor queryDocument(String documentId, String[] projection)
      throws FileNotFoundException {
    MatrixCursor cursor = new MatrixCursor(projection == null ? DOCUMENT_COLUMNS : projection);
    if (SIGN_IN_ID.equals(documentId)) {
      add(cursor, DocumentsContract.Document.COLUMN_DOCUMENT_ID, SIGN_IN_ID,
          DocumentsContract.Document.COLUMN_DISPLAY_NAME, "Sign in to Kerberos Authenticator",
          DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.MIME_TYPE_DIR,
          DocumentsContract.Document.COLUMN_FLAGS,
              DocumentsContract.Document.FLAG_SUPPORTS_SETTINGS);
      return cursor;
    }
    Resolved doc = resolve(documentId);
    if (doc.path.isEmpty()) {
      addDocument(cursor, documentId, doc.share.getDisplayName(), true, 0, 0, true);
      return cursor;
    }
    RemoteEntry entry = findEntry(doc);
    addDocument(cursor, documentId, entry.getName(), entry.isDirectory(), entry.getSize(),
        entry.getModifiedMillis(), false);
    return cursor;
  }

  @Override public Cursor queryChildDocuments(String parentDocumentId, String[] projection,
      String sortOrder) throws FileNotFoundException {
    MatrixCursor cursor = new MatrixCursor(projection == null ? DOCUMENT_COLUMNS : projection);
    cursor.setNotificationUri(context().getContentResolver(),
        DocumentsContract.buildChildDocumentsUri(AUTHORITY, parentDocumentId));
    if (SIGN_IN_ID.equals(parentDocumentId)) return cursor;
    Resolved parent = resolve(parentDocumentId);
    try (KerberosSmbClient client = connect(parent)) {
      for (RemoteEntry entry : client.list(parent.path)) {
        String path = ManagedDocumentId.childPath(parent.path, entry.getName());
        addDocument(cursor, id(parent.share, path, parent.config, parent.account),
            entry.getName(), entry.isDirectory(), entry.getSize(), entry.getModifiedMillis(), false);
      }
    } catch (IOException | IllegalArgumentException exception) {
      throw notFound(exception);
    }
    return cursor;
  }

  @Override public String createDocument(String parentDocumentId, String mimeType,
      String displayName) throws FileNotFoundException {
    Resolved parent = resolve(parentDocumentId);
    if (mimeType == null) throw new FileNotFoundException("Missing MIME type");
    try {
      String path = ManagedDocumentId.childPath(parent.path, displayName);
      try (KerberosSmbClient client = connect(parent)) {
        if (DocumentsContract.Document.MIME_TYPE_DIR.equals(mimeType)) {
          client.createDirectory(parent.path, displayName);
        } else {
          client.createFile(parent.path, displayName);
        }
      }
      notifyChildren(parentDocumentId);
      return id(parent.share, path, parent.config, parent.account);
    } catch (IOException | IllegalArgumentException exception) {
      throw notFound(exception);
    }
  }

  @Override public String renameDocument(String documentId, String displayName)
      throws FileNotFoundException {
    Resolved doc = resolve(documentId);
    if (doc.path.isEmpty()) throw new FileNotFoundException("Cannot rename a managed share");
    try {
      String parent = parent(doc.path);
      String newPath = ManagedDocumentId.childPath(parent, displayName);
      if (newPath.equals(doc.path)) return documentId;
      try (KerberosSmbClient client = connect(doc)) {
        client.rename(doc.path, displayName);
      }
      notifyChildren(id(doc.share, parent, doc.config, doc.account));
      return id(doc.share, newPath, doc.config, doc.account);
    } catch (IOException | IllegalArgumentException exception) {
      throw notFound(exception);
    }
  }

  @Override public void deleteDocument(String documentId) throws FileNotFoundException {
    Resolved doc = resolve(documentId);
    if (doc.path.isEmpty()) throw new FileNotFoundException("Cannot delete a managed share");
    RemoteEntry entry = findEntry(doc);
    try (KerberosSmbClient client = connect(doc)) {
      client.delete(doc.path, entry.isDirectory());
      notifyChildren(id(doc.share, parent(doc.path), doc.config, doc.account));
    } catch (IOException exception) {
      throw notFound(exception);
    }
  }

  @Override public boolean isChildDocument(String parentDocumentId, String documentId) {
    try {
      Resolved parent = resolve(parentDocumentId);
      Resolved child = resolve(documentId);
      return parent.share.getId().equals(child.share.getId())
          && !child.path.equals(parent.path)
          && (parent.path.isEmpty() || child.path.startsWith(parent.path + "\\"));
    } catch (FileNotFoundException exception) {
      return false;
    }
  }

  @Override public ParcelFileDescriptor openDocument(String documentId, String mode,
      CancellationSignal signal) throws FileNotFoundException {
    if (signal != null) signal.throwIfCanceled();
    Resolved doc = resolve(documentId);
    if (doc.path.isEmpty()) throw new FileNotFoundException("Cannot open a directory");
    boolean writable = !"r".equals(mode);
    boolean truncate = "wt".equals(mode) || "rwt".equals(mode);
    if (!("r".equals(mode) || "w".equals(mode) || "wt".equals(mode)
        || "wa".equals(mode) || "rw".equals(mode) || "rwt".equals(mode))) {
      throw new FileNotFoundException("Unsupported access mode");
    }
    KerberosSmbClient client = null;
    KerberosSmbClient.RemoteFile remote = null;
    HandlerThread thread = null;
    ProxyHandle handle = null;
    try {
      client = connect(doc);
      if (signal != null) signal.throwIfCanceled();
      remote = client.openFile(doc.path, writable, false);
      thread = new HandlerThread("EnterpriseDocumentsIO");
      thread.start();
      handle = new ProxyHandle(documentId, client, remote, thread, signal,
          "wa".equals(mode));
      HANDLES.add(handle);
      if (signal != null) signal.setOnCancelListener(handle::close);
      handle.check();
      if (truncate) handle.truncateForOpen();
      StorageManager storage = (StorageManager) context().getSystemService(Context.STORAGE_SERVICE);
      int flags = "r".equals(mode) ? ParcelFileDescriptor.MODE_READ_ONLY
          : ("rw".equals(mode) || "rwt".equals(mode))
              ? ParcelFileDescriptor.MODE_READ_WRITE : ParcelFileDescriptor.MODE_WRITE_ONLY;
      ParcelFileDescriptor descriptor = storage.openProxyFileDescriptor(
          flags, handle, new Handler(thread.getLooper()));
      return descriptor;
    } catch (IOException | RuntimeException | ErrnoException exception) {
      if (handle != null) handle.close();
      else {
        if (thread != null) thread.quitSafely();
        if (remote != null) remote.close();
        if (client != null) client.close();
      }
      if (signal != null) signal.throwIfCanceled();
      throw notFound(exception);
    }
  }

  private RemoteEntry findEntry(Resolved doc) throws FileNotFoundException {
    try (KerberosSmbClient client = connect(doc)) {
      String parent = parent(doc.path);
      String name = doc.path.substring(parent.isEmpty() ? 0 : parent.length() + 1);
      for (RemoteEntry entry : client.list(parent)) {
        if (entry.getName().equals(name)) return entry;
      }
      throw new FileNotFoundException("Document not found");
    } catch (IOException exception) {
      throw notFound(exception);
    }
  }

  private KerberosSmbClient connect(Resolved doc) throws IOException {
    return KerberosSmbClient.connect(context(), doc.account, doc.share,
        doc.config.isRequireEncryption());
  }

  private void notifyChildren(String documentId) {
    context().getContentResolver().notifyChange(
        DocumentsContract.buildChildDocumentsUri(AUTHORITY, documentId), null);
  }

  private static String parent(String path) {
    int separator = path.lastIndexOf('\\');
    return separator < 0 ? "" : path.substring(0, separator);
  }

  private static String mimeType(String name, boolean directory) {
    if (directory) return DocumentsContract.Document.MIME_TYPE_DIR;
    String type = URLConnection.guessContentTypeFromName(name);
    return type == null ? "application/octet-stream" : type;
  }

  private void addDocument(MatrixCursor cursor, String id, String name, boolean directory,
      long size, long modified, boolean root) {
    int flags = directory ? DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE
        : DocumentsContract.Document.FLAG_SUPPORTS_WRITE;
    if (!root) flags |= DocumentsContract.Document.FLAG_SUPPORTS_RENAME
        | DocumentsContract.Document.FLAG_SUPPORTS_DELETE;
    add(cursor, DocumentsContract.Document.COLUMN_DOCUMENT_ID, id,
        DocumentsContract.Document.COLUMN_DISPLAY_NAME, name,
        DocumentsContract.Document.COLUMN_MIME_TYPE, mimeType(name, directory),
        DocumentsContract.Document.COLUMN_SIZE, directory ? null : size,
        DocumentsContract.Document.COLUMN_LAST_MODIFIED, modified,
        DocumentsContract.Document.COLUMN_FLAGS, flags);
  }

  private static void add(MatrixCursor cursor, Object... columns) {
    MatrixCursor.RowBuilder row = cursor.newRow();
    for (String name : cursor.getColumnNames()) {
      Object value = null;
      for (int i = 0; i < columns.length; i += 2) {
        if (name.equals(columns[i])) { value = columns[i + 1]; break; }
      }
      row.add(value);
    }
  }

  private static FileNotFoundException notFound(Exception cause) {
    FileNotFoundException error = new FileNotFoundException(cause.getMessage());
    error.initCause(cause);
    return error;
  }

  private static final class Resolved {
    final EnterpriseConfiguration config;
    final KerberosAccount account;
    final ManagedShare share;
    final String path;
    Resolved(EnterpriseConfiguration config, KerberosAccount account, ManagedShare share,
        String path) {
      this.config = config;
      this.account = account;
      this.share = share;
      this.path = path;
    }
  }

  final class ProxyHandle extends ProxyFileDescriptorCallback {
    private final String documentId;
    private final KerberosSmbClient client;
    private final SmbRandomAccess remote;
    private final HandlerThread thread;
    private final CancellationSignal signal;
    private final boolean append;
    private final AtomicBoolean closed = new AtomicBoolean();

    ProxyHandle(String documentId, KerberosSmbClient client, SmbRandomAccess remote,
        HandlerThread thread, CancellationSignal signal, boolean append) {
      this.documentId = documentId;
      this.client = client;
      this.remote = remote;
      this.thread = thread;
      this.signal = signal;
      this.append = append;
    }

    private void check() throws ErrnoException {
      if (closed.get() || (signal != null && signal.isCanceled()))
        throw new ErrnoException("enterprise document", OsConstants.ECANCELED);
      try {
        resolve(documentId);
      } catch (FileNotFoundException exception) {
        close();
        throw new ErrnoException("enterprise document", OsConstants.EACCES);
      }
    }

    @Override public synchronized long onGetSize() throws ErrnoException {
      check();
      try { return remote.size(); }
      catch (RuntimeException exception) { throw ioError(); }
    }

    synchronized void truncateForOpen() throws ErrnoException {
      check();
      try { remote.truncate(0); }
      catch (RuntimeException exception) { throw ioError(); }
    }

    @Override public synchronized int onRead(long offset, int size, byte[] data)
        throws ErrnoException {
      check();
      try {
        int wanted = Math.min(size, data.length);
        int total = 0;
        while (total < wanted) {
          check();
          int count = remote.read(data, offset + total, total, wanted - total);
          if (count <= 0) break;
          total += count;
        }
        return total;
      }
      catch (RuntimeException exception) { throw ioError(); }
    }

    @Override public synchronized int onWrite(long offset, int size, byte[] data)
        throws ErrnoException {
      check();
      try {
        int wanted = Math.min(size, data.length);
        int total = 0;
        long position = append ? remote.size() : offset;
        while (total < wanted) {
          check();
          int count = remote.write(data, position + total, total, wanted - total);
          if (count <= 0) throw ioError();
          total += count;
        }
        return total;
      }
      catch (IOException | RuntimeException exception) { throw ioError(); }
    }

    @Override public synchronized void onFsync() throws ErrnoException {
      check();
      try { remote.flush(); }
      catch (RuntimeException exception) { throw ioError(); }
    }

    @Override public void onRelease() { close(); }

    void close() {
      if (!closed.compareAndSet(false, true)) return;
      HANDLES.remove(this);
      try { remote.close(); } catch (RuntimeException ignored) {}
      if (client != null) client.close();
      if (thread != null) thread.quitSafely();
    }

    private ErrnoException ioError() {
      return new ErrnoException("enterprise document I/O",
          closed.get() || (signal != null && signal.isCanceled())
              ? OsConstants.ECANCELED : OsConstants.EIO);
    }
  }
}
