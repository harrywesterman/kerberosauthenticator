package com.poelbos.kerberosauthenticator.files;

import static com.hierynomus.mssmb2.SMB2Dialect.SMB_2_1;
import static com.hierynomus.mssmb2.SMB2Dialect.SMB_3_0;
import static com.hierynomus.mssmb2.SMB2Dialect.SMB_3_0_2;
import static com.hierynomus.mssmb2.SMB2Dialect.SMB_3_1_1;

import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.GSSAuthenticationContext;
import com.hierynomus.smbj.auth.SpnegoAuthenticator;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.poelbos.kerberosauthenticator.KerberosAccount;
import com.poelbos.kerberosauthenticator.internal.TicketGrantingTicket;
import java.io.Closeable;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import javax.security.auth.Subject;
import org.ietf.jgss.GSSException;
import sun.security.jgss.GSSUtil;
import sun.security.krb5.KrbException;

/** Kerberos-only SMB 2.1+ session. No password/NTLM authenticator is ever constructed. */
public final class KerberosSmbClient implements Closeable {
  private final ManagedShare managedShare;
  private final SMBClient client;
  private final Connection connection;
  private final Session session;
  private final DiskShare share;

  public static KerberosSmbClient connect(
      KerberosAccount account, ManagedShare managedShare, boolean requireEncryption)
      throws IOException {
    if (account == null || account.getTicketGrantingTicket().length == 0) {
      throw new IOException("Meld u opnieuw aan om deze share te openen");
    }
    TicketGrantingTicket tgt =
        TicketGrantingTicket.fromSerializedSubject(account.getTicketGrantingTicket());
    if (tgt == null || tgt.getExpiryDate() == null
        || tgt.getExpiryDate().getTime() <= System.currentTimeMillis()) {
      throw new IOException("Uw Kerberos-ticket is verlopen");
    }
    Subject subject = tgt.asSubject();
    GSSUtil.setGlobalSubject(subject);

    SmbConfig config = createConfig(requireEncryption);
    SMBClient client = new SMBClient(config);
    Connection connection = null;
    try {
      connection = client.connect(managedShare.getHost(), managedShare.getPort());
      GSSAuthenticationContext authentication = new GSSAuthenticationContext(
          account.getName(), account.getDomain(), subject, null);
      Session session = connection.authenticate(authentication);
      DiskShare share = (DiskShare) session.connectShare(managedShare.getShareName());
      return new KerberosSmbClient(managedShare, client, connection, session, share);
    } catch (RuntimeException | IOException exception) {
      if (connection != null) try { connection.close(); } catch (Exception ignored) {}
      try { client.close(); } catch (Exception ignored) {}
      throw connectionFailure(exception);
    }
  }

  static IOException connectionFailure(Exception exception) {
    Throwable cause = exception;
    for (int depth = 0; cause != null && depth < 32; depth++, cause = cause.getCause()) {
      if (cause instanceof GSSException) {
        GSSException gssException = (GSSException) cause;
        return new IOException(
            "Kerberos-aanmelding bij de share is mislukt (GSS "
                + gssException.getMajor() + "/" + gssException.getMinor() + ")",
            exception);
      }
    }
    cause = exception;
    for (int depth = 0; cause != null && depth < 32; depth++, cause = cause.getCause()) {
      if (cause instanceof SMBApiException) {
        long status = ((SMBApiException) cause).getStatusCode() & 0xffffffffL;
        return new IOException(
            String.format(
                java.util.Locale.ROOT,
                "Kerberos-aanmelding bij de share is mislukt (SMB 0x%08X)",
                status),
            exception);
      }
      if (cause instanceof KrbException) {
        return new IOException(
            "Kerberos-aanmelding bij de share is mislukt (KRB "
                + ((KrbException) cause).returnCode() + ")",
            exception);
      }
    }
    if (exception instanceof IOException) return (IOException) exception;
    return new IOException(
        "Kerberos-aanmelding bij de share is mislukt (" + exceptionTypes(exception) + ")",
        exception);
  }

  private static String exceptionTypes(Throwable exception) {
    StringBuilder result = new StringBuilder();
    Throwable cause = exception;
    for (int depth = 0; cause != null && depth < 6; depth++, cause = cause.getCause()) {
      if (result.length() > 0) result.append('>');
      String name = cause.getClass().getSimpleName();
      result.append(name.isEmpty() ? "Throwable" : name.replaceAll("[^A-Za-z0-9_$]", "_"));
    }
    return result.toString();
  }

  static SmbConfig createConfig(boolean requireEncryption) {
    return SmbConfig.builder()
        .withDialects(SMB_3_1_1, SMB_3_0_2, SMB_3_0, SMB_2_1)
        .withAuthenticators(new SpnegoAuthenticator.Factory())
        .withSigningRequired(true)
        .withEncryptData(requireEncryption)
        .withDfsEnabled(true)
        .build();
  }

  private KerberosSmbClient(
      ManagedShare managedShare, SMBClient client, Connection connection,
      Session session, DiskShare share) {
    this.managedShare = managedShare;
    this.client = client;
    this.connection = connection;
    this.session = session;
    this.share = share;
  }

  public List<RemoteEntry> list(String relativePath) {
    List<RemoteEntry> result = new ArrayList<>();
    for (FileIdBothDirectoryInformation item : share.list(resolve(relativePath))) {
      String name = item.getFileName();
      if (name.equals(".") || name.equals("..")) continue;
      boolean directory = (item.getFileAttributes()
          & FileAttributes.FILE_ATTRIBUTE_DIRECTORY.getValue()) != 0;
      result.add(new RemoteEntry(
          name, directory, item.getEndOfFile(), item.getLastWriteTime().toEpochMillis()));
    }
    result.sort(Comparator.comparing(RemoteEntry::isDirectory).reversed()
        .thenComparing(RemoteEntry::getName, String.CASE_INSENSITIVE_ORDER));
    return result;
  }

  public void createDirectory(String parent, String name) {
    validateFileName(name);
    share.mkdir(resolve(join(parent, name)));
  }

  public void delete(String relativePath, boolean directory) {
    String path = resolve(relativePath);
    if (directory) share.rmdir(path, true); else share.rm(path);
  }

  public void download(String relativePath, java.io.File destination) throws IOException {
    java.io.File parent = destination.getParentFile();
    if (parent != null && !parent.exists() && !parent.mkdirs()) {
      throw new IOException("Kan de tijdelijke map niet maken");
    }
    try (com.hierynomus.smbj.share.File remote = share.openFile(
            resolve(relativePath), EnumSet.of(AccessMask.GENERIC_READ),
            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL,
            SMB2CreateDisposition.FILE_OPEN,
            EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));
        InputStream input = remote.getInputStream();
        OutputStream output = new FileOutputStream(destination)) {
      byte[] buffer = new byte[128 * 1024];
      int count;
      while ((count = input.read(buffer)) >= 0) output.write(buffer, 0, count);
    }
  }

  public void upload(String relativePath, InputStream input) throws IOException {
    try (com.hierynomus.smbj.share.File remote = share.openFile(
            resolve(relativePath), EnumSet.of(AccessMask.GENERIC_WRITE),
            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL,
            SMB2CreateDisposition.FILE_OVERWRITE_IF,
            EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));
        OutputStream output = remote.getOutputStream()) {
      byte[] buffer = new byte[128 * 1024];
      int count;
      while ((count = input.read(buffer)) >= 0) output.write(buffer, 0, count);
    }
  }

  public void rename(String relativePath, String newName) {
    validateFileName(newName);
    String normalized = ManagedShare.normalizePath(relativePath);
    int separator = normalized.lastIndexOf('\\');
    String parent = separator < 0 ? "" : normalized.substring(0, separator);
    String target = resolve(join(parent, newName));
    try (com.hierynomus.smbj.share.DiskEntry entry = share.open(
        resolve(normalized), EnumSet.of(AccessMask.DELETE), null, SMB2ShareAccess.ALL,
        SMB2CreateDisposition.FILE_OPEN, null)) {
      entry.rename(target, false);
    }
  }

  private String resolve(String relativePath) {
    String path = ManagedShare.normalizePath(relativePath);
    return join(managedShare.getStartPath(), path);
  }

  public static String join(String parent, String child) {
    if (parent == null || parent.isEmpty()) return child == null ? "" : child;
    if (child == null || child.isEmpty()) return parent;
    return parent + "\\" + child;
  }

  private static void validateFileName(String name) {
    if (name == null || name.trim().isEmpty() || name.matches(".*[\\\\/:*?\"<>|].*")) {
      throw new IllegalArgumentException("Ongeldige mapnaam");
    }
  }

  @Override public void close() {
    try { share.close(); } catch (Exception ignored) {}
    try { session.close(); } catch (Exception ignored) {}
    try { connection.close(); } catch (Exception ignored) {}
    try { client.close(); } catch (Exception ignored) {}
    GSSUtil.setGlobalSubject(null);
  }
}
