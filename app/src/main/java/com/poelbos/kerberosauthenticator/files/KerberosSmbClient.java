package com.poelbos.kerberosauthenticator.files;

import static com.poelbos.kerberosauthenticator.Constants.TAG;
import static com.hierynomus.mssmb2.SMB2Dialect.SMB_2_1;
import static com.hierynomus.mssmb2.SMB2Dialect.SMB_3_0;
import static com.hierynomus.mssmb2.SMB2Dialect.SMB_3_0_2;
import static com.hierynomus.mssmb2.SMB2Dialect.SMB_3_1_1;

import android.content.Context;
import android.util.Log;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.GSSAuthenticationContext;
import com.hierynomus.smbj.auth.SpnegoAuthenticator;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.paths.DFSPathResolver;
import com.hierynomus.smbj.paths.PathResolveException;
import com.hierynomus.smbj.paths.PathResolver;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.poelbos.kerberosauthenticator.KerberosAccount;
import com.poelbos.kerberosauthenticator.internal.DnsKdcDiscovery;
import com.poelbos.kerberosauthenticator.internal.KerberosRuntimeCoordinator;
import com.poelbos.kerberosauthenticator.internal.TicketGrantingTicket;
import java.io.Closeable;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.security.auth.Subject;
import org.ietf.jgss.GSSException;
import sun.security.krb5.KrbException;

/** Kerberos-only SMB 2.1+ session. No password/NTLM authenticator is ever constructed. */
public final class KerberosSmbClient implements Closeable {
  private final Context context;
  private final String realm;
  private final String domainController;
  private final Subject subject;
  private final ManagedShare managedShare;
  private final SMBClient client;
  private final Connection connection;
  private final Session session;
  private final DiskShare share;
  private final PathResolver proactiveDfsResolver;

  public static KerberosSmbClient connect(
      Context context, KerberosAccount account, ManagedShare managedShare, boolean requireEncryption)
      throws IOException {
    if (account == null || account.getTicketGrantingTicket().length == 0) {
      throw new IOException("Sign in again to open this share");
    }
    ManagedShare resolvedShare = resolveManagedShare(managedShare, account.getName());
    TicketGrantingTicket tgt =
        TicketGrantingTicket.fromSerializedSubject(account.getTicketGrantingTicket());
    if (tgt == null || tgt.getExpiryDate() == null
        || tgt.getExpiryDate().getTime() <= System.currentTimeMillis()) {
      throw new IOException("Your Kerberos ticket has expired");
    }
    Subject subject = tgt.asSubject();
    return KerberosRuntimeCoordinator.run(
        context,
        account.getDomain(),
        account.getDomainController(),
        resolvedShare.getHost(),
        subject,
        configuredKerberosServers -> connectConfigured(
            context.getApplicationContext(), account, resolvedShare, requireEncryption, subject,
            configuredKerberosServers));
  }

  private static KerberosSmbClient connectConfigured(
      Context context,
      KerberosAccount account,
      ManagedShare resolvedShare,
      boolean requireEncryption,
      Subject subject,
      String configuredKerberosServers) throws IOException {
    String domainControllers = normalizeHost(resolvedShare.getHost())
            .equals(normalizeHost(account.getDomain()))
        ? DnsKdcDiscovery.discoverDomainControllers(context, account.getDomain())
        : null;
    List<String> candidates = initialConnectionHosts(
        resolvedShare.getHost(), account.getDomain(), domainControllers,
        configuredKerberosServers);
    try {
      return tryBootstrapCandidates(
          candidates,
          host -> connectCandidate(
              context, account, resolvedShare, requireEncryption, subject, host));
    } catch (RetryableBootstrapException exception) {
      throw connectionFailure(exception);
    }
  }

  private static KerberosSmbClient connectCandidate(
      Context context,
      KerberosAccount account,
      ManagedShare resolvedShare,
      boolean requireEncryption,
      Subject subject,
      String host) throws IOException {
    SmbConfig config = createConfig(requireEncryption);
    SMBClient client = new SMBClient(config);
    Connection connection = null;
    try {
      try {
        connection = client.connect(host, resolvedShare.getPort());
      } catch (RuntimeException | IOException exception) {
        throw bootstrapConnectFailure(exception);
      }
      GSSAuthenticationContext authentication = new GSSAuthenticationContext(
          account.getName(), account.getDomain(), subject, null);
      Session session;
      try {
        session = connection.authenticate(authentication);
      } catch (RuntimeException exception) {
        if (shouldRetryBootstrap(exception, false)) {
          throw new RetryableBootstrapException(exception);
        }
        throw exception;
      }
      DiskShare share = (DiskShare) session.connectShare(resolvedShare.getShareName());
      Log.i(TAG, "SMB_BOOTSTRAP_SELECTED host=" + host);
      return new KerberosSmbClient(
          context, account.getDomain(), account.getDomainController(), subject,
          resolvedShare, client, connection, session, share,
          new DFSPathResolver(PathResolver.LOCAL, config.getTransactTimeout()));
    } catch (RuntimeException | IOException exception) {
      if (connection != null) try { connection.close(); } catch (Exception ignored) {}
      try { client.close(); } catch (Exception ignored) {}
      if (exception instanceof RetryableBootstrapException) {
        Log.i(
            TAG,
            "SMB_BOOTSTRAP_RESULT host=" + host
                + " result=" + bootstrapFailureCategory(exception));
        throw (RetryableBootstrapException) exception;
      }
      throw connectionFailure(exception);
    }
  }

  static ManagedShare resolveManagedShare(ManagedShare share, String username) throws IOException {
    try {
      return share.resolveForUsername(username);
    } catch (IllegalArgumentException exception) {
      throw new IOException("The managed share path is invalid", exception);
    }
  }

  static List<String> initialConnectionHosts(
      String shareHost, String realm, String domainControllers, String kerberosServers) {
    String normalizedHost = normalizeHost(shareHost);
    if (!normalizedHost.equals(normalizeHost(realm))) {
      return Collections.singletonList(shareHost);
    }

    String candidates = isBlank(domainControllers) ? kerberosServers : domainControllers;
    Set<String> unique = new LinkedHashSet<>();
    if (!isBlank(candidates)) {
      for (String candidate : candidates.trim().split("\\s+")) {
        String normalized = normalizeHost(candidate);
        if (!normalized.isEmpty()) unique.add(normalized);
      }
    }
    if (unique.isEmpty()) unique.add(normalizedHost);
    return new ArrayList<>(unique);
  }

  static boolean shouldRetryBootstrap(Throwable exception, boolean sessionEstablished) {
    boolean containsIoFailure = false;
    for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
      if (cause instanceof KrbException) {
        return ((KrbException) cause).returnCode() == 7;
      }
      if (cause instanceof IOException) containsIoFailure = true;
    }
    return !sessionEstablished && containsIoFailure;
  }

  static IOException bootstrapConnectFailure(Exception exception) {
    if (exception instanceof IOException) {
      return new RetryableBootstrapException(exception);
    }
    return connectionFailure(exception);
  }

  interface BootstrapCandidateConnector<T> {
    T connect(String host) throws IOException;
  }

  static <T> T tryBootstrapCandidates(
      List<String> candidates, BootstrapCandidateConnector<T> connector) throws IOException {
    if (candidates == null || candidates.isEmpty()) {
      throw new IOException("No SMB bootstrap candidates are available");
    }
    for (int index = 0; index < candidates.size(); index++) {
      String candidate = candidates.get(index);
      try {
        return connector.connect(candidate);
      } catch (RetryableBootstrapException exception) {
        if (index + 1 >= candidates.size()) throw exception;
      }
    }
    throw new IOException("No SMB bootstrap candidate succeeded");
  }

  private static String bootstrapFailureCategory(Throwable exception) {
    for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
      if (cause instanceof KrbException) {
        return "KRB_" + ((KrbException) cause).returnCode();
      }
    }
    return "CONNECT";
  }

  static final class RetryableBootstrapException extends IOException {
    RetryableBootstrapException(Throwable cause) {
      super("SMB bootstrap candidate unavailable", cause);
    }
  }

  private static boolean isBlank(String value) {
    return value == null || value.trim().isEmpty();
  }

  private static String normalizeHost(String value) {
    String normalized = value == null ? "" : value.trim().toLowerCase(Locale.US);
    while (normalized.endsWith(".")) {
      normalized = normalized.substring(0, normalized.length() - 1);
    }
    return normalized;
  }

  static IOException connectionFailure(Exception exception) {
    GSSException gssFailure = null;
    Throwable cause = exception;
    for (int depth = 0; cause != null && depth < 32; depth++, cause = cause.getCause()) {
      if (cause instanceof GSSException) {
        gssFailure = (GSSException) cause;
      }
      if (cause instanceof KrbException && gssFailure != null) {
        return new IOException(
            "Kerberos sign-in to the share failed (GSS "
                + gssFailure.getMajor() + "/" + gssFailure.getMinor() + ", KRB "
                + ((KrbException) cause).returnCode() + ")",
            exception);
      }
    }
    if (gssFailure != null) {
      return new IOException(
          "Kerberos sign-in to the share failed (GSS "
              + gssFailure.getMajor() + "/" + gssFailure.getMinor() + ")",
          exception);
    }
    cause = exception;
    for (int depth = 0; cause != null && depth < 32; depth++, cause = cause.getCause()) {
      if (cause instanceof SMBApiException) {
        long status = ((SMBApiException) cause).getStatusCode() & 0xffffffffL;
        return new IOException(
            String.format(
                java.util.Locale.ROOT,
                "Kerberos sign-in to the share failed (SMB 0x%08X)",
                status),
            exception);
      }
      if (cause instanceof KrbException) {
        return new IOException(
            "Kerberos sign-in to the share failed (KRB "
                + ((KrbException) cause).returnCode() + ")",
            exception);
      }
    }
    if (exception instanceof IOException) return (IOException) exception;
    String location = exceptionLocation(exception);
    return new IOException(
        "Kerberos sign-in to the share failed (" + exceptionTypes(exception)
            + (location.isEmpty() ? "" : "@" + location) + ")",
        exception);
  }

  private static String exceptionLocation(Throwable exception) {
    for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
      for (StackTraceElement frame : cause.getStackTrace()) {
        String className = frame.getClassName();
        if (className.startsWith("com.hierynomus.")) {
          int separator = className.lastIndexOf('.');
          return className.substring(separator + 1) + "." + frame.getMethodName();
        }
      }
    }
    return "";
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
      Context context, String realm, String domainController, Subject subject,
      ManagedShare managedShare, SMBClient client, Connection connection,
      Session session, DiskShare share, PathResolver proactiveDfsResolver) {
    this.context = context;
    this.realm = realm;
    this.domainController = domainController;
    this.subject = subject;
    this.managedShare = managedShare;
    this.client = client;
    this.connection = connection;
    this.session = session;
    this.share = share;
    this.proactiveDfsResolver = proactiveDfsResolver;
  }

  public List<RemoteEntry> list(String relativePath) throws IOException {
    try {
      ResolvedTarget target = resolveTarget(relativePath);
      return listConfigured(target);
    } catch (RuntimeException exception) {
      throw connectionFailure(exception);
    }
  }

  private List<RemoteEntry> listConfigured(ResolvedTarget target) {
    List<RemoteEntry> result = new ArrayList<>();
    for (FileIdBothDirectoryInformation item : target.share.list(target.path)) {
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

  /**
   * Resolve a DFS namespace path before file I/O. SMBJ otherwise waits for
   * STATUS_PATH_NOT_COVERED and can lose the create response while following a link.
   */
  private ResolvedTarget resolveTarget(String relativePath) throws IOException {
    String path = resolve(relativePath);
    return KerberosRuntimeCoordinator.run(
        context, realm, domainController, managedShare.getHost(), subject,
        ignored -> {
          SmbPath requested = proactiveDfsRequestPath(
              managedShare, connection.getRemoteHostname(), path);
          SmbPath resolved;
          try {
            resolved = proactiveDfsResolver.resolve(session, requested, candidate -> candidate);
          } catch (PathResolveException exception) {
            throw new IOException("The managed DFS path could not be resolved", exception);
          }
          if (resolved == null || requested.isOnSameShare(resolved)) {
            return new ResolvedTarget(share, path, requested);
          }
          String targetServiceHost = resolvedTargetServiceHost(requested, resolved);
          return KerberosRuntimeCoordinator.run(
              context, realm, domainController, targetServiceHost, subject,
              targetConfiguration -> {
                Session targetSession = session.getNestedSession(resolved);
                DiskShare targetShare =
                    (DiskShare) targetSession.connectShare(resolved.getShareName());
                return new ResolvedTarget(
                    targetShare, nullToEmpty(resolved.getPath()), resolved);
              });
        });
  }

  static SmbPath proactiveDfsRequestPath(
      ManagedShare managedShare, String authenticatedHost, String path) {
    return new SmbPath(authenticatedHost, managedShare.getShareName(), path);
  }

  static String resolvedTargetServiceHost(SmbPath requested, SmbPath resolved) {
    return resolved == null || requested.isOnSameShare(resolved)
        ? requested.getHostname()
        : resolved.getHostname();
  }

  private static String nullToEmpty(String value) {
    return value == null ? "" : value;
  }

  private static final class ResolvedTarget {
    final DiskShare share;
    final String path;
    final SmbPath smbPath;

    ResolvedTarget(DiskShare share, String path, SmbPath smbPath) {
      this.share = share;
      this.path = path;
      this.smbPath = smbPath;
    }
  }

  static boolean isLazyDfsAuthenticationFailure(Throwable exception) {
    for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
      if (!(cause instanceof NullPointerException)) continue;
      for (StackTraceElement frame : cause.getStackTrace()) {
        if (frame.getClassName().equals("com.hierynomus.smbj.share.DiskShare")
            && frame.getMethodName().equals("getDiskEntry")) return true;
      }
    }
    return false;
  }

  public void createDirectory(String parent, String name) throws IOException {
    validateFileName(name);
    ResolvedTarget target = resolveTarget(join(parent, name));
    target.share.mkdir(target.path);
  }

  public void delete(String relativePath, boolean directory) throws IOException {
    ResolvedTarget target = resolveTarget(relativePath);
    if (directory) target.share.rmdir(target.path, true); else target.share.rm(target.path);
  }

  public void download(String relativePath, java.io.File destination) throws IOException {
    java.io.File parent = destination.getParentFile();
    if (parent != null && !parent.exists() && !parent.mkdirs()) {
      throw new IOException("Unable to create the temporary folder");
    }
    ResolvedTarget target = resolveTarget(relativePath);
    try (com.hierynomus.smbj.share.File remote = target.share.openFile(
            target.path, EnumSet.of(AccessMask.GENERIC_READ),
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
    ResolvedTarget target = resolveTarget(relativePath);
    try (com.hierynomus.smbj.share.File remote = target.share.openFile(
            target.path, EnumSet.of(AccessMask.GENERIC_WRITE),
            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL,
            SMB2CreateDisposition.FILE_OVERWRITE_IF,
            EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));
        OutputStream output = remote.getOutputStream()) {
      byte[] buffer = new byte[128 * 1024];
      int count;
      while ((count = input.read(buffer)) >= 0) output.write(buffer, 0, count);
    }
  }

  public void rename(String relativePath, String newName) throws IOException {
    validateFileName(newName);
    String normalized = ManagedShare.normalizePath(relativePath);
    int separator = normalized.lastIndexOf('\\');
    String parent = separator < 0 ? "" : normalized.substring(0, separator);
    ResolvedTarget source = resolveTarget(normalized);
    ResolvedTarget target = resolveTarget(join(parent, newName));
    if (!source.smbPath.isOnSameShare(target.smbPath)) {
      throw new IOException("The item cannot be moved across managed shares");
    }
    try (com.hierynomus.smbj.share.DiskEntry entry = source.share.open(
        source.path, EnumSet.of(AccessMask.DELETE), null, SMB2ShareAccess.ALL,
        SMB2CreateDisposition.FILE_OPEN, null)) {
      entry.rename(target.path, false);
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
      throw new IllegalArgumentException("Invalid folder name");
    }
  }

  @Override public void close() {
    try { share.close(); } catch (Exception ignored) {}
    try { session.close(); } catch (Exception ignored) {}
    try { connection.close(); } catch (Exception ignored) {}
    try { client.close(); } catch (Exception ignored) {}
  }
}
