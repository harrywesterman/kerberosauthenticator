package com.poelbos.kerberosauthenticator.internal;

import android.content.Context;
import java.io.IOException;
import java.util.concurrent.locks.ReentrantLock;
import javax.security.auth.Subject;
import sun.security.jgss.GSSUtil;
import androidx.annotation.VisibleForTesting;

/** Serializes the process-global state used by the embedded OpenJDK Kerberos runtime. */
public final class KerberosRuntimeCoordinator {
  private static final ReentrantLock RUNTIME_LOCK = new ReentrantLock(true);
  private static final SubjectAccess DEFAULT_SUBJECT_ACCESS = new SubjectAccess() {
    @Override public Subject get() { return GSSUtil.getGloballySetSubject(); }
    @Override public void set(Subject subject) { GSSUtil.setGlobalSubject(subject); }
  };
  private static SubjectAccess subjectAccess = DEFAULT_SUBJECT_ACCESS;

  private KerberosRuntimeCoordinator() {}

  public interface Operation<T> {
    T run(String configuredDomainController) throws IOException;
  }

  @VisibleForTesting
  interface SubjectAccess {
    Subject get();
    void set(Subject subject);
  }

  public static <T> T run(
      Context context,
      String realm,
      String domainController,
      String serviceHost,
      Subject subject,
      Operation<T> operation) throws IOException {
    RUNTIME_LOCK.lock();
    Subject previous = subjectAccess.get();
    try {
      String configured = KerberosEnvironment.configure(
          context.getApplicationContext(), realm, domainController, serviceHost);
      subjectAccess.set(subject);
      return operation.run(configured);
    } finally {
      subjectAccess.set(previous);
      RUNTIME_LOCK.unlock();
    }
  }

  @VisibleForTesting
  static <T> T runWithSubjectForTesting(Subject subject, Operation<T> operation)
      throws IOException {
    RUNTIME_LOCK.lock();
    Subject previous = subjectAccess.get();
    try {
      subjectAccess.set(subject);
      return operation.run("");
    } finally {
      subjectAccess.set(previous);
      RUNTIME_LOCK.unlock();
    }
  }

  @VisibleForTesting
  static void setSubjectAccessForTesting(SubjectAccess access) {
    subjectAccess = access;
  }

  @VisibleForTesting
  static void resetSubjectAccessForTesting() {
    subjectAccess = DEFAULT_SUBJECT_ACCESS;
  }
}
