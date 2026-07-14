package com.poelbos.kerberosauthenticator.internal;

import static com.google.common.truth.Truth.assertThat;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.security.auth.Subject;
import org.junit.Test;

public final class KerberosRuntimeCoordinatorTest {
  @Test public void restoresPreviousSubjectAfterFailure() {
    Subject previous = new Subject();
    Subject requested = new Subject();
    AtomicReference<Subject> current = new AtomicReference<>(previous);
    KerberosRuntimeCoordinator.setSubjectAccessForTesting(newSubjectAccess(current));

    try {
      KerberosRuntimeCoordinator.runWithSubjectForTesting(requested, ignored -> {
        assertThat(current.get()).isSameInstanceAs(requested);
        throw new IOException("expected");
      });
    } catch (IOException expected) {
      assertThat(expected).hasMessageThat().isEqualTo("expected");
    }

    assertThat(current.get()).isSameInstanceAs(previous);
    KerberosRuntimeCoordinator.resetSubjectAccessForTesting();
  }

  @Test public void serializesConcurrentOperations() throws Exception {
    AtomicReference<Subject> current = new AtomicReference<>();
    KerberosRuntimeCoordinator.setSubjectAccessForTesting(newSubjectAccess(current));
    AtomicInteger active = new AtomicInteger();
    AtomicInteger maximum = new AtomicInteger();
    CountDownLatch firstEntered = new CountDownLatch(1);
    CountDownLatch releaseFirst = new CountDownLatch(1);

    Thread first = new Thread(() -> runUnchecked(() -> {
      maximum.accumulateAndGet(active.incrementAndGet(), Math::max);
      firstEntered.countDown();
      await(releaseFirst);
      active.decrementAndGet();
    }));
    Thread second = new Thread(() -> runUnchecked(() -> {
      maximum.accumulateAndGet(active.incrementAndGet(), Math::max);
      active.decrementAndGet();
    }));

    first.start();
    assertThat(firstEntered.await(2, TimeUnit.SECONDS)).isTrue();
    second.start();
    Thread.sleep(50);
    releaseFirst.countDown();
    first.join(2000);
    second.join(2000);

    assertThat(maximum.get()).isEqualTo(1);
    KerberosRuntimeCoordinator.resetSubjectAccessForTesting();
  }

  private static void runUnchecked(Runnable action) {
    try {
      KerberosRuntimeCoordinator.runWithSubjectForTesting(new Subject(), ignored -> {
        action.run();
        return null;
      });
    } catch (IOException impossible) {
      throw new AssertionError(impossible);
    }
  }

  private static void await(CountDownLatch latch) {
    try {
      if (!latch.await(2, TimeUnit.SECONDS)) throw new AssertionError("timed out");
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new AssertionError(interrupted);
    }
  }

  private static KerberosRuntimeCoordinator.SubjectAccess newSubjectAccess(
      AtomicReference<Subject> current) {
    return new KerberosRuntimeCoordinator.SubjectAccess() {
      @Override public Subject get() { return current.get(); }
      @Override public void set(Subject subject) { current.set(subject); }
    };
  }
}
