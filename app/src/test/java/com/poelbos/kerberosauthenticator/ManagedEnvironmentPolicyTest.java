package com.poelbos.kerberosauthenticator;

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;

public final class ManagedEnvironmentPolicyTest {
  @Test public void managedProfileWithManagedRealmIsAllowed() {
    assertThat(ManagedEnvironmentPolicy.evaluate(true, true, false, true, true)).isTrue();
  }

  @Test public void fullyManagedDeviceWithManagedRealmIsAllowed() {
    assertThat(ManagedEnvironmentPolicy.evaluate(true, false, true, true, true)).isTrue();
  }

  @Test public void localConfigurationIsRejected() {
    assertThat(ManagedEnvironmentPolicy.evaluate(false, true, true, true, true)).isFalse();
  }

  @Test public void personalDeviceIsRejected() {
    assertThat(ManagedEnvironmentPolicy.evaluate(true, false, false, true, true)).isFalse();
  }

  @Test public void insecureDeviceIsRejected() {
    assertThat(ManagedEnvironmentPolicy.evaluate(true, true, false, false, true)).isFalse();
  }

  @Test public void softwareBackedKeyIsRejected() {
    assertThat(ManagedEnvironmentPolicy.evaluate(true, true, false, true, false)).isFalse();
  }
}
