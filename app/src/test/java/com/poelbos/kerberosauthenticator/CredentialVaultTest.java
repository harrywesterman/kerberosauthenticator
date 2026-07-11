package com.poelbos.kerberosauthenticator;

import static com.google.common.truth.Truth.assertThat;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 35)
public final class CredentialVaultTest {
  @Test public void unmanagedDeviceNeverPersistsPassword() {
    Context context = ApplicationProvider.getApplicationContext();
    CredentialVault vault = new CredentialVault(context);
    vault.delete();
    char[] password = "secret-value".toCharArray();

    assertThat(vault.store("alex", "EXAMPLE.COM", password)).isFalse();
    assertThat(vault.hasCredentials()).isFalse();
    assertThat(vault.load("alex", "EXAMPLE.COM")).isNull();
  }

  @Test public void deleteIsIdempotent() {
    CredentialVault vault = new CredentialVault(ApplicationProvider.getApplicationContext());
    vault.delete();
    vault.delete();
    assertThat(vault.hasCredentials()).isFalse();
  }
}
