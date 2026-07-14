package com.poelbos.kerberosauthenticator;

import static com.google.common.truth.Truth.assertThat;
import static org.robolectric.Shadows.shadowOf;

import android.Manifest;
import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
public final class NotificationPermissionControllerTest {
  @Test
  @Config(sdk = 32)
  public void permissionIsImplicitlyAllowedBeforeAndroid13() {
    Context context = ApplicationProvider.getApplicationContext();

    assertThat(NotificationPermissionController.isAllowed(context)).isTrue();
  }

  @Test
  @Config(sdk = 33)
  public void permissionReflectsDeniedAndGrantedStateOnAndroid13() {
    Context context = ApplicationProvider.getApplicationContext();
    assertThat(NotificationPermissionController.isAllowed(context)).isFalse();

    shadowOf((android.app.Application) context)
        .grantPermissions(Manifest.permission.POST_NOTIFICATIONS);

    assertThat(NotificationPermissionController.isAllowed(context)).isTrue();
  }
}
