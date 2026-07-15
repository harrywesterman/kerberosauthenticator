package com.poelbos.kerberosauthenticator.files;

import static com.google.common.truth.Truth.assertThat;
import static org.robolectric.Shadows.shadowOf;

import android.content.Intent;
import com.google.android.material.appbar.MaterialToolbar;
import com.poelbos.kerberosauthenticator.AuthenticatorStatusActivity;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 35)
public final class EnterpriseFilesActivityTest {
  @Test
  public void accountOverflowItemOpensAccountDestination() {
    EnterpriseFilesActivity activity =
        Robolectric.buildActivity(EnterpriseFilesActivity.class).setup().get();
    int toolbarId = activity.getResources().getIdentifier(
        "topAppBar", "id", activity.getPackageName());
    int accountActionId = activity.getResources().getIdentifier(
        "action_account", "id", activity.getPackageName());

    assertThat(toolbarId).isNotEqualTo(0);
    assertThat(accountActionId).isNotEqualTo(0);
    MaterialToolbar toolbar = activity.findViewById(toolbarId);
    assertThat(toolbar.getMenu().findItem(accountActionId)).isNotNull();
    toolbar.getMenu().performIdentifierAction(accountActionId, 0);

    Intent started = shadowOf(activity).getNextStartedActivity();
    assertThat(started.getComponent().getClassName())
        .isEqualTo(AuthenticatorStatusActivity.class.getName());
  }

  @Test
  public void accountButtonIsRemovedFromFileActionRow() {
    EnterpriseFilesActivity activity =
        Robolectric.buildActivity(EnterpriseFilesActivity.class).setup().get();

    int oldButtonId = activity.getResources().getIdentifier(
        "signInButton", "id", activity.getPackageName());
    assertThat(oldButtonId).isEqualTo(0);
  }
}
