package com.poelbos.kerberosauthenticator.files;

import static com.google.common.truth.Truth.assertThat;
import static org.robolectric.Shadows.shadowOf;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.Context;
import android.content.Intent;
import android.content.RestrictionsManager;
import android.os.Bundle;
import androidx.test.core.app.ApplicationProvider;
import com.google.android.material.appbar.MaterialToolbar;
import com.poelbos.kerberosauthenticator.AuthenticatorStatusActivity;
import com.poelbos.kerberosauthenticator.LoginActivity;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 35)
public final class EnterpriseFilesActivityTest {
  private AccountManager accountManager;
  private RestrictionsManager restrictions;

  @Before
  public void setUp() {
    Context context = ApplicationProvider.getApplicationContext();
    accountManager = AccountManager.get(context);
    for (Account account : accountManager.getAccountsByType("AndroidEnterpriseKerberos")) {
      accountManager.removeAccountExplicitly(account);
    }
    restrictions = (RestrictionsManager) context.getSystemService(Context.RESTRICTIONS_SERVICE);
    shadowOf(restrictions).setApplicationRestrictions(new Bundle());
  }

  @Test
  public void managedRealmWithoutAccountOpensAccountSignInFromLauncher() {
    setManagedRealm("EXAMPLE.COM");

    EnterpriseFilesActivity activity =
        Robolectric.buildActivity(EnterpriseFilesActivity.class).setup().get();

    Intent started = shadowOf(activity).getNextStartedActivity();
    assertThat(started.getComponent().getClassName()).isEqualTo(LoginActivity.class.getName());
    assertThat(started.getBooleanExtra(LoginActivity.RETURN_TO_ACCOUNT, false)).isTrue();
  }

  @Test
  public void missingOrEmptyManagedRealmDoesNotOpenAccountSignIn() {
    EnterpriseFilesActivity missingRealmActivity =
        Robolectric.buildActivity(EnterpriseFilesActivity.class).setup().get();
    assertThat(shadowOf(missingRealmActivity).getNextStartedActivity()).isNull();

    setManagedRealm("  ");
    EnterpriseFilesActivity emptyRealmActivity =
        Robolectric.buildActivity(EnterpriseFilesActivity.class).setup().get();

    assertThat(shadowOf(emptyRealmActivity).getNextStartedActivity()).isNull();
  }

  @Test
  public void accountSignInIsOfferedOnlyOncePerActivityInstance() {
    setManagedRealm("EXAMPLE.COM");
    ActivityController<EnterpriseFilesActivity> controller =
        Robolectric.buildActivity(EnterpriseFilesActivity.class).setup();
    EnterpriseFilesActivity activity = controller.get();
    assertThat(shadowOf(activity).getNextStartedActivity()).isNotNull();

    controller.pause().resume();

    assertThat(shadowOf(activity).getNextStartedActivity()).isNull();
  }

  @Test
  public void accountInManagedRealmDoesNotOpenAccountSignIn() {
    setManagedRealm("EXAMPLE.COM");
    Account account = new Account("alice", "AndroidEnterpriseKerberos");
    Bundle userData = new Bundle();
    userData.putString("ad_domain", "EXAMPLE.COM");
    assertThat(accountManager.addAccountExplicitly(account, null, userData)).isTrue();

    EnterpriseFilesActivity activity =
        Robolectric.buildActivity(EnterpriseFilesActivity.class).setup().get();

    assertThat(shadowOf(activity).getNextStartedActivity()).isNull();
  }

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

  private void setManagedRealm(String realm) {
    Bundle managed = new Bundle();
    managed.putString(EnterpriseConfiguration.REALM, realm);
    shadowOf(restrictions).setApplicationRestrictions(managed);
  }
}
