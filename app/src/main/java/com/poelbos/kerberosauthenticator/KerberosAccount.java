/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.poelbos.kerberosauthenticator;

import static com.poelbos.kerberosauthenticator.Constants.KERBEROS_ACCOUNT_TYPE;
import static com.poelbos.kerberosauthenticator.Constants.TAG;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import androidx.annotation.VisibleForTesting;
import android.util.Base64;
import android.util.Log;
import com.poelbos.kerberosauthenticator.BaseAuthenticatorActivity.ServiceTicketInfo;
import com.poelbos.kerberosauthenticator.internal.KerberosAccountDetails;
import java.util.Objects;

/** Kerberos account functionality. */
public class KerberosAccount {
  @VisibleForTesting static final String KEY_AD_DOMAIN = "ad_domain";
  @VisibleForTesting static final String KEY_AD_DC = "domain_controller";
  @VisibleForTesting static final String KEY_TGT = "ticket_granting_ticket";
  private static final AccountVisibilitySetter DEFAULT_ACCOUNT_VISIBILITY_SETTER =
      AccountManager::setAccountVisibility;
  private static AccountVisibilitySetter accountVisibilitySetter =
      DEFAULT_ACCOUNT_VISIBILITY_SETTER;

  private final String name;
  private final String password;
  private final Bundle userData = new Bundle();

  @VisibleForTesting
  interface AccountVisibilitySetter {
    boolean setVisibility(
        AccountManager accountManager, Account account, String packageName, int visibility);
  }

  KerberosAccount(String name, String password, String adDomain, String domainController) {
    this(name, password, adDomain, domainController, "");
  }

  private KerberosAccount(
      String name, String password, String adDomain, String domainController, String base64Tgt) {
    this.name = name;
    this.password = password;
    userData.putString(KEY_AD_DOMAIN, adDomain);
    userData.putString(KEY_AD_DC, domainController);
    userData.putString(KEY_TGT, base64Tgt);
  }

  KerberosAccount(KerberosAccountDetails accountDetails) {
    this(
        accountDetails.getUsername(),
        accountDetails.getPassword(),
        accountDetails.getActiveDirectoryDomain(),
        accountDetails.getAdDomainController());
  }

  public static void removeAccount(Context context) {
    new CredentialVault(context).delete();
    TgtRefreshScheduler.cancel(context);
    AccountManager am = AccountManager.get(context);
    Account[] accounts = am.getAccountsByType(KERBEROS_ACCOUNT_TYPE);
    if (accounts.length > 0) {
      am.removeAccountExplicitly(accounts[0]);
    }
    ServiceTicketInfo.clearServiceTicketInfo(
        context.getSharedPreferences(Constants.PREFERENCE_NAME, Activity.MODE_PRIVATE));
  }

  /**
   * Returns the Kerberos account currently configured in the AccountMAnager.
   * @return the account, or null if none is configured.
   * @throws IllegalStateException if more than one account is configured.
   */
  public static KerberosAccount getAccount(Context context) {
    AccountManager am = AccountManager.get(context);
    Account[] accounts = am.getAccountsByType(KERBEROS_ACCOUNT_TYPE);
    if (accounts.length > 1) {
      throw new IllegalStateException(
          "More than one Kerberos account available in the Account Manager");
    } else if (accounts.length < 1) {
      // Indicate there's no account.
      return null;
    }
    Account account = accounts[0];
    String password = am.getPassword(account);
    String adDomain = am.getUserData(account, KEY_AD_DOMAIN);
    String domainController = am.getUserData(account, KEY_AD_DC);
    String base64Tgt = am.getUserData(account, KEY_TGT);
    return new KerberosAccount(account.name, password, adDomain, domainController, base64Tgt);
  }

  public String getName() {
    return name;
  }

  KerberosAccount withPassword(String newPassword) {
    return new KerberosAccount(
        name,
        newPassword,
        userData.getString(KEY_AD_DOMAIN),
        userData.getString(KEY_AD_DC),
        userData.getString(KEY_TGT));
  }

  public byte[] getTicketGrantingTicket() {
    return Base64.decode(userData.getString(KEY_TGT), Base64.NO_WRAP);
  }

  void setTicketGrantingTicket(byte[] tgt) {
    userData.putString(KEY_TGT, Base64.encodeToString(tgt, Base64.NO_WRAP));
  }

  void save(Context context) {
    AccountManager am = AccountManager.get(context);
    Account[] accounts = am.getAccountsByType(KERBEROS_ACCOUNT_TYPE);
    boolean hasAccountWithIncorrectName = (accounts.length > 0) && !accounts[0].name.equals(name);
    boolean hasNoAccount = (accounts.length == 0);

    if (hasAccountWithIncorrectName) {
      throw new IllegalStateException(
          String.format(
              "Cannot save account details for user %s when the existing account is for user %s",
              name, accounts[0].name));
    }

    final Account account;
    if (hasNoAccount) {
      Log.i(TAG, "Adding Kerberos account.");
      account = new Account(name, KERBEROS_ACCOUNT_TYPE);
      am.addAccountExplicitly(account, null, userData);
      allowChromeToSeeAccount(am, account);
      return;
    }

    account = accounts[0];
    Log.i(TAG, "Updating stored TGT.");
    am.setUserData(account, KEY_TGT, userData.getString(KEY_TGT));

    // The account manager persists the TGT and account metadata, never the AD password.
    am.clearPassword(account);

    final String domain = userData.getString(KEY_AD_DOMAIN);
    final String currentDomain = am.getUserData(account, KEY_AD_DOMAIN);
    if (!Objects.equals(currentDomain, domain)) {
      Log.i(TAG, "Updating configured Kerberos realm.");
      am.setUserData(account, KEY_AD_DOMAIN, domain);
    }

    final String domainController = userData.getString(KEY_AD_DC);
    String currentDomainController = am.getUserData(account, KEY_AD_DC);
    if (!Objects.equals(currentDomainController, domainController)) {
      Log.i(TAG, "Updating configured KDC.");
      am.setUserData(account, KEY_AD_DC, domainController);
    }
    allowChromeToSeeAccount(am, account);
  }

  private static void allowChromeToSeeAccount(AccountManager accountManager, Account account) {
    boolean visible =
        accountVisibilitySetter.setVisibility(
            accountManager,
            account,
            Constants.CHROME_PACKAGE_NAME,
            AccountManager.VISIBILITY_VISIBLE);
    if (!visible) {
      Log.w(TAG, "Could not make Kerberos account visible to Chrome.");
    }
  }

  @VisibleForTesting
  static void setAccountVisibilitySetterForTesting(AccountVisibilitySetter setter) {
    accountVisibilitySetter = setter;
  }

  @VisibleForTesting
  static void resetAccountVisibilitySetterForTesting() {
    accountVisibilitySetter = DEFAULT_ACCOUNT_VISIBILITY_SETTER;
  }

  String getDomainController() {
    return userData.getString(KEY_AD_DC);
  }

  public String getDomain() {
    return userData.getString(KEY_AD_DOMAIN);
  }

  String getPassword() {
    return password;
  }
}
