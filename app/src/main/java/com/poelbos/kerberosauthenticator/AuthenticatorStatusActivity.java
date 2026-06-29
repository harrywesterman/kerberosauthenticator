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

import static com.poelbos.kerberosauthenticator.Constants.TAG;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

/** Show the authentication status for the current account. */
public class AuthenticatorStatusActivity extends BaseAuthenticatorActivity {
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    if (!accountConfiguration.hasManagedConfigs()) {
      if (EditConfigurationActivity.hasDebugConfig(this)) {
        // Debug config exists from a previous session, use it.
        // AccountConfiguration already picked it up from SharedPreferences.
      } else if (BuildConfig.DEBUG) {
        // No config at all: show debug entry screen so the user can enter credentials.
        startActivity(new Intent(this, EditConfigurationActivity.class));
        finish();
        return;
      } else {
        startActivity(DeclineAddingAccountActivity.getDeclineIntentDueToConfigMissing(this, null));
        finish();
        return;
      }
    }

    setContentView(R.layout.authenticator);

    boolean isLaunchedByUser = Intent.ACTION_MAIN.equals(getIntent().getAction());
    // Initialise the UI, showing a "Dismiss" button.
    initUI(isLaunchedByUser, "");

    // If only the status is shown, the activity remains open until the user taps the dismiss
    // button to finish it.
    Log.d(TAG, "Finished creating status activity.");
  }
}
