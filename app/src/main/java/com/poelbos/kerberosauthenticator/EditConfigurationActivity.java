package com.poelbos.kerberosauthenticator;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

/** Activity to enter AD credentials when no managed configuration is available. */
public class EditConfigurationActivity extends Activity {

  static final String LOCAL_CONFIG_PREFS_NAME = "kerberos_local_config";

  public static Intent getEditIntent(Context context) {
    return getEditIntent(context, null, null);
  }

  public static Intent getEditIntent(
      Context context,
      android.accounts.AccountAuthenticatorResponse response,
      String serviceName) {
    Intent intent = new Intent(context, EditConfigurationActivity.class);
    if (response != null) {
      intent.putExtra(android.accounts.AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
    }
    if (serviceName != null) {
      intent.putExtra(Constants.SERVICE_NAME, serviceName);
    }
    return intent;
  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_edit_configuration);

    EditText usernameField = findViewById(R.id.edit_username);
    EditText passwordField = findViewById(R.id.edit_password);
    EditText domainField = findViewById(R.id.edit_domain);

    SharedPreferences prefs = getSharedPreferences(LOCAL_CONFIG_PREFS_NAME, MODE_PRIVATE);
    usernameField.setText(prefs.getString("username", ""));
    passwordField.setText(prefs.getString("password", ""));
    domainField.setText(prefs.getString("adDomain", ""));

    findViewById(R.id.btn_save).setOnClickListener(v -> {
      SharedPreferences.Editor editor = prefs.edit();
      editor.putString("username", usernameField.getText().toString().trim());
      editor.putString("password", passwordField.getText().toString().trim());
      editor.putString("adDomain", domainField.getText().toString().trim());
      editor.apply();

      android.accounts.AccountAuthenticatorResponse response =
          getIntent().getParcelableExtra(
              android.accounts.AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE);
      Intent intent;
      if (response != null) {
        intent = LoginActivity.getAuthenticateIntent(
            this, response, getIntent().getStringExtra(Constants.SERVICE_NAME));
      } else {
        intent = new Intent(this, AuthenticatorStatusActivity.class);
      }
      intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
      startActivity(intent);
      finish();
    });

    findViewById(R.id.btn_clear).setOnClickListener(v -> {
      prefs.edit().clear().apply();
      finish();
    });
  }

  static boolean hasSavedConfig(Context context) {
    SharedPreferences prefs = context.getSharedPreferences(LOCAL_CONFIG_PREFS_NAME, Context.MODE_PRIVATE);
    String username = prefs.getString("username", null);
    String domain = prefs.getString("adDomain", null);
    return username != null && !username.isEmpty()
        && domain != null && !domain.isEmpty();
  }
}
