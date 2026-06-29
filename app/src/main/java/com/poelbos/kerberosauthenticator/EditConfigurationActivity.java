package com.poelbos.kerberosauthenticator;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

/**
 * Debug-only activity to enter AD credentials when no managed configuration is available.
 * Only enabled in debug builds. Saves credentials to SharedPreferences as fallback.
 */
public class EditConfigurationActivity extends Activity {

  static final String DEBUG_PREFS_NAME = "kerberos_debug_config";

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    if (!BuildConfig.DEBUG) {
      finish();
      return;
    }
    setContentView(R.layout.activity_edit_configuration);

    EditText usernameField = findViewById(R.id.edit_username);
    EditText passwordField = findViewById(R.id.edit_password);
    EditText domainField = findViewById(R.id.edit_domain);
    EditText controllerField = findViewById(R.id.edit_controller);

    SharedPreferences prefs = getSharedPreferences(DEBUG_PREFS_NAME, MODE_PRIVATE);
    usernameField.setText(prefs.getString("username", ""));
    passwordField.setText(prefs.getString("password", ""));
    domainField.setText(prefs.getString("adDomain", ""));
    controllerField.setText(prefs.getString("adController", ""));

    findViewById(R.id.btn_save).setOnClickListener(v -> {
      SharedPreferences.Editor editor = prefs.edit();
      editor.putString("username", usernameField.getText().toString().trim());
      editor.putString("password", passwordField.getText().toString().trim());
      editor.putString("adDomain", domainField.getText().toString().trim());
      editor.putString("adController", controllerField.getText().toString().trim());
      editor.apply();

      Intent intent = new Intent(this, AuthenticatorStatusActivity.class);
      intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
      startActivity(intent);
      finish();
    });

    findViewById(R.id.btn_clear).setOnClickListener(v -> {
      prefs.edit().clear().apply();
      finish();
    });
  }

  static boolean hasDebugConfig(Context context) {
    if (!BuildConfig.DEBUG) {
      return false;
    }
    SharedPreferences prefs = context.getSharedPreferences(DEBUG_PREFS_NAME, Context.MODE_PRIVATE);
    String username = prefs.getString("username", null);
    String domain = prefs.getString("adDomain", null);
    String controller = prefs.getString("adController", null);
    return username != null && !username.isEmpty()
        && domain != null && !domain.isEmpty()
        && controller != null && !controller.isEmpty();
  }
}
