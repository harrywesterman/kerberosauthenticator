package com.poelbos.kerberosauthenticator;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import androidx.core.app.NotificationCompat;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import com.poelbos.kerberosauthenticator.internal.KerberosAccountDetails;
import com.poelbos.kerberosauthenticator.internal.TicketGrantingTicket;
import com.poelbos.kerberosauthenticator.internal.kinit.UserAuthenticationTask;
import java.util.Arrays;

/** Acquires a completely new TGT using the device-bound stored credential. */
public final class TgtRefreshWorker extends Worker {
  public static final String STATUS_PREFS = "tgt_refresh_status";
  public static final String LAST_SUCCESS = "last_success";
  public static final String LAST_CATEGORY = "last_category";
  private static final String CHANNEL = "kerberos_account";

  public TgtRefreshWorker(@NonNull Context context, @NonNull WorkerParameters parameters) {
    super(context, parameters);
  }

  @NonNull @Override public Result doWork() {
    Context context = getApplicationContext();
    KerberosAccount account = KerberosAccount.getAccount(context);
    if (account == null) return Result.success();
    CredentialVault vault = new CredentialVault(context);
    char[] password = vault.load(account.getName(), account.getDomain());
    if (password == null) {
      record(context, "reauthentication_required", false);
      return Result.success();
    }
    try {
      UserAuthenticationTask.AuthenticationOutcome outcome = UserAuthenticationTask.authenticate(
          context,
          new KerberosAccountDetails(account.getName(), new String(password), account.getDomain(),
              account.getDomainController()));
      if (outcome.getResult().successful() && outcome.getSubject() != null) {
        TicketGrantingTicket tgt = new TicketGrantingTicket(outcome.getSubject());
        account.setTicketGrantingTicket(tgt.asSerialized());
        account.save(context);
        record(context, "success", true);
        return Result.success();
      }
      if (outcome.getResult().isCredentialRejected()) {
        vault.delete();
        KerberosAccount.removeAccount(context);
        record(context, "credentials_rejected", false);
        notifyReauthentication(context);
        return Result.success();
      }
      record(context, "temporary_kdc_failure", false);
      return Result.retry();
    } finally {
      Arrays.fill(password, '\0');
    }
  }

  private static void record(Context context, String category, boolean successful) {
    SharedPreferences.Editor editor = context.getSharedPreferences(STATUS_PREFS, Context.MODE_PRIVATE)
        .edit().putString(LAST_CATEGORY, category);
    if (successful) editor.putLong(LAST_SUCCESS, System.currentTimeMillis());
    editor.apply();
  }

  private static void notifyReauthentication(Context context) {
    NotificationManager manager =
        (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
    if (manager == null) return;
    manager.createNotificationChannel(new NotificationChannel(
        CHANNEL, "Work account", NotificationManager.IMPORTANCE_DEFAULT));
    android.app.PendingIntent intent = android.app.PendingIntent.getActivity(
        context, 0, new android.content.Intent(context, AuthenticatorStatusActivity.class),
        android.app.PendingIntent.FLAG_UPDATE_CURRENT | android.app.PendingIntent.FLAG_IMMUTABLE);
    manager.notify(7001, new NotificationCompat.Builder(context, CHANNEL)
        .setSmallIcon(R.mipmap.ic_launcher)
        .setContentTitle("Sign-in required")
        .setContentText("Your work account must be signed in again.")
        .setContentIntent(intent).setAutoCancel(true).build());
  }
}
