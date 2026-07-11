package com.poelbos.kerberosauthenticator;

import android.content.Context;
import androidx.work.Constraints;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.NetworkType;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import java.util.concurrent.TimeUnit;

/** Owns the single daily TGT refresh job. */
public final class TgtRefreshScheduler {
  static final String UNIQUE_WORK = "daily-enterprise-tgt-refresh";

  private TgtRefreshScheduler() {}

  public static void schedule(Context context) {
    Constraints constraints = new Constraints.Builder()
        .setRequiredNetworkType(NetworkType.CONNECTED).build();
    PeriodicWorkRequest request = new PeriodicWorkRequest.Builder(
        TgtRefreshWorker.class, 24, TimeUnit.HOURS, 2, TimeUnit.HOURS)
        .setConstraints(constraints)
        .build();
    try {
      WorkManager.getInstance(context).enqueueUniquePeriodicWork(
          UNIQUE_WORK, ExistingPeriodicWorkPolicy.UPDATE, request);
    } catch (IllegalStateException exception) {
      android.util.Log.w(Constants.TAG, "WorkManager is not available", exception);
    }
  }

  public static void cancel(Context context) {
    try {
      WorkManager.getInstance(context).cancelUniqueWork(UNIQUE_WORK);
    } catch (IllegalStateException exception) {
      android.util.Log.w(Constants.TAG, "WorkManager is not available", exception);
    }
  }
}
