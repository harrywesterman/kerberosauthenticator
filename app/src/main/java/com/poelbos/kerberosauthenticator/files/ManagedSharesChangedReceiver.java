package com.poelbos.kerberosauthenticator.files;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Refresh system Files roots and close handles when MDM restrictions change. */
public final class ManagedSharesChangedReceiver extends BroadcastReceiver {
  @Override public void onReceive(Context context, Intent intent) {
    if (Intent.ACTION_APPLICATION_RESTRICTIONS_CHANGED.equals(intent.getAction())) {
      com.poelbos.kerberosauthenticator.KerberosAuthenticator.clearPendingHttpAuthentication();
      EnterpriseDocumentsProvider.invalidate(context);
    }
  }
}
