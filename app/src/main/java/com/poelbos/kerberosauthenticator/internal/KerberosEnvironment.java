/*
 * Copyright 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package com.poelbos.kerberosauthenticator.internal;

import static com.poelbos.kerberosauthenticator.Constants.TAG;

import android.content.Context;
import android.text.TextUtils;
import android.util.Log;
import com.google.common.base.Ascii;
import java.io.IOException;

/** Configures the Kerberos system properties required by the OpenJDK Kerberos port. */
public final class KerberosEnvironment {
  private KerberosEnvironment() {}

  public static String configure(
      Context context, String adDomain, String configuredDomainController, boolean debug)
      throws IOException {
    String realm = Ascii.toUpperCase(adDomain);
    String domainController = trimToNull(configuredDomainController);
    if (domainController == null) {
      Log.i(TAG, String.format("Discovering KDC for realm %s from DNS SRV records.", realm));
      domainController = DnsKdcDiscovery.discover(context, realm);
    }
    if (TextUtils.isEmpty(domainController)) {
      throw new IOException("No domain controller configured and DNS SRV lookup found no KDC.");
    }

    System.setProperty("java.security.krb5.kdc", domainController);
    System.setProperty("java.security.krb5.realm", realm);
    System.setProperty("sun.security.jgss.debug", Boolean.toString(debug));
    return domainController;
  }

  private static String trimToNull(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }
}
