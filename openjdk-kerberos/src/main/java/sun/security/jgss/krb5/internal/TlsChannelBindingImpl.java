/*
 * Copyright 2026
 * Licensed under the Apache License, Version 2.0.
 */
package sun.security.jgss.krb5.internal;

import org.ietf.jgss.ChannelBinding;

/** Marks RFC 5929 TLS channel-binding data for the Kerberos checksum encoding. */
public final class TlsChannelBindingImpl extends ChannelBinding {
  public TlsChannelBindingImpl(byte[] applicationData) {
    super(applicationData);
  }
}
