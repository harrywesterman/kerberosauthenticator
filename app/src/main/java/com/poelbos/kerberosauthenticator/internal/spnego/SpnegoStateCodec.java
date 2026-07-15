package com.poelbos.kerberosauthenticator.internal.spnego;

import android.os.Bundle;
import java.util.Locale;

/** Encodes the opaque context Chrome returns to the authenticator on the next round. */
public final class SpnegoStateCodec {
  private static final int VERSION = 1;
  private static final String VERSION_KEY = "version";
  private static final String HOST_KEY = "host";
  private static final String MECHANISM_KEY = "mechanism";
  private static final String PHASE_KEY = "phase";
  private static final String SERVICE_KEY = "selectedService";
  private static final String KERBEROS_CONTEXT_KEY = "kerberosContext";
  private static final String NTLM_TYPE1_KEY = "ntlmType1";
  private static final String NTLM_OFFERED_KEY = "ntlmOffered";

  private SpnegoStateCodec() {}

  public static Bundle encode(SpnegoNegotiationState state) {
    Bundle bundle = new Bundle();
    bundle.putInt(VERSION_KEY, VERSION);
    bundle.putString(HOST_KEY, normalizeHost(state.getHost()));
    bundle.putString(MECHANISM_KEY, state.getMechanism().name());
    bundle.putString(PHASE_KEY, state.getPhase().name());
    if (state.getSelectedService() != null) {
      bundle.putString(SERVICE_KEY, state.getSelectedService());
    }
    if (state.getKerberosContext() != null) {
      bundle.putByteArray(KERBEROS_CONTEXT_KEY, state.getKerberosContext());
    }
    if (state.getNtlmType1() != null) {
      bundle.putByteArray(NTLM_TYPE1_KEY, state.getNtlmType1());
    }
    if (state.wasNtlmOffered()) {
      bundle.putBoolean(NTLM_OFFERED_KEY, true);
    }
    return bundle;
  }

  public static SpnegoNegotiationState decode(Bundle bundle, String expectedHost) {
    if (bundle == null || bundle.getInt(VERSION_KEY, -1) != VERSION) {
      throw new IllegalArgumentException("Unsupported SPNEGO state version");
    }
    String host = normalizeHost(bundle.getString(HOST_KEY));
    if (!host.equals(normalizeHost(expectedHost))) {
      throw new IllegalArgumentException("SPNEGO state host mismatch");
    }
    try {
      return SpnegoNegotiationState.decoded(
          host,
          SpnegoNegotiationState.Mechanism.valueOf(bundle.getString(MECHANISM_KEY, "")),
          SpnegoNegotiationState.Phase.valueOf(bundle.getString(PHASE_KEY, "")),
          bundle.getString(SERVICE_KEY),
          bundle.getByteArray(KERBEROS_CONTEXT_KEY),
          bundle.getByteArray(NTLM_TYPE1_KEY),
          bundle.getBoolean(NTLM_OFFERED_KEY, false));
    } catch (RuntimeException error) {
      throw new IllegalArgumentException("Invalid SPNEGO state", error);
    }
  }

  static String normalizeHost(String host) {
    if (host == null) throw new IllegalArgumentException("Missing state host");
    String normalized = host.trim().toLowerCase(Locale.ROOT);
    while (normalized.endsWith(".")) {
      normalized = normalized.substring(0, normalized.length() - 1);
    }
    if (normalized.isEmpty()) throw new IllegalArgumentException("Missing state host");
    return normalized;
  }
}
