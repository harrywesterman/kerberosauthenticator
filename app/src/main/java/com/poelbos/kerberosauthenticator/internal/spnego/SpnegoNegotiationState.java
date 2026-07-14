package com.poelbos.kerberosauthenticator.internal.spnego;

import java.util.Arrays;

/** Request-local state carried by Chrome between HTTP Negotiate rounds. */
public final class SpnegoNegotiationState {
  public enum Mechanism { UNSELECTED, KERBEROS, NTLM }

  public enum Phase { OFFERED, KERBEROS_CONTINUE, NTLM_TYPE1_SENT, NTLM_TYPE3_SENT }

  private final String host;
  private final Mechanism mechanism;
  private final Phase phase;
  private final String selectedService;
  private final byte[] kerberosContext;
  private final byte[] ntlmType1;

  private SpnegoNegotiationState(
      String host,
      Mechanism mechanism,
      Phase phase,
      String selectedService,
      byte[] kerberosContext,
      byte[] ntlmType1) {
    this.host = host;
    this.mechanism = mechanism;
    this.phase = phase;
    this.selectedService = selectedService;
    this.kerberosContext = copy(kerberosContext);
    this.ntlmType1 = copy(ntlmType1);
    validate();
  }

  public static SpnegoNegotiationState offered(String host) {
    return new SpnegoNegotiationState(host, Mechanism.UNSELECTED, Phase.OFFERED, null, null, null);
  }

  public static SpnegoNegotiationState offered(
      String host, String selectedService, byte[] kerberosContext) {
    return new SpnegoNegotiationState(
        host, Mechanism.UNSELECTED, Phase.OFFERED, selectedService, kerberosContext, null);
  }

  public static SpnegoNegotiationState kerberos(
      String host, String selectedService, byte[] kerberosContext) {
    return new SpnegoNegotiationState(
        host,
        Mechanism.KERBEROS,
        Phase.KERBEROS_CONTINUE,
        selectedService,
        kerberosContext,
        null);
  }

  public static SpnegoNegotiationState ntlmType1Sent(String host, byte[] ntlmType1) {
    return new SpnegoNegotiationState(
        host, Mechanism.NTLM, Phase.NTLM_TYPE1_SENT, null, null, ntlmType1);
  }

  public static SpnegoNegotiationState ntlmType3Sent(String host) {
    return new SpnegoNegotiationState(
        host, Mechanism.NTLM, Phase.NTLM_TYPE3_SENT, null, null, null);
  }

  static SpnegoNegotiationState decoded(
      String host,
      Mechanism mechanism,
      Phase phase,
      String selectedService,
      byte[] kerberosContext,
      byte[] ntlmType1) {
    return new SpnegoNegotiationState(
        host, mechanism, phase, selectedService, kerberosContext, ntlmType1);
  }

  private void validate() {
    if (host == null || host.isEmpty()) throw new IllegalArgumentException("Missing state host");
    switch (mechanism) {
      case UNSELECTED:
        if (phase != Phase.OFFERED) throw new IllegalArgumentException("Invalid offered phase");
        if ((selectedService == null) != (kerberosContext == null)) {
          throw new IllegalArgumentException("Incomplete optimistic Kerberos state");
        }
        break;
      case KERBEROS:
        if (phase != Phase.KERBEROS_CONTINUE
            || selectedService == null
            || kerberosContext == null) {
          throw new IllegalArgumentException("Invalid Kerberos state");
        }
        break;
      case NTLM:
        if (phase == Phase.NTLM_TYPE1_SENT && ntlmType1 == null) {
          throw new IllegalArgumentException("Missing NTLM Type 1 state");
        }
        if (phase != Phase.NTLM_TYPE1_SENT && phase != Phase.NTLM_TYPE3_SENT) {
          throw new IllegalArgumentException("Invalid NTLM phase");
        }
        break;
      default:
        throw new IllegalArgumentException("Unknown mechanism");
    }
  }

  public String getHost() { return host; }

  public Mechanism getMechanism() { return mechanism; }

  public Phase getPhase() { return phase; }

  public String getSelectedService() { return selectedService; }

  public byte[] getKerberosContext() { return copy(kerberosContext); }

  public byte[] getNtlmType1() { return copy(ntlmType1); }

  private static byte[] copy(byte[] value) {
    return value == null ? null : Arrays.copyOf(value, value.length);
  }
}
