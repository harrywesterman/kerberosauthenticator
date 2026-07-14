package com.poelbos.kerberosauthenticator.internal.spnego;

import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.spnego.NegTokenInit;
import com.hierynomus.spnego.NegTokenTarg;
import com.poelbos.kerberosauthenticator.internal.ntlm.HttpNtlmV2Engine;
import com.poelbos.kerberosauthenticator.internal.ntlm.NtlmIdentity;
import java.util.Arrays;

/** Routes each request-local HTTP SPNEGO round to Kerberos or NTLMv2. */
public final class HttpSpnegoCoordinator {
  public interface KerberosProvider {
    KerberosRound next(
        String host, byte[] incomingToken, byte[] exportedContext, String selectedService);
  }

  public interface CredentialProvider {
    boolean isAvailable(String username, String realm);
    char[] load(String username, String realm);
  }

  public static final class KerberosRound {
    private final boolean successful;
    private final byte[] token;
    private final byte[] context;
    private final String selectedService;
    private final String error;

    private KerberosRound(
        boolean successful,
        byte[] token,
        byte[] context,
        String selectedService,
        String error) {
      this.successful = successful;
      this.token = copy(token);
      this.context = copy(context);
      this.selectedService = selectedService;
      this.error = error;
    }

    public static KerberosRound success(
        byte[] token, byte[] context, String selectedService) {
      return new KerberosRound(true, token, context, selectedService, null);
    }

    public static KerberosRound failure(String error) {
      return new KerberosRound(false, null, null, null, error);
    }
  }

  private final KerberosProvider kerberos;
  private final HttpNtlmV2Engine ntlm;
  private final CredentialProvider credentials;

  public HttpSpnegoCoordinator(
      KerberosProvider kerberos, HttpNtlmV2Engine ntlm, CredentialProvider credentials) {
    this.kerberos = kerberos;
    this.ntlm = ntlm;
    this.credentials = credentials;
  }

  public HttpSpnegoResult nextToken(
      String requestedHost,
      String accountName,
      String realm,
      String ntlmDomain,
      boolean ntlmEnabled,
      byte[] incomingToken,
      SpnegoNegotiationState state) {
    final String host;
    try {
      host = SpnegoStateCodec.normalizeHost(requestedHost);
      if (state != null && !host.equals(SpnegoStateCodec.normalizeHost(state.getHost()))) {
        return HttpSpnegoResult.failure(
            HttpSpnegoResult.ERR_INVALID_RESPONSE, "SPNEGO context host mismatch");
      }
    } catch (IllegalArgumentException error) {
      return HttpSpnegoResult.failure(HttpSpnegoResult.ERR_INVALID_RESPONSE, error.getMessage());
    }

    if (state == null) {
      return initialOffer(host, accountName, realm, ntlmDomain, ntlmEnabled);
    }
    if (state.getPhase() == SpnegoNegotiationState.Phase.NTLM_TYPE3_SENT) {
      return HttpSpnegoResult.failure(
          HttpSpnegoResult.ERR_INVALID_AUTH_CREDENTIALS, "NTLM credentials were rejected");
    }
    if (state.getMechanism() == SpnegoNegotiationState.Mechanism.NTLM) {
      return finishNtlm(
          host, accountName, realm, ntlmDomain, ntlmEnabled, incomingToken, state);
    }

    try {
      NegTokenTarg server = new NegTokenTarg().read(incomingToken);
      if (HttpNtlmV2Engine.NTLMSSP_OID.equals(server.getSupportedMech())) {
        return selectNtlm(
            host, accountName, realm, ntlmDomain, ntlmEnabled, incomingToken, server);
      }
    } catch (Exception error) {
      return HttpSpnegoResult.failure(
          HttpSpnegoResult.ERR_INVALID_RESPONSE, "Invalid SPNEGO server response");
    }

    KerberosRound round =
        kerberos.next(
            host,
            incomingToken,
            state.getKerberosContext(),
            state.getSelectedService());
    if (!round.successful || round.token == null) {
      return HttpSpnegoResult.failure(
          HttpSpnegoResult.ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS, round.error);
    }
    SpnegoNegotiationState nextState =
        round.context == null
            ? null
            : SpnegoNegotiationState.kerberos(
                host,
                round.selectedService == null ? state.getSelectedService() : round.selectedService,
                round.context);
    return HttpSpnegoResult.success(
        round.token,
        nextState,
        SpnegoNegotiationState.Mechanism.KERBEROS,
        round.selectedService == null ? state.getSelectedService() : round.selectedService);
  }

  private HttpSpnegoResult initialOffer(
      String host,
      String accountName,
      String realm,
      String ntlmDomain,
      boolean ntlmEnabled) {
    KerberosRound round = kerberos.next(host, null, null, null);
    if (!round.successful || round.token == null) {
      return HttpSpnegoResult.failure(
          HttpSpnegoResult.ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS, round.error);
    }
    boolean ntlmEligible =
        ntlmEnabled
            && ntlmDomain != null
            && credentials.isAvailable(accountName, realm);
    byte[] token = round.token;
    if (ntlmEligible) {
      try {
        token = appendNtlm(round.token);
      } catch (Exception error) {
        return HttpSpnegoResult.failure(
            HttpSpnegoResult.ERR_INVALID_RESPONSE, "Invalid optimistic Kerberos token");
      }
    }
    SpnegoNegotiationState nextState =
        round.context == null
            ? SpnegoNegotiationState.offered(host)
            : SpnegoNegotiationState.offered(host, round.selectedService, round.context);
    return HttpSpnegoResult.success(token, nextState);
  }

  private HttpSpnegoResult selectNtlm(
      String host,
      String accountName,
      String realm,
      String ntlmDomain,
      boolean ntlmEnabled,
      byte[] incomingToken,
      NegTokenTarg server) {
    HttpSpnegoResult eligibility = ensureNtlmEligible(
        accountName, realm, ntlmDomain, ntlmEnabled);
    if (eligibility != null) return eligibility;

    byte[] wrappedType1 = ntlm.createType1();
    byte[] type1 = HttpNtlmV2Engine.responseToken(wrappedType1);
    if (isNtlmMessage(server.getResponseToken(), 2)) {
      return createType3(
          host, accountName, realm, ntlmDomain, type1, incomingToken);
    }
    return HttpSpnegoResult.success(
        wrappedType1, SpnegoNegotiationState.ntlmType1Sent(host, type1));
  }

  private HttpSpnegoResult finishNtlm(
      String host,
      String accountName,
      String realm,
      String ntlmDomain,
      boolean ntlmEnabled,
      byte[] incomingToken,
      SpnegoNegotiationState state) {
    HttpSpnegoResult eligibility = ensureNtlmEligible(
        accountName, realm, ntlmDomain, ntlmEnabled);
    if (eligibility != null) return eligibility;
    return createType3(
        host, accountName, realm, ntlmDomain, state.getNtlmType1(), incomingToken);
  }

  private HttpSpnegoResult createType3(
      String host,
      String accountName,
      String realm,
      String ntlmDomain,
      byte[] type1,
      byte[] incomingToken) {
    final NtlmIdentity identity;
    try {
      identity = NtlmIdentity.parse(accountName, realm, ntlmDomain);
    } catch (IllegalArgumentException error) {
      return HttpSpnegoResult.failure(
          HttpSpnegoResult.ERR_MALFORMED_IDENTITY, error.getMessage());
    }
    char[] password = credentials.load(accountName, realm);
    if (password == null) {
      return HttpSpnegoResult.failure(
          HttpSpnegoResult.ERR_MISSING_AUTH_CREDENTIALS, "NTLM credentials unavailable");
    }
    try {
      byte[] type3 = ntlm.createType3(host, identity, password, type1, incomingToken);
      return HttpSpnegoResult.success(type3, SpnegoNegotiationState.ntlmType3Sent(host));
    } catch (IllegalArgumentException error) {
      return HttpSpnegoResult.failure(
          HttpSpnegoResult.ERR_INVALID_RESPONSE, "Invalid NTLM challenge");
    } finally {
      Arrays.fill(password, '\0');
    }
  }

  private HttpSpnegoResult ensureNtlmEligible(
      String accountName, String realm, String ntlmDomain, boolean ntlmEnabled) {
    if (!ntlmEnabled || ntlmDomain == null) {
      return HttpSpnegoResult.failure(
          HttpSpnegoResult.ERR_UNSUPPORTED_AUTH_SCHEME, "HTTP NTLMv2 is disabled");
    }
    if (!credentials.isAvailable(accountName, realm)) {
      return HttpSpnegoResult.failure(
          HttpSpnegoResult.ERR_MISSING_AUTH_CREDENTIALS, "NTLM credentials unavailable");
    }
    return null;
  }

  private static byte[] appendNtlm(byte[] kerberosToken) throws Exception {
    InspectableNegTokenInit parsed = new InspectableNegTokenInit();
    parsed.read(kerberosToken);
    NegTokenInit combined = new NegTokenInit();
    boolean hasNtlm = false;
    for (ASN1ObjectIdentifier mechanism : parsed.getSupportedMechTypes()) {
      combined.addSupportedMech(mechanism);
      if (HttpNtlmV2Engine.NTLMSSP_OID.equals(mechanism)) hasNtlm = true;
    }
    if (!hasNtlm) combined.addSupportedMech(HttpNtlmV2Engine.NTLMSSP_OID);
    combined.setMechToken(parsed.optimisticToken());
    Buffer.PlainBuffer encoded = new Buffer.PlainBuffer(Endian.LE);
    combined.write(encoded);
    return encoded.getCompactData();
  }

  private static boolean isNtlmMessage(byte[] token, int messageType) {
    if (token == null || token.length < 12) return false;
    byte[] signature = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    for (int i = 0; i < signature.length; i++) {
      if (token[i] != signature[i]) return false;
    }
    int actual =
        (token[8] & 0xff)
            | ((token[9] & 0xff) << 8)
            | ((token[10] & 0xff) << 16)
            | ((token[11] & 0xff) << 24);
    return actual == messageType;
  }

  private static byte[] copy(byte[] value) {
    return value == null ? null : Arrays.copyOf(value, value.length);
  }

  private static final class InspectableNegTokenInit extends NegTokenInit {
    byte[] optimisticToken() { return copy(mechToken); }
  }
}
