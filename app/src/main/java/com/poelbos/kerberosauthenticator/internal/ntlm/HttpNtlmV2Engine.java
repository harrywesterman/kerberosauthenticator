package com.poelbos.kerberosauthenticator.internal.ntlm;

import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_KEY_EXCH;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SEAL;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_SIGN;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_TARGET_INFO;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET;

import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.ntlm.av.AvId;
import com.hierynomus.ntlm.av.AvPairChannelBindings;
import com.hierynomus.ntlm.av.AvPairFlags;
import com.hierynomus.ntlm.av.AvPairTimestamp;
import com.hierynomus.ntlm.av.AvPairString;
import com.hierynomus.ntlm.functions.ComputedNtlmV2Response;
import com.hierynomus.ntlm.functions.NtlmFunctions;
import com.hierynomus.ntlm.functions.NtlmV2Functions;
import com.hierynomus.ntlm.messages.NtlmAuthenticate;
import com.hierynomus.ntlm.messages.NtlmChallenge;
import com.hierynomus.ntlm.messages.NtlmNegotiate;
import com.hierynomus.ntlm.messages.NtlmNegotiateFlag;
import com.hierynomus.ntlm.messages.TargetInfo;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.spnego.NegTokenTarg;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Random;
import java.util.Set;
import java.util.function.LongSupplier;

/** HTTP-specific NTLMv2 message generation inside SPNEGO. */
public final class HttpNtlmV2Engine {
  public static final ASN1ObjectIdentifier NTLMSSP_OID =
      new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.10");

  private final Random random;
  private final LongSupplier clockMillis;
  private final SecurityProvider securityProvider;

  public HttpNtlmV2Engine(
      Random random, LongSupplier clockMillis, SecurityProvider securityProvider) {
    this.random = random;
    this.clockMillis = clockMillis;
    this.securityProvider = securityProvider;
  }

  public byte[] createType1() {
    EnumSet<NtlmNegotiateFlag> flags =
        EnumSet.of(
            NTLMSSP_NEGOTIATE_UNICODE,
            NTLMSSP_NEGOTIATE_NTLM,
            NTLMSSP_REQUEST_TARGET,
            NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
            NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
            NTLMSSP_NEGOTIATE_SIGN,
            NTLMSSP_NEGOTIATE_KEY_EXCH,
            NTLMSSP_NEGOTIATE_128);
    NtlmNegotiate message = new NtlmNegotiate(flags, "", "", null, true);
    Buffer.PlainBuffer raw = new Buffer.PlainBuffer(Endian.LE);
    message.write(raw);
    return wrap(raw.getCompactData());
  }

  public byte[] createType3(
      String host,
      NtlmIdentity identity,
      char[] password,
      byte[] type1,
      byte[] wrappedChallenge) {
    byte[] type2 = null;
    byte[] sessionBaseKey = null;
    byte[] ntResponse = null;
    byte[] lmResponse = null;
    byte[] keyExchangeKey = null;
    byte[] exportedSessionKey = null;
    byte[] encryptedSessionKey = null;
    byte[] mic = null;
    try {
      NegTokenTarg targ = new NegTokenTarg().read(wrappedChallenge);
      if (targ.getSupportedMech() != null && !NTLMSSP_OID.equals(targ.getSupportedMech())) {
        throw new IllegalArgumentException("Server did not select NTLMSSP");
      }
      type2 = targ.getResponseToken();
      if (type2 == null || type2.length < 48) {
        throw new IllegalArgumentException("Missing NTLM Type 2 challenge");
      }
      validateType2(type2);
      NtlmChallenge challenge = new NtlmChallenge();
      challenge.read(new Buffer.PlainBuffer(type2, Endian.LE));
      validateFlags(challenge.getNegotiateFlags());
      if (challenge.getTargetInfo() == null) {
        throw new IllegalArgumentException("NTLMv2 requires TargetInfo");
      }

      TargetInfo targetInfo = challenge.getTargetInfo().copy();
      targetInfo.putAvPair(new AvPairChannelBindings(new byte[16]));
      targetInfo.putAvPair(new AvPairString(AvId.MsvAvTargetName, "HTTP/" + host));
      AvPairFlags existing = targetInfo.getAvPair(AvId.MsvAvFlags);
      boolean includeMic =
          targetInfo.hasAvPair(AvId.MsvAvTimestamp)
              || (existing != null && (existing.getValue() & 0x02L) != 0);
      if (includeMic) {
        long flags = 0x02L;
        if (existing != null) flags |= existing.getValue();
        targetInfo.putAvPair(new AvPairFlags(flags));
      }

      long time = FileTime.ofEpochMillis(clockMillis.getAsLong()).getWindowsTimeStamp();
      AvPairTimestamp timestamp = targetInfo.getAvPair(AvId.MsvAvTimestamp);
      if (timestamp != null) time = timestamp.getValue().getWindowsTimeStamp();

      NtlmV2Functions functions = new NtlmV2Functions(random, securityProvider);
      ComputedNtlmV2Response computed =
          functions.computeResponse(
              identity.getUsername(), identity.getDomain(), password, challenge, time, targetInfo);
      sessionBaseKey = computed.getSessionBaseKey();
      ntResponse = computed.getNtResponse();
      lmResponse = new byte[0];
      keyExchangeKey = functions.kxKey(
          sessionBaseKey, computed.getLmResponse(), challenge.getServerChallenge());

      Set<NtlmNegotiateFlag> serverFlags = challenge.getNegotiateFlags();
      if (serverFlags.contains(NTLMSSP_NEGOTIATE_KEY_EXCH)
          && (serverFlags.contains(NTLMSSP_NEGOTIATE_SIGN)
              || serverFlags.contains(NTLMSSP_NEGOTIATE_SEAL)
              || serverFlags.contains(NTLMSSP_NEGOTIATE_ALWAYS_SIGN))) {
        exportedSessionKey = new byte[16];
        random.nextBytes(exportedSessionKey);
        encryptedSessionKey = NtlmFunctions.rc4k(
            securityProvider, keyExchangeKey, exportedSessionKey);
      } else {
        exportedSessionKey = Arrays.copyOf(keyExchangeKey, keyExchangeKey.length);
      }

      EnumSet<NtlmNegotiateFlag> responseFlags = EnumSet.copyOf(serverFlags);
      responseFlags.remove(NTLMSSP_NEGOTIATE_VERSION);
      NtlmAuthenticate authenticate =
          new NtlmAuthenticate(
              lmResponse,
              ntResponse,
              identity.getUsername(),
              identity.getDomain(),
              "",
              encryptedSessionKey,
              responseFlags,
              null);
      if (includeMic) {
        authenticate.setMic(new byte[16]);
        byte[] zeroMic = serialize(authenticate);
        mic = NtlmFunctions.hmac_md5(
            securityProvider, exportedSessionKey, type1, type2, zeroMic);
        Arrays.fill(zeroMic, (byte) 0);
        authenticate.setMic(mic);
      }
      return wrap(serialize(authenticate));
    } catch (IllegalArgumentException error) {
      throw error;
    } catch (Exception error) {
      throw new IllegalArgumentException("Invalid NTLM Type 2 challenge", error);
    } finally {
      clear(type2);
      clear(sessionBaseKey);
      clear(ntResponse);
      clear(lmResponse);
      clear(keyExchangeKey);
      clear(exportedSessionKey);
      clear(encryptedSessionKey);
      clear(mic);
    }
  }

  public static byte[] responseToken(byte[] wrapped) {
    try {
      byte[] token = new NegTokenTarg().read(wrapped).getResponseToken();
      return token == null ? null : Arrays.copyOf(token, token.length);
    } catch (Exception error) {
      throw new IllegalArgumentException("Invalid SPNEGO response token", error);
    }
  }

  private static void validateFlags(Set<NtlmNegotiateFlag> flags) {
    if (!flags.contains(NTLMSSP_NEGOTIATE_UNICODE)
        || !flags.contains(NTLMSSP_NEGOTIATE_NTLM)
        || !flags.contains(NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
        || !flags.contains(NTLMSSP_NEGOTIATE_TARGET_INFO)
        || !flags.contains(NTLMSSP_NEGOTIATE_128)) {
      throw new IllegalArgumentException("Server does not meet NTLMv2 security requirements");
    }
  }

  private static void validateType2(byte[] message) {
    byte[] signature = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    if (!Arrays.equals(signature, Arrays.copyOf(message, signature.length))
        || readInt(message, 8) != 2) {
      throw new IllegalArgumentException("Invalid NTLM Type 2 header");
    }
    int flags = readInt(message, 20);
    int payloadFloor =
        (flags & (int) NTLMSSP_NEGOTIATE_VERSION.getValue()) == 0 ? 48 : 56;
    int[] targetName = securityBuffer(message, 12, payloadFloor, false);
    int[] targetInfo = securityBuffer(message, 40, payloadFloor, true);
    if ((targetName[0] & 1) != 0) {
      throw new IllegalArgumentException("Invalid Unicode target name");
    }
    if (targetName[0] > 0
        && targetInfo[0] > 0
        && targetName[1] < targetInfo[1] + targetInfo[0]
        && targetInfo[1] < targetName[1] + targetName[0]) {
      throw new IllegalArgumentException("Overlapping NTLM Type 2 buffers");
    }
  }

  private static int[] securityBuffer(
      byte[] message, int fieldOffset, int payloadFloor, boolean required) {
    int length = readShort(message, fieldOffset);
    int maximumLength = readShort(message, fieldOffset + 2);
    long rawOffset = Integer.toUnsignedLong(readInt(message, fieldOffset + 4));
    if (maximumLength < length
        || (required && length == 0)
        || (length > 0
            && (rawOffset < payloadFloor || rawOffset + length > message.length))) {
      throw new IllegalArgumentException("Invalid NTLM Type 2 security buffer");
    }
    return new int[] {length, (int) rawOffset};
  }

  private static int readShort(byte[] bytes, int offset) {
    return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
  }

  private static int readInt(byte[] bytes, int offset) {
    return (bytes[offset] & 0xff)
        | ((bytes[offset + 1] & 0xff) << 8)
        | ((bytes[offset + 2] & 0xff) << 16)
        | ((bytes[offset + 3] & 0xff) << 24);
  }

  private static byte[] serialize(NtlmAuthenticate message) {
    Buffer.PlainBuffer raw = new Buffer.PlainBuffer(Endian.LE);
    message.write(raw);
    return raw.getCompactData();
  }

  private static byte[] wrap(byte[] rawToken) {
    try {
      NegTokenTarg targ = new NegTokenTarg();
      targ.setResponseToken(rawToken);
      Buffer.PlainBuffer wrapped = new Buffer.PlainBuffer(Endian.LE);
      targ.write(wrapped);
      return wrapped.getCompactData();
    } catch (Exception error) {
      throw new IllegalStateException("Unable to encode SPNEGO NTLM token", error);
    }
  }

  private static void clear(byte[] value) {
    if (value != null) Arrays.fill(value, (byte) 0);
  }
}
