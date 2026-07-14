package com.poelbos.kerberosauthenticator.internal.ntlm;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.ntlm.messages.NtlmNegotiateFlag;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.spnego.NegTokenTarg;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Random;
import org.junit.Test;

public final class HttpNtlmV2EngineTest {
  @Test public void unavailableChannelBindingIsProtocolZeroValue() {
    assertThat(HttpNtlmV2Engine.unavailableChannelBindingHash()).isEqualTo(new byte[16]);
  }
  private static final ASN1ObjectIdentifier NTLMSSP =
      new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.10");

  private final HttpNtlmV2Engine engine =
      new HttpNtlmV2Engine(
          new FixedRandom(), () -> 0L, SmbConfig.createDefaultConfig().getSecurityProvider());

  @Test
  public void type1IsNtlmV2CapableAndContainsNoIdentity() throws Exception {
    byte[] wrapped = engine.createType1();
    NegTokenTarg token = new NegTokenTarg().read(wrapped);
    byte[] type1 = token.getResponseToken();

    assertThat(Arrays.copyOf(type1, 8))
        .isEqualTo(new byte[] {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0});
    assertThat(readInt(type1, 8)).isEqualTo(1);
    int flags = readInt(type1, 12);
    assertThat(flags & (int) NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE.getValue()).isNotEqualTo(0);
    assertThat(flags & (int) NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM.getValue()).isNotEqualTo(0);
    assertThat(flags & (int) NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.getValue())
        .isNotEqualTo(0);
    assertThat(flags & (int) NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128.getValue()).isNotEqualTo(0);
    assertThat(type1.length).isEqualTo(32);
  }

  @Test
  public void type3UsesConfiguredIdentityEmptyLmAndHttpTargetName() throws Exception {
    byte[] wrappedType1 = engine.createType1();
    byte[] rawType1 = new NegTokenTarg().read(wrappedType1).getResponseToken();
    byte[] challenge = wrappedType2(requiredFlags());
    char[] password = "Password".toCharArray();

    byte[] wrappedType3 =
        engine.createType3(
            "portal.example.com",
            NtlmIdentity.parse("User", "EXAMPLE.COM", "Domain"),
            password,
            rawType1,
            challenge);
    byte[] type3 = new NegTokenTarg().read(wrappedType3).getResponseToken();

    assertThat(readInt(type3, 8)).isEqualTo(3);
    assertThat(readShort(type3, 12)).isEqualTo(0);
    assertThat(readSecurityBufferString(type3, 28)).isEqualTo("Domain");
    assertThat(readSecurityBufferString(type3, 36)).isEqualTo("User");
    assertThat(indexOf(type3, "HTTP/portal.example.com".getBytes(StandardCharsets.UTF_16LE)))
        .isAtLeast(0);
    assertThat(indexOf(type3, zeroChannelBindingsAvPair())).isAtLeast(0);
    assertThat(Arrays.copyOfRange(type3, 72, 88)).isNotEqualTo(new byte[16]);
  }

  @Test
  public void usesLocalClockWhenServerOmitsTimestamp() throws Exception {
    HttpNtlmV2Engine clockedEngine =
        new HttpNtlmV2Engine(
            new FixedRandom(),
            () -> 1234L,
            SmbConfig.createDefaultConfig().getSecurityProvider());
    byte[] rawType1 = new NegTokenTarg().read(clockedEngine.createType1()).getResponseToken();

    byte[] wrappedType3 =
        clockedEngine.createType3(
            "portal.example.com",
            NtlmIdentity.parse("User", "EXAMPLE.COM", "Domain"),
            "Password".toCharArray(),
            rawType1,
            wrappedType2(requiredFlags(), false));
    byte[] type3 = new NegTokenTarg().read(wrappedType3).getResponseToken();
    int ntResponseOffset = readInt(type3, 24);

    assertThat(readLong(type3, ntResponseOffset + 24))
        .isEqualTo(FileTime.ofEpochMillis(1234L).getWindowsTimeStamp());
  }

  @Test
  public void rejectsMalformedOrWeakType2() throws Exception {
    byte[] rawType1 = new NegTokenTarg().read(engine.createType1()).getResponseToken();
    NtlmIdentity identity = NtlmIdentity.parse("User", "EXAMPLE.COM", "Domain");

    assertThrows(
        IllegalArgumentException.class,
        () -> engine.createType3("portal.example.com", identity, "Password".toCharArray(),
            rawType1, new byte[] {1, 2, 3}));

    EnumSet<NtlmNegotiateFlag> weak = requiredFlags();
    weak.remove(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);
    assertThrows(
        IllegalArgumentException.class,
        () -> engine.createType3("portal.example.com", identity, "Password".toCharArray(),
            rawType1, wrappedType2(weak)));
  }

  @Test
  public void rejectsOverlappingType2SecurityBuffers() throws Exception {
    byte[] rawType1 = new NegTokenTarg().read(engine.createType1()).getResponseToken();
    byte[] rawType2 = new NegTokenTarg().read(wrappedType2(requiredFlags())).getResponseToken();
    putShort(rawType2, 12, 2);
    putShort(rawType2, 14, 2);
    putInt(rawType2, 16, 48);

    assertThrows(
        IllegalArgumentException.class,
        () ->
            engine.createType3(
                "portal.example.com",
                NtlmIdentity.parse("User", "EXAMPLE.COM", "Domain"),
                "Password".toCharArray(),
                rawType1,
                wrapType2(rawType2)));
  }

  @Test
  public void type3NeverDisclosesAnOsVersion() throws Exception {
    EnumSet<NtlmNegotiateFlag> flags = requiredFlags();
    flags.add(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION);
    byte[] rawType1 = new NegTokenTarg().read(engine.createType1()).getResponseToken();

    byte[] wrappedType3 =
        engine.createType3(
            "portal.example.com",
            NtlmIdentity.parse("User", "EXAMPLE.COM", "Domain"),
            "Password".toCharArray(),
            rawType1,
            wrappedType2(flags));
    byte[] type3 = new NegTokenTarg().read(wrappedType3).getResponseToken();

    assertThat(readInt(type3, 60) & (int) NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION.getValue())
        .isEqualTo(0);
  }

  private static EnumSet<NtlmNegotiateFlag> requiredFlags() {
    return EnumSet.of(
        NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_UNICODE,
        NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_NTLM,
        NtlmNegotiateFlag.NTLMSSP_REQUEST_TARGET,
        NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
        NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_TARGET_INFO,
        NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
        NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_128);
  }

  private static byte[] wrappedType2(EnumSet<NtlmNegotiateFlag> flags) throws Exception {
    return wrappedType2(flags, true);
  }

  private static byte[] wrappedType2(
      EnumSet<NtlmNegotiateFlag> flags, boolean includeTimestamp) throws Exception {
    Buffer.PlainBuffer targetInfo = new Buffer.PlainBuffer(Endian.LE);
    putAvString(targetInfo, 2, "Domain");
    putAvString(targetInfo, 1, "Server");
    if (includeTimestamp) targetInfo.putUInt16(7).putUInt16(8).putLong(0L);
    targetInfo.putUInt16(0).putUInt16(0);
    byte[] av = targetInfo.getCompactData();

    Buffer.PlainBuffer type2 = new Buffer.PlainBuffer(Endian.LE);
    type2.putRawBytes(new byte[] {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0});
    type2.putUInt32(2);
    int payloadOffset = flags.contains(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION) ? 56 : 48;
    putSecurityBuffer(type2, 0, payloadOffset);
    long combined = 0;
    for (NtlmNegotiateFlag flag : flags) combined |= flag.getValue();
    type2.putUInt32(combined);
    type2.putRawBytes(new byte[] {1, 35, 69, 103, (byte) 137, (byte) 171, (byte) 205, (byte) 239});
    type2.putLong(0L);
    putSecurityBuffer(type2, av.length, payloadOffset);
    if (payloadOffset == 56) {
      type2.putRawBytes(new byte[] {10, 0, 0, 0, 0, 0, 0, 15});
    }
    type2.putRawBytes(av);

    return wrapType2(type2.getCompactData());
  }

  private static byte[] wrapType2(byte[] rawType2) throws Exception {
    NegTokenTarg targ = new NegTokenTarg();
    targ.setSupportedMech(NTLMSSP);
    targ.setResponseToken(rawType2);
    Buffer.PlainBuffer wrapped = new Buffer.PlainBuffer(Endian.LE);
    targ.write(wrapped);
    return wrapped.getCompactData();
  }

  private static void putShort(byte[] bytes, int offset, int value) {
    bytes[offset] = (byte) value;
    bytes[offset + 1] = (byte) (value >>> 8);
  }

  private static void putInt(byte[] bytes, int offset, int value) {
    bytes[offset] = (byte) value;
    bytes[offset + 1] = (byte) (value >>> 8);
    bytes[offset + 2] = (byte) (value >>> 16);
    bytes[offset + 3] = (byte) (value >>> 24);
  }

  private static void putAvString(Buffer.PlainBuffer out, int id, String value) {
    byte[] bytes = value.getBytes(StandardCharsets.UTF_16LE);
    out.putUInt16(id).putUInt16(bytes.length).putRawBytes(bytes);
  }

  private static void putSecurityBuffer(Buffer.PlainBuffer out, int length, int offset) {
    out.putUInt16(length).putUInt16(length).putUInt32(offset);
  }

  private static int readShort(byte[] value, int offset) {
    return (value[offset] & 0xff) | ((value[offset + 1] & 0xff) << 8);
  }

  private static int readInt(byte[] value, int offset) {
    return readShort(value, offset) | (readShort(value, offset + 2) << 16);
  }

  private static long readLong(byte[] value, int offset) {
    long result = 0;
    for (int i = 0; i < 8; i++) result |= (long) (value[offset + i] & 0xff) << (8 * i);
    return result;
  }

  private static byte[] zeroChannelBindingsAvPair() {
    byte[] pair = new byte[20];
    pair[0] = 10;
    pair[2] = 16;
    return pair;
  }

  private static String readSecurityBufferString(byte[] message, int descriptorOffset) {
    int length = readShort(message, descriptorOffset);
    int offset = readInt(message, descriptorOffset + 4);
    return new String(message, offset, length, StandardCharsets.UTF_16LE);
  }

  private static int indexOf(byte[] haystack, byte[] needle) {
    outer:
    for (int i = 0; i <= haystack.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) continue outer;
      }
      return i;
    }
    return -1;
  }

  private static final class FixedRandom extends Random {
    @Override public void nextBytes(byte[] bytes) {
      Arrays.fill(bytes, (byte) 0xaa);
    }
  }
}
