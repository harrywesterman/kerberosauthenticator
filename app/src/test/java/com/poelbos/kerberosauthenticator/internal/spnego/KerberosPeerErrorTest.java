package com.poelbos.kerberosauthenticator.internal.spnego;

import static org.junit.Assert.*;
import java.util.Arrays;
import java.util.Base64;
import org.junit.Test;

public class KerberosPeerErrorTest {
  // Synthetic error for a fictional account, independently encoded as DER.
  private final byte[] error = Base64.getDecoder().decode(
      "fkwwSqADAgEFoQMCAR6kERgPMjAyNjEwMTQxNDAwMDBapQMCAQCmAwIBKakNGwtFWEFNUExFLkNPTaoSMBCgAwIBAaEJMAcbBXdlYjIk");
  @Test public void readsOnlyErrorMetadataAndRejectsMalformedInput() {
    KerberosPeerError result = KerberosPeerError.parse(error);
    assertEquals(41, result.code);
    assertEquals("web2$@EXAMPLE.COM", result.principal);
    assertNull(KerberosPeerError.parse(null));
    assertNull(KerberosPeerError.parse(new byte[65537]));
    for (int length = 0; length < error.length; length++)
      assertNull(KerberosPeerError.parse(Arrays.copyOf(error, length)));
    byte[] wrongMessageType = error.clone();
    for (int i = 0; i < wrongMessageType.length - 4; i++)
      if ((wrongMessageType[i] & 255) == 0xa1 && wrongMessageType[i+1] == 3
          && wrongMessageType[i+2] == 2 && wrongMessageType[i+3] == 1 && wrongMessageType[i+4] == 30) {
        wrongMessageType[i+4] = 31; break;
      }
    assertNull(KerberosPeerError.parse(wrongMessageType));
  }
}
