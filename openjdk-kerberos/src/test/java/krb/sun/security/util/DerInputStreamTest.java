package krb.sun.security.util;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import org.junit.Test;

public final class DerInputStreamTest {
  @Test public void acceptsBerLongLengthWithRedundantLeadingZero() throws Exception {
    ByteArrayInputStream input = new ByteArrayInputStream(new byte[] {0, (byte) 0x82});

    assertEquals(130, DerInputStream.getLength(0x82, input));
  }
}
