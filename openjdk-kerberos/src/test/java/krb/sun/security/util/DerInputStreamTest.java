package krb.sun.security.util;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.junit.Test;

public final class DerInputStreamTest {
  @Test public void acceptsBerLongLengthWithRedundantLeadingZero() throws Exception {
    ByteArrayInputStream input = new ByteArrayInputStream(new byte[] {0, (byte) 0x82});

    assertEquals(130, DerInputStream.getLength(0x82, input));
  }

  @Test public void acceptsPaddedBerLongLengthBelowShortFormBoundary() throws Exception {
    ByteArrayInputStream input = new ByteArrayInputStream(new byte[] {0, 0x7f});

    assertEquals(127, DerInputStream.getLength(0x82, input));
  }

  @Test(expected = IOException.class)
  public void rejectsUnpaddedLongLengthBelowShortFormBoundary() throws Exception {
    ByteArrayInputStream input = new ByteArrayInputStream(new byte[] {0x7f});

    DerInputStream.getLength(0x81, input);
  }
}
