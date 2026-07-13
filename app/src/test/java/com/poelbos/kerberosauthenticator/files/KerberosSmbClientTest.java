package com.poelbos.kerberosauthenticator.files;

import static com.hierynomus.mssmb2.SMB2Dialect.SMB_2_1;
import static com.hierynomus.mssmb2.SMB2Dialect.SMB_3_1_1;
import static org.junit.Assert.assertTrue;

import com.hierynomus.smbj.SmbConfig;
import org.junit.Test;

public final class KerberosSmbClientTest {
  @Test public void createsDfsReadySignedConfiguration() {
    SmbConfig config = KerberosSmbClient.createConfig(false);

    assertTrue(config.isDfsEnabled());
    assertTrue(config.isSigningRequired());
    assertTrue(config.getSupportedDialects().contains(SMB_3_1_1));
    assertTrue(config.getSupportedDialects().contains(SMB_2_1));
  }

  @Test public void enablesEncryptionWhenRequired() {
    assertTrue(KerberosSmbClient.createConfig(true).isEncryptData());
  }
}
