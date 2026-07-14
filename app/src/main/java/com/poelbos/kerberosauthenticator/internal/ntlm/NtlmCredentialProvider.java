package com.poelbos.kerberosauthenticator.internal.ntlm;

import android.content.Context;
import com.poelbos.kerberosauthenticator.CredentialVault;
import com.poelbos.kerberosauthenticator.internal.spnego.HttpSpnegoCoordinator;
import java.util.Arrays;

/** Loads an NTLM password from the existing hardware-backed AD credential vault. */
public final class NtlmCredentialProvider implements HttpSpnegoCoordinator.CredentialProvider {
  interface Loader {
    char[] load(String username, String realm);
  }

  private final Loader loader;

  public NtlmCredentialProvider(Context context) {
    CredentialVault vault = new CredentialVault(context);
    this.loader = vault::load;
  }

  NtlmCredentialProvider(Loader loader) {
    this.loader = loader;
  }

  @Override
  public boolean isAvailable(String username, String realm) {
    char[] loaded = loader.load(username, realm);
    if (loaded == null) return false;
    Arrays.fill(loaded, '\0');
    return true;
  }

  @Override
  public char[] load(String username, String realm) {
    return loader.load(username, realm);
  }
}
