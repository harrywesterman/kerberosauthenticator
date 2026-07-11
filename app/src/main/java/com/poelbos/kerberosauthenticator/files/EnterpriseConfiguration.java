package com.poelbos.kerberosauthenticator.files;

import android.content.Context;
import android.content.RestrictionsManager;
import android.os.Bundle;
import android.os.Parcelable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Strict parser for Android Enterprise managed configuration. */
public final class EnterpriseConfiguration {
  public static final String REALM = "ad_realm";
  public static final String USERNAME = "username";
  public static final String SHARES = "shares";
  public static final String KDC_HOSTS = "kdc_hosts";
  public static final String REQUIRE_ENCRYPTION = "require_smb_encryption";
  public static final String ALLOW_CACHE = "allow_local_cache";
  public static final String ALLOW_SCREENSHOTS = "allow_screenshots";
  public static final String SUPPORT_CONTACT = "support_contact";

  private final String realm;
  private final String username;
  private final List<ManagedShare> shares;
  private final List<String> kdcHosts;
  private final boolean requireEncryption;
  private final boolean allowCache;
  private final boolean allowScreenshots;
  private final String supportContact;
  private final List<String> errors;

  public static EnterpriseConfiguration from(Context context) {
    RestrictionsManager manager =
        (RestrictionsManager) context.getSystemService(Context.RESTRICTIONS_SERVICE);
    return from(manager == null ? Bundle.EMPTY : manager.getApplicationRestrictions());
  }

  public static EnterpriseConfiguration from(Bundle source) {
    Bundle bundle = source == null ? Bundle.EMPTY : source;
    List<String> errors = new ArrayList<>();
    String realm = clean(bundle.getString(REALM));
    // Backwards compatibility with the existing authenticator MDM key.
    if (realm.isEmpty()) realm = clean(bundle.getString("adDomain"));
    String username = clean(bundle.getString(USERNAME));
    if (realm.isEmpty()) errors.add("Active Directory-realm ontbreekt");
    if (username.isEmpty()) errors.add("Gebruikersnaam ontbreekt");

    List<ManagedShare> shares = new ArrayList<>();
    Set<String> ids = new LinkedHashSet<>();
    Parcelable[] configuredShares = bundle.getParcelableArray(SHARES);
    if (configuredShares != null) {
      for (int index = 0; index < configuredShares.length; index++) {
        if (!(configuredShares[index] instanceof Bundle)) {
          errors.add("Share " + (index + 1) + " heeft een ongeldig formaat");
          continue;
        }
        Bundle item = (Bundle) configuredShares[index];
        try {
          ManagedShare share = new ManagedShare(
              item.getString("id"), item.getString("display_name"), item.getString("host"),
              item.getInt("port", 445), item.getString("share_name"),
              item.getString("start_path", ""));
          if (!ids.add(share.getId())) throw new IllegalArgumentException("id must be unique");
          shares.add(share);
        } catch (IllegalArgumentException exception) {
          errors.add("Share " + (index + 1) + ": " + exception.getMessage());
        }
      }
    }
    if (shares.isEmpty()) errors.add("Er zijn geen geldige bedrijfsshares geconfigureerd");

    List<String> kdcs = new ArrayList<>();
    String[] configuredKdcs = bundle.getStringArray(KDC_HOSTS);
    if (configuredKdcs != null) {
      for (String kdc : configuredKdcs) if (!clean(kdc).isEmpty()) kdcs.add(clean(kdc));
    } else {
      String configuredKdcList = clean(bundle.getString(KDC_HOSTS));
      if (!configuredKdcList.isEmpty()) {
        for (String kdc : configuredKdcList.split(",")) {
          if (!clean(kdc).isEmpty()) kdcs.add(clean(kdc));
        }
      }
    }
    return new EnterpriseConfiguration(
        realm.toUpperCase(), username, shares, kdcs,
        bundle.getBoolean(REQUIRE_ENCRYPTION, false),
        bundle.getBoolean(ALLOW_CACHE, true),
        bundle.getBoolean(ALLOW_SCREENSHOTS, false), clean(bundle.getString(SUPPORT_CONTACT)), errors);
  }

  private EnterpriseConfiguration(
      String realm, String username, List<ManagedShare> shares, List<String> kdcHosts,
      boolean requireEncryption, boolean allowCache, boolean allowScreenshots,
      String supportContact, List<String> errors) {
    this.realm = realm;
    this.username = username;
    this.shares = Collections.unmodifiableList(new ArrayList<>(shares));
    this.kdcHosts = Collections.unmodifiableList(new ArrayList<>(kdcHosts));
    this.requireEncryption = requireEncryption;
    this.allowCache = allowCache;
    this.allowScreenshots = allowScreenshots;
    this.supportContact = supportContact;
    this.errors = Collections.unmodifiableList(new ArrayList<>(errors));
  }

  private static String clean(String value) { return value == null ? "" : value.trim(); }
  public boolean isValid() { return errors.isEmpty(); }
  public String getRealm() { return realm; }
  public String getUsername() { return username; }
  public List<ManagedShare> getShares() { return shares; }
  public List<String> getKdcHosts() { return kdcHosts; }
  public boolean isRequireEncryption() { return requireEncryption; }
  public boolean isAllowCache() { return allowCache; }
  public boolean isAllowScreenshots() { return allowScreenshots; }
  public String getSupportContact() { return supportContact; }
  public List<String> getErrors() { return errors; }
}
