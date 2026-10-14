package com.poelbos.kerberosauthenticator.internal.spnego;

import java.io.ByteArrayInputStream;
import java.util.HashMap;
import java.util.Map;
import krb.sun.security.util.DerValue;

/** Non-sensitive KRB-ERROR metadata. The peer's principal is a hint, never an authorization. */
public final class KerberosPeerError {
  public final int code;
  public final String principal;
  private KerberosPeerError(int code, String principal) { this.code = code; this.principal = principal; }

  public static KerberosPeerError parse(byte[] mechanism) {
    if (mechanism == null || mechanism.length > 65536) return null;
    for (int i = 0; i < mechanism.length; i++) {
      if ((mechanism[i] & 255) != 0x7e) continue;
      try {
        DerValue application = new DerValue(new ByteArrayInputStream(mechanism, i, mechanism.length - i));
        DerValue sequence = application.getData().getDerValue();
        if (sequence.tag != DerValue.tag_Sequence || application.getData().available() != 0) continue;
        Map<Integer, DerValue> fields = new HashMap<>();
        while (sequence.getData().available() > 0) {
          DerValue field = sequence.getData().getDerValue();
          int tag = field.tag & 255;
          if (tag < 0xa0 || tag > 0xac || fields.put(tag, field.getData().getDerValue()) != null
              || field.getData().available() != 0) throw new IllegalArgumentException();
        }
        if (fields.get(0xa0).getInteger() != 5 || fields.get(0xa1).getInteger() != 30) continue;
        int code = fields.get(0xa6).getInteger();
        String realm = fields.get(0xa9).getGeneralString();
        DerValue name = fields.get(0xaa);
        if (name.tag != DerValue.tag_Sequence) continue;
        StringBuilder principal = new StringBuilder();
        while (name.getData().available() > 0) {
          DerValue part = name.getData().getDerValue();
          if ((part.tag & 255) == 0xa1) {
            DerValue names = part.getData().getDerValue();
            if (names.tag != DerValue.tag_Sequence) throw new IllegalArgumentException();
            while (names.getData().available() > 0) {
              if (principal.length() > 0) principal.append('/');
              principal.append(names.getData().getDerValue().getGeneralString());
            }
          }
        }
        String reported = principal + "@" + realm;
        if (code < 0 || principal.length() == 0 || !reported.matches("[a-zA-Z0-9._$/@-]{1,255}")) return null;
        return new KerberosPeerError(code, reported);
      } catch (Exception ignored) { }
    }
    return null;
  }
}
