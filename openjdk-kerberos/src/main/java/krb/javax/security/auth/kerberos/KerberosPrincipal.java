/*
 * Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package krb.javax.security.auth.kerberos;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import sun.security.krb5.KrbException;
import sun.security.krb5.PrincipalName;
import sun.security.krb5.Realm;
import krb.sun.security.util.*;

/**
 * This class encapsulates a Kerberos principal.
 *
 * @author Mayank Upadhyay
 * @since 1.4
 */

public final class KerberosPrincipal
    implements java.security.Principal, java.io.Serializable {

    private static final long serialVersionUID = -7374788026156829911L;

    //name types

    /**
     * unknown name type.
     */

    public static final int KRB_NT_UNKNOWN =   0;

    /**
     * user principal name type.
     */

    public static final int KRB_NT_PRINCIPAL = 1;

    /**
     * service and other unique instance (krbtgt) name type.
     */
    public static final int KRB_NT_SRV_INST =  2;

    /**
     * service with host name as instance (telnet, rcommands) name type.
     */

    public static final int KRB_NT_SRV_HST =   3;

    /**
     * service with host as remaining components name type.
     */

    public static final int KRB_NT_SRV_XHST =  4;

    /**
     * unique ID name type.
     */

    public static final int KRB_NT_UID = 5;

    private transient String fullName;

    private transient String realm;

    private transient int nameType;


    /**
     * Constructs a KerberosPrincipal from the provided string input. The
     * name type for this  principal defaults to
     * {@link #KRB_NT_PRINCIPAL KRB_NT_PRINCIPAL}
     * This string is assumed to contain a name in the format
     * that is specified in Section 2.1.1. (Kerberos Principal Name Form) of
     * <a href=http://www.ietf.org/rfc/rfc1964.txt> RFC 1964 </a>
     * (for example, <i>duke@FOO.COM</i>, where <i>duke</i>
     * represents a principal, and <i>FOO.COM</i> represents a realm).
     *
     * <p>If the input name does not contain a realm, the default realm
     * is used. The default realm can be specified either in a Kerberos
     * configuration file or via the java.security.krb5.realm
     * system property. For more information,
     * <a href="../../../../../technotes/guides/security/jgss/tutorials/index.html">
     * Kerberos Requirements </a>
     *
     * @param name the principal name
     * @throws IllegalArgumentException if name is improperly
     * formatted, if name is null, or if name does not contain
     * the realm to use and the default realm is not specified
     * in either a Kerberos configuration file or via the
     * java.security.krb5.realm system property.
     */
    public KerberosPrincipal(String name) {
        this(name, KRB_NT_PRINCIPAL);
    }

    /**
     * Constructs a KerberosPrincipal from the provided string and
     * name type input.  The string is assumed to contain a name in the
     * format that is specified in Section 2.1 (Mandatory Name Forms) of
     * <a href=http://www.ietf.org/rfc/rfc1964.txt>RFC 1964</a>.
     * Valid name types are specified in Section 6.2 (Principal Names) of
     * <a href=http://www.ietf.org/rfc/rfc4120.txt>RFC 4120</a>.
     * The input name must be consistent with the provided name type.
     * (for example, <i>duke@FOO.COM</i>, is a valid input string for the
     * name type, KRB_NT_PRINCIPAL where <i>duke</i>
     * represents a principal, and <i>FOO.COM</i> represents a realm).

     * <p> If the input name does not contain a realm, the default realm
     * is used. The default realm can be specified either in a Kerberos
     * configuration file or via the java.security.krb5.realm
     * system property. For more information, see
     * <a href="../../../../../technotes/guides/security/jgss/tutorials/index.html">
     * Kerberos Requirements</a>.
     *
     * @param name the principal name
     * @param nameType the name type of the principal
     * @throws IllegalArgumentException if name is improperly
     * formatted, if name is null, if the nameType is not supported,
     * or if name does not contain the realm to use and the default
     * realm is not specified in either a Kerberos configuration
     * file or via the java.security.krb5.realm system property.
     */

    public KerberosPrincipal(String name, int nameType) {

        PrincipalName krb5Principal = null;

        try {
            // Appends the default realm if it is missing
            krb5Principal  = new PrincipalName(name,nameType);
        } catch (KrbException e) {
            throw new IllegalArgumentException(e.getMessage());
        }

        // A ServicePermission with a principal in the deduced realm and
        // any action must be granted if no realm is provided by caller.
        if (krb5Principal.isRealmDeduced() && !Realm.AUTODEDUCEREALM) {
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                try {
                    sm.checkPermission(new ServicePermission(
                            "@" + krb5Principal.getRealmAsString(), "-"));
                } catch (SecurityException se) {
                    // Swallow the actual exception to hide info
                    throw new SecurityException("Cannot read realm info");
                }
            }
        }
        this.nameType = nameType;
        fullName = krb5Principal.toString();
        realm = krb5Principal.getRealmString();
    }
    /**
     * Returns the realm component of this Kerberos principal.
     *
     * @return the realm component of this Kerberos principal.
     */
    public String getRealm() {
        return realm;
    }

    /**
     * Returns a hashcode for this principal. The hash code is defined to
     * be the result of the following  calculation:
     * <pre>{@code
     *  hashCode = getName().hashCode();
     * }</pre>
     *
     * @return a hashCode() for the {@code KerberosPrincipal}
     */
    public int hashCode() {
        return getName().hashCode();
    }

    /**
     * Compares the specified Object with this Principal for equality.
     * Returns true if the given object is also a
     * {@code KerberosPrincipal} and the two
     * {@code KerberosPrincipal} instances are equivalent.
     * More formally two {@code KerberosPrincipal} instances are equal
     * if the values returned by {@code getName()} are equal.
     *
     * @param other the Object to compare to
     * @return true if the Object passed in represents the same principal
     * as this one, false otherwise.
     */
    public boolean equals(Object other) {

        if (other == this)
            return true;

        if (! (other instanceof KerberosPrincipal)) {
            return false;
        }
        String myFullName = getName();
        String otherFullName = ((KerberosPrincipal) other).getName();
        return myFullName.equals(otherFullName);
    }

    /**
     * Save the KerberosPrincipal object to a stream
     *
     * @serialData this {@code KerberosPrincipal} is serialized
     *          by writing out the PrincipalName and the
     *          realm in their DER-encoded form as specified in Section 5.2.2 of
     *          <a href=http://www.ietf.org/rfc/rfc4120.txt> RFC4120</a>.
     */
    private void writeObject(ObjectOutputStream oos)
            throws IOException {

        PrincipalName krb5Principal;
        try {
            krb5Principal  = new PrincipalName(fullName, nameType);
            oos.writeObject(krb5Principal.asn1Encode());
            oos.writeObject(krb5Principal.getRealm().asn1Encode());
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * Reads this object from a stream (i.e., deserializes it)
     */
    private void readObject(ObjectInputStream ois)
            throws IOException, ClassNotFoundException {
        byte[] asn1EncPrincipal = (byte [])ois.readObject();
        byte[] encRealm = (byte [])ois.readObject();
        try {
           realm = decodeKerberosString(new DerValue(encRealm));
           DecodedPrincipal principal = decodePrincipalName(new DerValue(asn1EncPrincipal));
           fullName = principal.toFullName(realm);
           nameType = principal.nameType;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private static DecodedPrincipal decodePrincipalName(DerValue encoding) throws IOException {
        if (encoding == null) {
            throw new IllegalArgumentException("Null encoding not allowed");
        }
        if (encoding.getTag() != DerValue.tag_Sequence) {
            throw new IOException("PrincipalName is not a sequence");
        }

        DerValue typeDer = encoding.getData().getDerValue();
        if ((typeDer.getTag() & 0x1F) != 0x00) {
            throw new IOException("PrincipalName is missing name-type");
        }
        int decodedNameType = typeDer.getData().getBigInteger().intValue();

        DerValue namesDer = encoding.getData().getDerValue();
        if ((namesDer.getTag() & 0x1F) != 0x01) {
            throw new IOException("PrincipalName is missing name-string");
        }
        DerValue namesSequence = namesDer.getData().getDerValue();
        if (namesSequence.getTag() != DerValue.tag_SequenceOf) {
            throw new IOException("PrincipalName name-string is not a sequence");
        }

        List<String> decodedNameStrings = new ArrayList<>();
        while (namesSequence.getData().available() > 0) {
            decodedNameStrings.add(decodeKerberosString(namesSequence.getData().getDerValue()));
        }
        return new DecodedPrincipal(decodedNameType, decodedNameStrings);
    }

    private static String decodeKerberosString(DerValue der) throws IOException {
        if (der.tag != DerValue.tag_GeneralString) {
            throw new IOException("KerberosString's tag is incorrect: " + der.tag);
        }
        Charset charset =
                Boolean.getBoolean("sun.security.krb5.msinterop.kstring")
                        ? StandardCharsets.UTF_8
                        : StandardCharsets.US_ASCII;
        return new String(der.getDataBytes(), charset);
    }

    private static final class DecodedPrincipal {
        private final int nameType;
        private final List<String> nameStrings;

        private DecodedPrincipal(int nameType, List<String> nameStrings) {
            this.nameType = nameType;
            this.nameStrings = nameStrings;
        }

        private String toFullName(String realm) {
            StringBuilder fullName = new StringBuilder();
            for (int i = 0; i < nameStrings.size(); i++) {
                if (i > 0) {
                    fullName.append("/");
                }
                fullName.append(nameStrings.get(i));
            }
            fullName.append("@");
            fullName.append(realm);
            return fullName.toString();
        }
    }

    /**
     * The returned string corresponds to the single-string
     * representation of a Kerberos Principal name as specified in
     * Section 2.1 of <a href=http://www.ietf.org/rfc/rfc1964.txt>RFC 1964</a>.
     *
     * @return the principal name.
     */
    public String getName() {
        return fullName;
    }

    /**
     * Returns the name type of the KerberosPrincipal. Valid name types
     * are specified in Section 6.2 of
     * <a href=http://www.ietf.org/rfc/rfc4120.txt> RFC4120</a>.
     *
     * @return the name type.
     */
    public int getNameType() {
        return nameType;
    }

    // Inherits javadocs from Object
    public String toString() {
        return getName();
    }
}
