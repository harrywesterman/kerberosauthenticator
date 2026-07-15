package krb.sun.security.jgss.krb5;

import javax.security.auth.Subject;
import krb.javax.security.auth.kerberos.KerberosTicket;

/** Selects the local-realm TGT without confusing cached service tickets for credentials. */
public final class InitialTgtSelector {
  private InitialTgtSelector() {}

  public static KerberosTicket select(Subject subject, String clientPrincipal) {
    if (subject == null) {
      return null;
    }
    for (KerberosTicket ticket : subject.getPrivateCredentials(KerberosTicket.class)) {
      if (!ticket.isCurrent()) {
        continue;
      }
      if (clientPrincipal != null
          && !clientPrincipal.equals(ticket.getClient().getName())) {
        continue;
      }
      String realm = ticket.getClient().getRealm();
      String initialTgt = "krbtgt/" + realm + "@" + realm;
      if (initialTgt.equals(ticket.getServer().getName())) {
        return ticket;
      }
    }
    return null;
  }
}
