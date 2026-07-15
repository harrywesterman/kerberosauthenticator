package krb.sun.security.jgss.krb5;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertNull;

import java.util.Date;
import javax.security.auth.Subject;
import krb.javax.security.auth.kerberos.KerberosPrincipal;
import krb.javax.security.auth.kerberos.KerberosTicket;
import org.junit.Test;

public final class InitialTgtSelectorTest {
  @Test public void selectsInitialTgtAfterServiceTicketWasCached() {
    KerberosTicket service = ticket("cifs/server.example.test@EXAMPLE.TEST");
    KerberosTicket tgt = ticket("krbtgt/EXAMPLE.TEST@EXAMPLE.TEST");
    Subject subject = new Subject();
    subject.getPrivateCredentials().add(service);
    subject.getPrivateCredentials().add(tgt);

    assertSame(tgt, InitialTgtSelector.select(subject, null));
  }

  @Test public void doesNotUseServiceTicketAsInitialCredential() {
    Subject subject = new Subject();
    subject.getPrivateCredentials().add(ticket("cifs/server.example.test@EXAMPLE.TEST"));

    assertNull(InitialTgtSelector.select(subject, null));
  }

  @Test public void honorsRequestedClientPrincipal() {
    Subject subject = new Subject();
    subject.getPrivateCredentials().add(ticket("krbtgt/EXAMPLE.TEST@EXAMPLE.TEST"));

    assertNull(InitialTgtSelector.select(subject, "other@EXAMPLE.TEST"));
  }

  private static KerberosTicket ticket(String server) {
    Date now = new Date();
    return new KerberosTicket(
        new byte[] {1},
        new KerberosPrincipal("member@EXAMPLE.TEST"),
        new KerberosPrincipal(server),
        new byte[] {2},
        18,
        new boolean[32],
        now,
        now,
        new Date(now.getTime() + 60_000),
        null,
        null);
  }
}
