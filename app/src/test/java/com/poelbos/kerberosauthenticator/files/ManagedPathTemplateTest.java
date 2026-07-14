package com.poelbos.kerberosauthenticator.files;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;

public final class ManagedPathTemplateTest {
  @Test public void expandsUsernameAndLastDigit() {
    assertEquals(
        "users\\2\\isc36512",
        ManagedPathTemplate.resolve(
            "users\\${username:last:1}\\${username}", "isc36512"));
  }

  @Test public void leavesStaticPathUnchanged() {
    assertEquals(
        "Public\\Policies",
        ManagedPathTemplate.resolve("Public\\Policies", "isc36512"));
  }

  @Test public void rejectsMissingUsernameWithoutDisclosingIt() {
    IllegalArgumentException exception = assertThrows(
        IllegalArgumentException.class,
        () -> ManagedPathTemplate.resolve("users\\${username}", ""));

    assertEquals("The managed path requires a signed-in username", exception.getMessage());
  }

  @Test public void rejectsUnknownPlaceholder() {
    IllegalArgumentException exception = assertThrows(
        IllegalArgumentException.class,
        () -> ManagedPathTemplate.resolve("users\\${account}", "isc36512"));

    assertEquals("The managed path contains an unsupported placeholder", exception.getMessage());
  }

  @Test public void rejectsIncompletePlaceholder() {
    IllegalArgumentException exception = assertThrows(
        IllegalArgumentException.class,
        () -> ManagedPathTemplate.resolve("users\\${username", "isc36512"));

    assertEquals("The managed path contains an incomplete placeholder", exception.getMessage());
  }

  @Test public void rejectsNonNumericUsernameSuffix() {
    IllegalArgumentException exception = assertThrows(
        IllegalArgumentException.class,
        () -> ManagedPathTemplate.resolve("users\\${username:last:1}", "userx"));

    assertEquals("The managed path requires a username ending in a digit", exception.getMessage());
  }
}
