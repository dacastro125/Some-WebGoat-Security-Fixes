/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.Properties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Verification test suite for Transport Layer Security (TLS) and session cookie hardening (V2 - CWE-319).
 */
class TransportSecurityTest {

  @Test
  @DisplayName("V2: KeyStore goatkeystore.pkcs12 must exist and be a valid PKCS12 keystore")
  void keystoreExistsAndContainsGoatAlias() throws Exception {
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (InputStream is = getClass().getResourceAsStream("/goatkeystore.pkcs12")) {
      assertThat(is)
          .as("goatkeystore.pkcs12 must be present in classpath")
          .isNotNull();
      keyStore.load(is, "password".toCharArray());
    }
    assertThat(keyStore.containsAlias("goat"))
        .as("Keystore must contain the 'goat' key alias for TLS negotiation")
        .isTrue();
  }

  @Test
  @DisplayName("V2: application-webgoat.properties must enable SSL/TLS and modern protocols by default")
  void applicationPropertiesEnforcesTlsConfiguration() throws Exception {
    Properties properties = new Properties();
    try (InputStream is = getClass().getResourceAsStream("/application-webgoat.properties")) {
      assertThat(is)
          .as("application-webgoat.properties must be present in classpath")
          .isNotNull();
      properties.load(is);
    }

    assertThat(properties.getProperty("server.ssl.enabled"))
        .as("server.ssl.enabled must default to true to mitigate CWE-319")
        .isEqualTo("${WEBGOAT_SSLENABLED:true}");

    assertThat(properties.getProperty("server.ssl.protocol"))
        .as("server.ssl.protocol must be set to TLS")
        .isEqualTo("TLS");

    assertThat(properties.getProperty("server.ssl.enabled-protocols"))
        .as("server.ssl.enabled-protocols must be restricted to modern TLSv1.2 and TLSv1.3")
        .isEqualTo("TLSv1.2,TLSv1.3");

    assertThat(properties.getProperty("server.ssl.ciphers"))
        .as("server.ssl.ciphers must include TLS 1.3 and TLS 1.2 AEAD GCM cipher suites")
        .contains("TLS_AES_128_GCM_SHA256")
        .contains("TLS_AES_256_GCM_SHA384")
        .contains("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        .contains("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
  }

  @Test
  @DisplayName("V2: Session cookie JSESSIONID must be hardened with Secure, HttpOnly, and SameSite")
  void sessionCookieIsHardened() throws Exception {
    Properties properties = new Properties();
    try (InputStream is = getClass().getResourceAsStream("/application-webgoat.properties")) {
      assertThat(is).isNotNull();
      properties.load(is);
    }

    assertThat(properties.getProperty("server.servlet.session.cookie.secure"))
        .as("Session cookie must have Secure attribute to prevent transmission over cleartext HTTP")
        .isEqualTo("true");

    assertThat(properties.getProperty("server.servlet.session.cookie.http-only"))
        .as("Session cookie must have HttpOnly attribute to prevent XSS-based theft")
        .isEqualTo("true");

    assertThat(properties.getProperty("server.servlet.session.cookie.same-site"))
        .as("Session cookie must have SameSite attribute set to lax for CSRF mitigation")
        .isEqualTo("lax");
  }
}
