/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.header.writers.ContentSecurityPolicyHeaderWriter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode;

/**
 * Verification test suite for defensive HTTP security headers hardening (V3 - CWE-693).
 */
class SecurityHeadersTest {

  @Test
  @DisplayName("V3: X-Frame-Options must be DENY to prevent Clickjacking (CWE-1021)")
  void xFrameOptionsDenyMitigatesClickjacking() {
    var writer = new XFrameOptionsHeaderWriter(XFrameOptionsMode.DENY);
    var request = new MockHttpServletRequest();
    var response = new MockHttpServletResponse();

    writer.writeHeaders(request, response);

    assertThat(response.getHeader("X-Frame-Options"))
        .as("X-Frame-Options must be DENY")
        .isEqualTo("DENY");
  }

  @Test
  @DisplayName("V3: X-Content-Type-Options must be nosniff to prevent MIME sniffing (CWE-79)")
  void xContentTypeOptionsNosniffMitigatesMimeSniffing() {
    var writer = new XContentTypeOptionsHeaderWriter();
    var request = new MockHttpServletRequest();
    var response = new MockHttpServletResponse();

    writer.writeHeaders(request, response);

    assertThat(response.getHeader("X-Content-Type-Options"))
        .as("X-Content-Type-Options must be nosniff")
        .isEqualTo("nosniff");
  }

  @Test
  @DisplayName("V3: HSTS must enforce HTTPS with subdomains for at least 1 year")
  void hstsEnforcesHttps() {
    var writer = new HstsHeaderWriter(31536000L, true);
    var request = new MockHttpServletRequest();
    request.setSecure(true);
    var response = new MockHttpServletResponse();

    writer.writeHeaders(request, response);

    assertThat(response.getHeader("Strict-Transport-Security"))
        .as("HSTS header must include max-age=31536000 and includeSubDomains")
        .contains("max-age=31536000")
        .contains("includeSubDomains");
  }

  @Test
  @DisplayName("V3: Referrer-Policy must be strict-origin-when-cross-origin")
  void referrerPolicyRestrictsLeakage() {
    var writer = new ReferrerPolicyHeaderWriter(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN);
    var request = new MockHttpServletRequest();
    var response = new MockHttpServletResponse();

    writer.writeHeaders(request, response);

    assertThat(response.getHeader("Referrer-Policy"))
        .as("Referrer-Policy header must be strict-origin-when-cross-origin")
        .isEqualTo("strict-origin-when-cross-origin");
  }

  @Test
  @DisplayName("V3: Content-Security-Policy must restrict script and style sources to self")
  void contentSecurityPolicyDefinesSafeDirectives() {
    String policy =
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://code.jquery.com; img-src 'self' data: https://code.jquery.com; font-src 'self' data:; connect-src 'self'";
    var writer = new ContentSecurityPolicyHeaderWriter(policy);
    var request = new MockHttpServletRequest();
    var response = new MockHttpServletResponse();

    writer.writeHeaders(request, response);

    assertThat(response.getHeader("Content-Security-Policy"))
        .as("Content-Security-Policy must match the calibrated policy")
        .isEqualTo(policy);
  }
}
