/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * Verification test suite for GlobalExceptionHandler and stack trace suppression (V4 - CWE-209).
 */
class GlobalExceptionHandlerTest {

  private GlobalExceptionHandler handler;
  private MockHttpServletRequest request;
  private MockHttpServletResponse response;

  @BeforeEach
  void setUp() {
    handler = new GlobalExceptionHandler();
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
  }

  @SuppressWarnings("unchecked")
  private ResponseEntity<Map<String, Object>> json(Exception ex) {
    request.addHeader("Accept", "application/json");
    Object result = handler.handleException(ex, request, response);
    assertThat(result).isInstanceOf(ResponseEntity.class);
    return (ResponseEntity<Map<String, Object>>) result;
  }

  private ModelAndView html(Exception ex) {
    request.addHeader("Accept", "text/html,application/xhtml+xml");
    Object result = handler.handleException(ex, request, response);
    assertThat(result).isInstanceOf(ModelAndView.class);
    return (ModelAndView) result;
  }

  private static NoResourceFoundException notFound(String path) {
    return new NoResourceFoundException(HttpMethod.GET, path, "Resource not found");
  }

  @Test
  @DisplayName("V4: 404 HTML request renders the WebGoat error view with status 404, no trace")
  void notFoundReturnsSanitizedHtml() {
    request.setRequestURI("/WebGoat/non_existent_page_123");

    ModelAndView mav = html(notFound("/non_existent_page_123"));

    assertThat(mav.getViewName()).isEqualTo(GlobalExceptionHandler.ERROR_VIEW);
    assertThat(mav.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(mav.getModel().get("status")).isEqualTo(404);
    assertThat(mav.getModel().get("error")).isEqualTo("Recurso no encontrado");
    assertThat(mav.getModel().get("message").toString())
        .doesNotContain("Exception")
        .doesNotContain("at org.springframework")
        .contains("La página o recurso que está buscando no existe");
  }

  @Test
  @DisplayName("V4: 404 JSON request returns sanitized structured response")
  void notFoundReturnsSanitizedJson() {
    request.setRequestURI("/WebGoat/api/unknown");

    var response = json(notFound("/api/unknown"));

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    Map<String, Object> body = response.getBody();
    assertThat(body).isNotNull();
    assertThat(body.get("status")).isEqualTo(404);
    assertThat(body.get("error")).isEqualTo("Not Found");
    assertThat(body.get("path")).isEqualTo("/WebGoat/api/unknown");
    assertThat(body.get("message").toString()).doesNotContain("Exception");
  }

  @Test
  @DisplayName("V4: unexpected exception (HTML) becomes a generic 500 without exception details")
  void unexpectedExceptionReturnsSanitizedHtml() {
    var ex = new RuntimeException("Sensitive database credentials leaked in trace: secret_pw");

    ModelAndView mav = html(ex);

    assertThat(mav.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    assertThat(mav.getModel().get("status")).isEqualTo(500);
    assertThat(mav.getModel().get("error")).isEqualTo("Error interno");
    assertThat(mav.getModel().get("message").toString())
        .doesNotContain("secret_pw")
        .doesNotContain("RuntimeException")
        .contains("Ha ocurrido un error interno en el servidor");
  }

  @Test
  @DisplayName("V4: unexpected exception (JSON) becomes a generic 500 without exception details")
  void unexpectedExceptionReturnsSanitizedJson() {
    var ex =
        new NullPointerException(
            "Null pointer at org.owasp.webgoat.service.InternalService.process(InternalService.java:42)");

    var response = json(ex);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    Map<String, Object> body = response.getBody();
    assertThat(body).isNotNull();
    assertThat(body.get("status")).isEqualTo(500);
    assertThat(body.get("error")).isEqualTo("Internal Server Error");
    assertThat(body.get("message").toString())
        .doesNotContain("NullPointerException")
        .doesNotContain("InternalService.java")
        .contains("Ha ocurrido un error interno en el servidor");
  }

  @Test
  @DisplayName("V4: malformed request body keeps 400 instead of becoming 500")
  void malformedBodyKeepsBadRequest() {
    var ex =
        new HttpMessageNotReadableException(
            "JSON parse error: Unexpected end-of-input", new MockHttpInputMessage(new byte[0]));

    var response = json(ex);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(response.getBody().get("message").toString())
        .doesNotContain("JSON parse error")
        .contains("La solicitud no pudo ser procesada");
  }

  @Test
  @DisplayName("V4: unsupported method keeps 405 and its Allow header (JSON and HTML)")
  void methodNotAllowedKeepsStatusAndAllowHeader() {
    var ex = new HttpRequestMethodNotSupportedException("POST", List.of("GET"));

    var jsonResponse = json(ex);
    assertThat(jsonResponse.getStatusCode()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
    assertThat(jsonResponse.getHeaders().getAllow()).containsExactly(HttpMethod.GET);

    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
    ModelAndView mav = html(ex);
    assertThat(mav.getStatus()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
    assertThat(mav.getModel().get("error")).isEqualTo("Solicitud no válida");
    assertThat(response.getHeader("Allow")).isEqualTo("GET");
  }

  @Test
  @DisplayName("V4: unsupported request media type keeps 415")
  void unsupportedMediaTypeKeepsStatus() {
    var ex =
        new HttpMediaTypeNotSupportedException(
            MediaType.TEXT_PLAIN, List.of(MediaType.APPLICATION_JSON));

    assertThat(json(ex).getStatusCode()).isEqualTo(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
  }

  @Test
  @DisplayName("V4: unacceptable response type keeps 406 with an empty body")
  void notAcceptableKeepsStatusWithoutBody() {
    var ex = new HttpMediaTypeNotAcceptableException(List.of(MediaType.APPLICATION_JSON));

    var response = json(ex);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_ACCEPTABLE);
    assertThat(response.getBody()).isNull();
  }

  @Test
  @DisplayName("V1/V4: AccessDeniedException is rethrown so Spring Security answers with 403")
  void accessDeniedIsRethrownToSecurityChain() {
    var ex = new AccessDeniedException("Access Denied");

    assertThatThrownBy(() -> handler.rethrowSecurityException(ex)).isSameAs(ex);
  }

  @Test
  @DisplayName("V4: application-webgoat.properties must strictly disable stack trace and message inclusion")
  void applicationPropertiesDisablesStackTraceInclusion() throws Exception {
    Properties properties = new Properties();
    try (InputStream is = getClass().getResourceAsStream("/application-webgoat.properties")) {
      assertThat(is).isNotNull();
      properties.load(is);
    }

    // Spring Boot 4 ignores the legacy server.error.* keys, so only spring.web.error.* counts.
    assertThat(properties.getProperty("spring.web.error.include-stacktrace"))
        .as("spring.web.error.include-stacktrace must be 'never'")
        .isEqualTo("never");

    assertThat(properties.getProperty("spring.web.error.include-message"))
        .as("spring.web.error.include-message must be 'never'")
        .isEqualTo("never");

    assertThat(properties.getProperty("spring.web.error.whitelabel.enabled"))
        .as("Whitelabel error page must be disabled")
        .isEqualTo("false");

    assertThat(properties.stringPropertyNames())
        .as("Legacy server.error.* keys are ignored by Spring Boot 4 and must not be relied on")
        .noneMatch(name -> name.startsWith("server.error."));
  }
}
