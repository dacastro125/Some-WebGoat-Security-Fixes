/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * Verification test suite for GlobalExceptionHandler and stack trace suppression (V4 - CWE-209).
 */
class GlobalExceptionHandlerTest {

  private GlobalExceptionHandler handler;
  private MockHttpServletRequest request;

  @BeforeEach
  void setUp() {
    handler = new GlobalExceptionHandler();
    request = new MockHttpServletRequest();
  }

  @Test
  @DisplayName("V4: 404 HTML request returns sanitized ModelAndView without stack trace leakage")
  void handleNotFoundReturnsSanitizedHtml() {
    request.setRequestURI("/WebGoat/non_existent_page_123");
    request.addHeader("Accept", "text/html,application/xhtml+xml");

    var ex = new NoResourceFoundException(org.springframework.http.HttpMethod.GET, "/non_existent_page_123");
    Object result = handler.handleNotFound(ex, request);

    assertThat(result).isInstanceOf(ModelAndView.class);
    ModelAndView mav = (ModelAndView) result;
    assertThat(mav.getViewName()).isEqualTo("error");
    assertThat(mav.getModel().get("status")).isEqualTo(404);
    assertThat(mav.getModel().get("error")).isEqualTo("Recurso no encontrado");
    assertThat(mav.getModel().get("message").toString())
        .doesNotContain("Exception")
        .doesNotContain("at org.springframework")
        .contains("La página o recurso que está buscando no existe");
  }

  @Test
  @DisplayName("V4: 404 JSON request returns sanitized structured response without internal class names")
  @SuppressWarnings("unchecked")
  void handleNotFoundReturnsSanitizedJson() {
    request.setRequestURI("/WebGoat/api/unknown");
    request.addHeader("Accept", "application/json");

    var ex = new NoResourceFoundException(org.springframework.http.HttpMethod.GET, "/api/unknown");
    Object result = handler.handleNotFound(ex, request);

    assertThat(result).isInstanceOf(ResponseEntity.class);
    ResponseEntity<Map<String, Object>> response = (ResponseEntity<Map<String, Object>>) result;
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    Map<String, Object> body = response.getBody();
    assertThat(body).isNotNull();
    assertThat(body.get("status")).isEqualTo(404);
    assertThat(body.get("error")).isEqualTo("Not Found");
    assertThat(body.get("path")).isEqualTo("/WebGoat/api/unknown");
    assertThat(body.get("message").toString())
        .doesNotContain("Exception")
        .doesNotContain("at org.springframework");
  }

  @Test
  @DisplayName("V4: 500 HTML request returns generic error without exposing raw exception details")
  void handleGlobalExceptionReturnsSanitizedHtml() {
    request.setRequestURI("/WebGoat/trigger_error");
    request.addHeader("Accept", "text/html");

    var ex = new RuntimeException("Sensitive database connection credentials leaked in trace: secret_pw");
    Object result = handler.handleGlobalException(ex, request);

    assertThat(result).isInstanceOf(ModelAndView.class);
    ModelAndView mav = (ModelAndView) result;
    assertThat(mav.getViewName()).isEqualTo("error");
    assertThat(mav.getModel().get("status")).isEqualTo(500);
    assertThat(mav.getModel().get("error")).isEqualTo("Error interno");
    assertThat(mav.getModel().get("message").toString())
        .doesNotContain("secret_pw")
        .doesNotContain("RuntimeException")
        .contains("Ha ocurrido un error inesperado");
  }

  @Test
  @DisplayName("V4: 500 JSON request returns sanitized response without leaking internal exception message")
  @SuppressWarnings("unchecked")
  void handleGlobalExceptionReturnsSanitizedJson() {
    request.setRequestURI("/WebGoat/trigger_api_error");
    request.addHeader("Accept", "application/json");

    var ex = new NullPointerException("Null internal pointer at org.owasp.webgoat.service.InternalService.process(InternalService.java:42)");
    Object result = handler.handleGlobalException(ex, request);

    assertThat(result).isInstanceOf(ResponseEntity.class);
    ResponseEntity<Map<String, Object>> response = (ResponseEntity<Map<String, Object>>) result;
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
  @DisplayName("V4: application-webgoat.properties must strictly disable stack trace and message inclusion")
  void applicationPropertiesDisablesStackTraceInclusion() throws Exception {
    Properties properties = new Properties();
    try (InputStream is = getClass().getResourceAsStream("/application-webgoat.properties")) {
      assertThat(is).isNotNull();
      properties.load(is);
    }

    assertThat(properties.getProperty("server.error.include-stacktrace"))
        .as("server.error.include-stacktrace must be 'never'")
        .isEqualTo("never");

    assertThat(properties.getProperty("server.error.include-message"))
        .as("server.error.include-message must be 'never'")
        .isEqualTo("never");

    assertThat(properties.getProperty("spring.web.error.include-stacktrace"))
        .as("spring.web.error.include-stacktrace must be 'never'")
        .isEqualTo("never");

    assertThat(properties.getProperty("server.error.whitelabel.enabled"))
        .as("Whitelabel error page must be disabled")
        .isEqualTo("false");
  }
}
