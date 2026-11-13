/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.TypeMismatchException;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.ModelAndView;

/**
 * Global exception handler mitigating CWE-209 (Generation of Error Message Containing Sensitive
 * Information).
 *
 * <p>Client-facing error responses are sanitized while the full diagnostic stack trace is kept in
 * the server logs only. The HTTP status of the original failure is preserved: framework client
 * errors keep their 4xx code (and headers such as {@code Allow}), and only genuinely unexpected
 * failures become a generic 500. Spring Security exceptions are rethrown so the security filter
 * chain answers them (403 / login redirect) instead of this handler.
 */
@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

  static final String ERROR_VIEW = "error";

  private static final String MSG_NOT_FOUND =
      "La página o recurso que está buscando no existe o fue movido.";
  private static final String MSG_CLIENT_ERROR =
      "La solicitud no pudo ser procesada. Verifique los datos enviados.";
  private static final String MSG_SERVER_ERROR =
      "Ha ocurrido un error interno en el servidor. Por favor intente más tarde.";

  /** Lets Spring Security's ExceptionTranslationFilter produce the 403 / login redirect. */
  @ExceptionHandler({AccessDeniedException.class, AuthenticationException.class})
  public void rethrowSecurityException(RuntimeException ex) {
    throw ex;
  }

  @ExceptionHandler(Exception.class)
  public Object handleException(
      Exception ex, HttpServletRequest request, HttpServletResponse response) {
    HttpStatusCode status = resolveStatus(ex);
    HttpHeaders headers = ex instanceof ErrorResponse errorResponse
        ? errorResponse.getHeaders()
        : HttpHeaders.EMPTY;

    if (status.is5xxServerError()) {
      log.error(
          "Unhandled exception intercepted during request to {}: {}",
          request.getRequestURI(),
          ex.getMessage(),
          ex);
    } else {
      log.warn(
          "Client error [{}] on {} {}: {}",
          status.value(),
          request.getMethod(),
          request.getRequestURI(),
          ex.getClass().getSimpleName());
    }

    if (status.value() == HttpStatus.NOT_ACCEPTABLE.value()) {
      // The client accepts none of our representations, so there is no body we can send.
      return ResponseEntity.status(status).headers(headers).build();
    }

    if (isJsonRequest(request)) {
      return ResponseEntity.status(status).headers(headers).body(jsonBody(status, request));
    }

    headers.forEach((name, values) -> values.forEach(value -> response.addHeader(name, value)));
    ModelAndView mav = new ModelAndView(ERROR_VIEW, status);
    mav.addObject("status", status.value());
    mav.addObject("error", htmlTitle(status));
    mav.addObject("message", userMessage(status));
    return mav;
  }

  static HttpStatusCode resolveStatus(Exception ex) {
    if (ex instanceof ErrorResponse errorResponse) {
      return errorResponse.getStatusCode();
    }
    if (ex instanceof HttpMessageNotReadableException || ex instanceof TypeMismatchException) {
      return HttpStatus.BAD_REQUEST;
    }
    ResponseStatus annotated =
        AnnotatedElementUtils.findMergedAnnotation(ex.getClass(), ResponseStatus.class);
    if (annotated != null) {
      return annotated.code();
    }
    return HttpStatus.INTERNAL_SERVER_ERROR;
  }

  private static Map<String, Object> jsonBody(HttpStatusCode status, HttpServletRequest request) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("timestamp", LocalDateTime.now().toString());
    body.put("status", status.value());
    HttpStatus known = HttpStatus.resolve(status.value());
    body.put("error", known != null ? known.getReasonPhrase() : "Error");
    body.put("message", userMessage(status));
    body.put("path", request.getRequestURI());
    return body;
  }

  private static String userMessage(HttpStatusCode status) {
    if (status.value() == HttpStatus.NOT_FOUND.value()) {
      return MSG_NOT_FOUND;
    }
    return status.is4xxClientError() ? MSG_CLIENT_ERROR : MSG_SERVER_ERROR;
  }

  private static String htmlTitle(HttpStatusCode status) {
    if (status.value() == HttpStatus.NOT_FOUND.value()) {
      return "Recurso no encontrado";
    }
    return status.is4xxClientError() ? "Solicitud no válida" : "Error interno";
  }

  private static boolean isJsonRequest(HttpServletRequest request) {
    String accept = request.getHeader("Accept");
    return accept != null && accept.contains("application/json");
  }
}
