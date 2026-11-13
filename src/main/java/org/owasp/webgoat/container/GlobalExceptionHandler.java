/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * Global exception handler mitigating CWE-209 (Generation of Error Message Containing Sensitive Information).
 * Sanitizes all client-facing error responses while preserving full diagnostic stack traces exclusively
 * in the server's internal logs.
 */
@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

  /**
   * Handles static resource / route not found exceptions (HTTP 404).
   */
  @ExceptionHandler(NoResourceFoundException.class)
  @ResponseStatus(HttpStatus.NOT_FOUND)
  public Object handleNotFound(NoResourceFoundException ex, HttpServletRequest request) {
    log.warn(
        "Resource not found [404] requested from {}: {}",
        request.getRemoteAddr(),
        request.getRequestURI());

    if (isJsonRequest(request)) {
      Map<String, Object> errorBody = new HashMap<>();
      errorBody.put("timestamp", LocalDateTime.now().toString());
      errorBody.put("status", 404);
      errorBody.put("error", "Not Found");
      errorBody.put("message", "El recurso solicitado no fue encontrado.");
      errorBody.put("path", request.getRequestURI());
      return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorBody);
    }

    ModelAndView mav = new ModelAndView("error");
    mav.addObject("status", 404);
    mav.addObject("error", "Recurso no encontrado");
    mav.addObject("message", "La página o recurso que está buscando no existe o fue movido.");
    return mav;
  }

  /**
   * Global catch-all handler for unhandled runtime exceptions (HTTP 500).
   */
  @ExceptionHandler(Exception.class)
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  public Object handleGlobalException(Exception ex, HttpServletRequest request) {
    log.error(
        "Unhandled exception intercepted during request to {}: {}",
        request.getRequestURI(),
        ex.getMessage(),
        ex);

    if (isJsonRequest(request)) {
      Map<String, Object> errorBody = new HashMap<>();
      errorBody.put("timestamp", LocalDateTime.now().toString());
      errorBody.put("status", 500);
      errorBody.put("error", "Internal Server Error");
      errorBody.put(
          "message",
          "Ha ocurrido un error interno en el servidor. Por favor intente más tarde.");
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorBody);
    }

    ModelAndView mav = new ModelAndView("error");
    mav.addObject("status", 500);
    mav.addObject("error", "Error interno");
    mav.addObject("message", "Ha ocurrido un error inesperado al procesar su solicitud.");
    return mav;
  }

  private boolean isJsonRequest(HttpServletRequest request) {
    String accept = request.getHeader("Accept");
    return accept != null && accept.contains("application/json");
  }
}
