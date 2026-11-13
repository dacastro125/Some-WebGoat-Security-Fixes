/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.service;

import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.session.LabelDebugger;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Exposes global label debugging controls strictly to {@code WEBGOAT_ADMIN} accounts, because
 * {@link LabelDebugger} holds shared application-wide state.
 */
@Controller
@Slf4j
@AllArgsConstructor
@PreAuthorize("hasAuthority('WEBGOAT_ADMIN')")
public class LabelDebugService {

  private static final String URL_DEBUG_LABELS_MVC = "/service/debug/labels.mvc";
  private static final String KEY_ENABLED = "enabled";
  private static final String KEY_SUCCESS = "success";

  private LabelDebugger labelDebugger;

  /**
   * Checks if debugging of labels is enabled or disabled
   *
   * @return a {@link org.springframework.http.ResponseEntity} object.
   */
  @GetMapping(path = URL_DEBUG_LABELS_MVC, produces = MediaType.APPLICATION_JSON_VALUE)
  public @ResponseBody ResponseEntity<Map<String, Object>> checkDebuggingStatus() {
    log.debug("Checking label debugging, it is {}", labelDebugger.isEnabled());
    Map<String, Object> result = createResponse(labelDebugger.isEnabled());
    return new ResponseEntity<>(result, HttpStatus.OK);
  }

  /**
   * Sets the enabled flag on the label debugger to the given parameter. State changes are POST-only:
   * a GET (e.g. a cross-site link followed by an administrator, which SameSite=Lax still allows)
   * only reads the current state.
   *
   * @param enabled {@link org.owasp.webgoat.container.session.LabelDebugger} object
   * @return a {@link org.springframework.http.ResponseEntity} object.
   */
  @PostMapping(
      value = URL_DEBUG_LABELS_MVC,
      produces = MediaType.APPLICATION_JSON_VALUE,
      params = KEY_ENABLED)
  public @ResponseBody ResponseEntity<Map<String, Object>> setDebuggingStatus(
      @RequestParam("enabled") Boolean enabled) {
    log.debug("Setting label debugging to {} ", labelDebugger.isEnabled());
    Map<String, Object> result = createResponse(enabled);
    labelDebugger.setEnabled(enabled);
    return new ResponseEntity<>(result, HttpStatus.OK);
  }

  /**
   * @param enabled {@link org.owasp.webgoat.container.session.LabelDebugger} object
   * @return a {@link java.util.Map} object.
   */
  private Map<String, Object> createResponse(Boolean enabled) {
    return Map.of(KEY_SUCCESS, Boolean.TRUE, KEY_ENABLED, enabled);
  }
}
