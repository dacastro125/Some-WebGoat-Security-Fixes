/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.container.WebGoat;
import org.owasp.webgoat.container.session.LabelDebugger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Verifies role-based access control on {@link LabelDebugService} across both HTTP security
 * filter rules and method-level authorization, while ensuring public UI label endpoints remain
 * accessible to authenticated users.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK, classes = WebGoat.class)
@TestPropertySource(
    locations = {
      "classpath:/application-webgoat.properties",
      "classpath:/application-webgoat-test.properties"
    })
class LabelDebugAccessControlTest {

  private static final String DEBUG_URL = "/service/debug/labels.mvc";

  @Autowired private WebApplicationContext wac;
  @Autowired private LabelDebugger labelDebugger;
  @Autowired private LabelDebugService labelDebugService;

  @MockitoBean private ClientRegistrationRepository clientRegistrationRepository;

  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    labelDebugger.setEnabled(false);
    mockMvc = MockMvcBuilders.webAppContextSetup(wac).apply(springSecurity()).build();
  }

  @AfterEach
  void tearDown() {
    labelDebugger.setEnabled(false);
  }

  @ParameterizedTest
  @ValueSource(strings = {DEBUG_URL, DEBUG_URL + "?enabled=true", DEBUG_URL + "?enabled=false"})
  void unauthenticatedRequestsAreRejectedAndDoNotModifyState(String url) throws Exception {
    mockMvc.perform(get(url)).andExpect(status().is3xxRedirection());
    assertThat(labelDebugger.isEnabled()).isFalse();
  }

  @ParameterizedTest
  @ValueSource(strings = {DEBUG_URL, DEBUG_URL + "?enabled=true", DEBUG_URL + "?enabled=false"})
  @WithMockUser(username = "usuarioprueba1", authorities = "WEBGOAT_USER")
  void regularUserIsForbiddenFromDebugEndpointsAndStateRemainsUnchanged(String url)
      throws Exception {
    mockMvc.perform(get(url)).andExpect(status().isForbidden());
    assertThat(labelDebugger.isEnabled()).isFalse();
  }

  @Test
  @WithMockUser(username = "usuarioprueba1", authorities = "WEBGOAT_USER")
  void methodLevelSecurityBlocksDirectInvocationByRegularUser() {
    assertThatThrownBy(() -> labelDebugService.checkDebuggingStatus())
        .isInstanceOf(AccessDeniedException.class);
    assertThatThrownBy(() -> labelDebugService.setDebuggingStatus(true))
        .isInstanceOf(AccessDeniedException.class);
    assertThat(labelDebugger.isEnabled()).isFalse();
  }

  @Test
  @WithMockUser(username = "admin", authorities = "WEBGOAT_ADMIN")
  void adminCanInspectAndToggleDebugState() throws Exception {
    mockMvc
        .perform(get(DEBUG_URL))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.enabled").value(false))
        .andExpect(jsonPath("$.success").value(true));

    mockMvc
        .perform(get(DEBUG_URL).param("enabled", "true"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.enabled").value(true))
        .andExpect(jsonPath("$.success").value(true));
    assertThat(labelDebugger.isEnabled()).isTrue();

    mockMvc
        .perform(get(DEBUG_URL).param("enabled", "false"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.enabled").value(false))
        .andExpect(jsonPath("$.success").value(true));
    assertThat(labelDebugger.isEnabled()).isFalse();
  }

  @Test
  @WithMockUser(username = "usuarioprueba1", authorities = "WEBGOAT_USER")
  void regularUserStillAccessesPublicLabelsEndpoint() throws Exception {
    mockMvc.perform(get("/service/labels.mvc")).andExpect(status().isOk());
  }
}
