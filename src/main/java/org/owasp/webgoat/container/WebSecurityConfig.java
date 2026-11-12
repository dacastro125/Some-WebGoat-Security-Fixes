/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import lombok.AllArgsConstructor;
import org.owasp.webgoat.container.users.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;

/** Security configuration for WebGoat. */
@Configuration
@AllArgsConstructor
@EnableWebSecurity
public class WebSecurityConfig {

  private final UserService userDetailsService;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(
            auth ->
                auth.requestMatchers(
                        "/favicon.ico",
                        "/css/**",
                        "/images/**",
                        "/js/**",
                        "/fonts/**",
                        "/plugins/**",
                        "/proxy.pac",
                        "/registration",
                        "/register.mvc",
                        "/actuator/**")
                    .permitAll()
                    // Lessons deliver mail by POSTing to the mailbox over HTTP (RestTemplate),
                    // which carries no session, so the receiving endpoint must be public. Reading
                    // the mailbox (GET /mail) stays authenticated so users only see their own mail.
                    .requestMatchers(HttpMethod.POST, "/mail")
                    .permitAll()
                    // Administration endpoints: restricted to WEBGOAT_ADMIN only.
                    .requestMatchers("/service/admin/**")
                    .hasAuthority("WEBGOAT_ADMIN")
                    .anyRequest()
                    .authenticated())
        .formLogin(
            login ->
                login
                    .loginPage("/login")
                    .defaultSuccessUrl("/welcome.mvc", true)
                    .usernameParameter("username")
                    .passwordParameter("password")
                    .permitAll())
        .oauth2Login(
            oidc -> {
              oidc.defaultSuccessUrl("/login-oauth.mvc");
              oidc.loginPage("/login");
            })
        .logout(logout -> logout.deleteCookies("JSESSIONID").invalidateHttpSession(true))
        .csrf(csrf -> csrf.disable())
        .headers(
            headers ->
                headers
                    .frameOptions(frame -> frame.deny())
                    .contentTypeOptions(contentType -> {})
                    .xssProtection(xss -> {})
                    .httpStrictTransportSecurity(
                        hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
                    .referrerPolicy(
                        referrer ->
                            referrer.policy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                    .contentSecurityPolicy(
                        csp ->
                            csp.policyDirectives(
                                "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'")))
        .exceptionHandling(
            handling ->
                handling.authenticationEntryPoint(new AjaxAuthenticationEntryPoint("/login")))
        .build();
  }

  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService);
  }

  @Bean
  @Primary
  public UserDetailsService userDetailsServiceBean() {
    return userDetailsService;
  }

  @Bean
  public AuthenticationManager authenticationManager(
      AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  @Bean
  public NoOpPasswordEncoder passwordEncoder() {
    return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
  }
}
