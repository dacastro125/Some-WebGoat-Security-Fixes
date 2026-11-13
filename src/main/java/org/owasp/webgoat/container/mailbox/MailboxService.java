/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.mailbox;

import java.time.LocalDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Delivers lesson e-mails straight into the WebGoat mailbox.
 *
 * <p>Lessons used to POST their e-mails to {@code /WebGoat/mail} over a plain-HTTP self-call. Once
 * the connector only accepts TLS that call fails, so lessons deliver in-process instead. The
 * controller uses the same method, so both paths store mail identically.
 */
@Service
@RequiredArgsConstructor
public class MailboxService {

  private final MailboxRepository mailboxRepository;

  public Email deliver(Email email) {
    // The receipt time is server-controlled, whatever the sender supplied.
    email.setTime(LocalDateTime.now());
    return mailboxRepository.save(email);
  }

  public Email deliver(String sender, String recipient, String title, String contents) {
    return deliver(
        Email.builder()
            .sender(sender)
            .recipient(recipient)
            .title(title)
            .contents(contents)
            .build());
  }
}
