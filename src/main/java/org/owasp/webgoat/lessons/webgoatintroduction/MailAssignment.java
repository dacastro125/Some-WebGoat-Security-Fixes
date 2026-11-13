/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webgoatintroduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.mailbox.MailboxService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MailAssignment implements AssignmentEndpoint {

  private final MailboxService mailboxService;

  public MailAssignment(MailboxService mailboxService) {
    this.mailboxService = mailboxService;
  }

  @PostMapping("/WebGoat/mail/send")
  @ResponseBody
  public AttackResult sendEmail(
      @RequestParam String email, @CurrentUsername String webGoatUsername) {
    String username = email.substring(0, email.indexOf("@"));
    if (username.equalsIgnoreCase(webGoatUsername)) {
      Email mailEvent =
          Email.builder()
              .recipient(username)
              .title("Test messages from WebGoat")
              .contents(
                  "This is a test message from WebGoat, your unique code is: "
                      + StringUtils.reverse(username))
              .sender("webgoat@owasp.org")
              .build();
      try {
        mailboxService.deliver(
            mailEvent.getSender(), mailEvent.getRecipient(), mailEvent.getTitle(), mailEvent.getContents());
      } catch (RuntimeException e) {
        return informationMessage(this).feedback("webgoat.email_failed").build();
      }
      return informationMessage(this).feedback("webgoat.email_send").feedbackArgs(email).build();
    } else {
      return informationMessage(this)
          .feedback("webgoat.email_mismatch")
          .feedbackArgs(username)
          .build();
    }
  }

  @PostMapping("/WebGoat/mail")
  @ResponseBody
  public AttackResult completed(@RequestParam String uniqueCode, @CurrentUsername String username) {
    if (uniqueCode.equals(StringUtils.reverse(username))) {
      return success(this).build();
    } else {
      return failed(this).feedbackArgs("webgoat.code_incorrect").feedbackArgs(uniqueCode).build();
    }
  }
}
