---
title: Configure SeaCat Auth to send mails
---

# Configure SeaCat Auth to send mails

SeaCat Auth can send mails respective emails to users, eg. when they forget password and so on.
For this, outbound mailing server aka SMTP has to be configured.


## Generic SMTP configuration

```
[seacatauth:communication:email:smtp]
sender_email_address=<user@email.info>
host=<hostname.example.com>
port=<25|if missing, default is guessed>
user=<username>
password=<password>
ssl=<yes|no>
starttls=<yes|no>
```

## SMTP configuration form SendGrid

Based on: https://sendgrid.com/docs/for-developers/sending-email/getting-started-smtp/

```
[seacatauth:communication:email:smtp]
sender_email_address=<user@email.info>
host=smtp.sendgrid.net
ssl=yes
starttls=no

# Username is always `apikey`
user=apikey

# SendGrid API key from the SendGrid API Keys page.
password=XX.xxxxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy

```

