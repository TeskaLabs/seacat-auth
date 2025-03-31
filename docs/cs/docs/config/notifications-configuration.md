---
title: Odesílání oznámení
---

# Konfigurace SeaCat Auth pro odesílání e-mailů

SeaCat Auth může odesílat e-maily uživatelům, např. když zapomenou heslo atd. K tomu je nutné nakonfigurovat odchozí poštovní server, známý jako SMTP.

## Obecná konfigurace SMTP

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

## Konfigurace SMTP pro SendGrid

Na základě: https://sendgrid.com/docs/for-developers/sending-email/getting-started-smtp/

```
[seacatauth:communication:email:smtp]
sender_email_address=<user@email.info>
host=smtp.sendgrid.net
ssl=yes
starttls=no

# Uživatelské jméno je vždy `apikey`
user=apikey

# API klíč SendGrid z stránky API Keys SendGrid.
password=XX.xxxxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy

```