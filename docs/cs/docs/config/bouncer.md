---
title: SeaCat Auth Bouncer
---

# SeaCat Auth Bouncer

Mechanismus přesměrování zajišťuje, že po úspěšném přihlášení uživatele
prostřednictvím SeaCat Auth OpenIDConnect je uživatel přesměrován na specifikovanou URL,
i když URL obsahuje speciální znaky, jako je hash (#),
což by normálně bránilo serveru v přesměrování na správný zdroj.

## BatMan

Ve výchozím nastavení SeaCat Auth Bouncer přesměrovává uživatele po přihlášení na BatMan,
takže se přihlášení uloží také do cookie.
Bez tohoto přesměrování by aplikační server, jako je NGINX,
přesměroval uživatele zpět na BatMan a ztratil části URL (například #).

## Obecná konfigurace Bounceru

```
[bouncer]
allowed_urls=<MY_URL>/kibana;<MY_URL>/grafana
seacat_auth_url_prefix=/api/seacat
```

`allowed_urls` slouží jako bílá listina URL oddělených `;`, na které může být uživatel přesměrován,
ostatní URL nejsou povolena k použití v bounceru a uživatel obdrží
HTTP 400 - Bad Request odpověď.

`seacat_auth_url_prefix` specifikuje relativní cestu v URL, na které SeaCat Auth běží,
to je potřeba pro správné přesměrování na přihlášení, BatMan, zpět na bouncer po přihlášení atd.

## Obecná konfigurace BatMan

```
[batman]
oidc_url=<MY_SEACAT_AUTH_URL>/openidconnect
```

`oidc_url` specifikuje OpenIDConnect URL, na kterou BatMan přesměrovává uživatele k přihlášení.