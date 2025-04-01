---
title: Grafana
---

# Použití autorizace Seacat v Grafaně

Tento návod vám ukáže, jak nastavit [Grafanu](https://grafana.com/), abyste mohli používat Seacat Auth pro přihlášení a řízení přístupu. Grafana má nativní podporu pro OAuth autorizační tok, takže její propojení se Seacat Auth je poměrně jednoduché.

1. Zaregistrujte nového klienta pro vaši aplikaci Grafana v sekci **Clients** v Seacat Admin UI. Poznamenejte si ID klienta.
2. Vytvořte následující ID zdrojů v sekci **Resources** v Seacat Admin UI (nebo si zvolte jiná jména, ale nezapomeňte je změnit v konfiguraci `role_attribute_path` v Grafaně níže):
    - `grafana:access`: Bude mapováno na [Grafanovu roli _Viewer_](https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/#organization-roles), 
    která uživateli umožňuje procházet dashboardy a další data, ale ne vytvářet nebo měnit cokoliv.
    - `grafana:edit`: Bude mapováno na [Grafanovu roli _Editor_](https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/#organization-roles), 
    která uživateli umožňuje procházet a upravovat dashboardy a další data.
3. Nakonfigurujte Grafanu tak, aby používala vaši instanci Seacat Auth jako [Generic OAuth provider](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/generic-oauth/).
  To lze provést buď v konfiguračním souboru Grafany, nebo možná pohodlněji pomocí proměnných prostředí ve vašem souboru `docker-compose.yaml`, jak je následující:

```yaml
services:
  grafana:
    image: grafana/grafana:10.3.1
    network_mode: host
    (...)
    environment:
      ## Required configuration options
      # URL, kde je Grafana přístupná v prohlížeči
      GF_SERVER_ROOT_URL: ${PUBLIC_URL}/grafana/
      # Povolit OAuth přihlášení
      GF_AUTH_GENERIC_OAUTH_ENABLED: true
      # ID klienta vydané Seacat Auth
      GF_AUTH_GENERIC_OAUTH_CLIENT_ID: ${GRAFANA_CLIENT_ID}
      # Tajemství klienta vydané Seacat Auth (zatím není podporováno)
      GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET: ""
      # OAuth rozsahy, které Grafana požádá od Seacat Auth
      GF_AUTH_GENERIC_OAUTH_SCOPES: openid email profile
      # Veřejná URL adresa koncového bodu autorizace Seacat Auth OAuth
      GF_AUTH_GENERIC_OAUTH_AUTH_URL: ${PUBLIC_URL}/api/openidconnect/authorize
      # Interní URL adresa koncového bodu tokenů Seacat Auth OAuth
      GF_AUTH_GENERIC_OAUTH_TOKEN_URL: ${INTERNAL_SEACAT_AUTH_URL}/openidconnect/token
      # Interní URL adresa koncového bodu uživatelských informací Seacat Auth OAuth
      GF_AUTH_GENERIC_OAUTH_API_URL: ${INTERNAL_SEACAT_AUTH_URL}/openidconnect/userinfo
      
      ## Další užitečné konfigurační možnosti
      # Kam je uživatel přesměrován po stisknutí tlačítka "Odhlásit se"
      GF_AUTH_SIGNOUT_REDIRECT_URL: ${PUBLIC_URL}
      # Přeskočit přihlašovací obrazovku Grafany a automaticky přihlásit uživatele
      GF_AUTH_GENERIC_OAUTH_AUTO_LOGIN: true
      # Zakázat PKCE
      GF_AUTH_GENERIC_OAUTH_USE_PKCE: false
      # Zakázat obnovovací tokeny (zatím není podporováno)
      GF_AUTH_GENERIC_OAUTH_USE_REFRESH_TOKEN: false
      # Název poskytovatele OAuth zobrazený na tlačítku "Přihlásit se pomocí ..." na přihlašovací obrazovce Grafany
      GF_AUTH_GENERIC_OAUTH_NAME: Seacat Auth
      # Získat uživatelské jméno a jméno na obrazovce primárně z pole standardu OpenID Connect "preferred_username", s fallbackem na pole "username" a "sub"
      GF_AUTH_GENERIC_OAUTH_LOGIN_ATTRIBUTE_PATH: preferred_username || username || sub
      GF_AUTH_GENERIC_OAUTH_NAME_ATTRIBUTE_PATH: preferred_username || username || sub
      # Řídit oprávnění uživatelů pomocí autorizovaných zdrojů Seacat Auth:
      #   Následující výraz JMESPath přiřazuje uživateli roli Grafana v závislosti na autorizovaných zdrojích v jejich ID tokenu nebo Userinfo
      GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH: >
        contains(resources."*"[*], 'authz:superuser') && 'Admin' 
        || contains(resources."*"[*], 'grafana:edit') && 'Editor' 
        || contains(resources."*"[*], 'grafana:access') && 'Viewer'
      # Zamezit přihlášení, pokud uživatel není autorizován pro žádný z zdrojů ve výrazu výše
      GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT: true
```

- `PUBLIC_URL` je základní URL adresa, ze které je Seacat Auth přístupný z prohlížeče, například `https://example.com`.
- `INTERNAL_SEACAT_AUTH_URL` je interní URL adresa soukromého webového kontejneru Seacat Auth, obvykle `http://localhost:8900`.
- `GRAFANA_CLIENT_ID` je ID klienta vydané Seacat Auth.

**POZNÁMKA:** Výše uvedená konfigurace předpokládá, že backend Grafany komunikuje se serverem Seacat Auth přes zabezpečenou interní síť (obvykle VPN). 
Pokud tomu tak není a obě služby nemají sdílenou interní síť, nakonfigurujte `GF_AUTH_GENERIC_OAUTH_TOKEN_URL` a `GF_AUTH_GENERIC_OAUTH_API_URL` pomocí veřejných URL.

Pokud je toto vaše testovací prostředí a používáte samostatně podepsaný SSL certifikát, budete muset přidat také následující přepínač:
```yaml
GF_AUTH_GENERIC_OAUTH_TLS_SKIP_VERIFY_INSECURE: true
```

Pro více informací o konfiguraci Grafana OAuth, [odkazujte na její dokumentaci](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/generic-oauth/).