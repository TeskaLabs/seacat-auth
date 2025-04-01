---
title: Připojení aplikací OAuth
---

# Připojení aplikací OAuth


## Nastavení introspekce OAuth2 pro webovou aplikaci

Nejprve zaregistrujte svou webovou aplikaci v sekci Klient v uživatelském rozhraní SeaCat.
Získáte `client_id`, který je nezbytný pro požadavek na introspekci.

Nastavte umístění pro vaši aplikaci v konfiguraci Nginx:

```nginx
location <APPLICATION_PATH> {
    proxy_pass <INTERNAL_APPLICATION_URL>;
    
    auth_request        /_oauth2_introspect;
    auth_request_set    $authorization $upstream_http_authorization;
    proxy_set_header    Authorization $authorization;

    error_page 401 /auth/api/openidconnect/authorize?<CLIENT_PARAMETERS>&redirect_uri=$request_uri;
}

```

- `<APPLICATION_PATH>` je cesta, kde bude vaše aplikace přístupná uživatelům.
- `<INTERNAL_APPLICATION_URL>` je interní URL vašeho aplikačního serveru.
- `<CLIENT_PARAMETERS>` je dotazovací řetězec vašich registrovaných klientských parametrů, obvykle zahrnující `client_id`, `response_type`, `scope`. Všimněte si, že další parametry, jako například `client_secret`, mohou být vyžadovány v závislosti na typu a konfiguraci vašeho klienta. 
Příklad cesty s minimálními parametry: `/auth/api/openidconnect/authorize?client_id=abc1230ZM3n37BmbtKrqqw&response_type=code&scope=openid&redirect_uri=$request_uri`