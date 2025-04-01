---
title: Postman
---

# Použití SeaCat Auth s Postmanem

Postman je užitečný vývojový nástroj pro ladění aplikací, které interagují se SeaCat Auth. 
Hlavní výhodou je, že Postman nativně **zpracovává OAuth2.0 autentizaci** a poskytuje nástroje pro **správu autentizačních tokenů**.

## Požadavky

- Běžící instance SeaCat Auth
  - Zkontrolujte sekci `[general]` v konfiguraci, abyste se ujistili, že proměnné `auth_webui_base_url` a 
    `public_api_base_url` ukazují na skutečné URL vaší SeaCat Auth WebUI 
- Běžící instance SeaCat Auth WebUI
  - Auth WebUI je vyžadováno pro autentizaci v SeaCat Auth
  - Zkontrolujte směrování proxy (v Nginx), abyste se ujistili, že správně ukazuje 
    na váš backend SeaCat Auth

## Konfigurace prostředí Postman

- [Importujte OpenAPI specifikace](https://learning.postman.com/docs/integrations/available-integrations/working-with-openAPI/) 
  z `/asab/v1/openapi` v SeaCat Auth API.
- Nastavte prostředí SeaCat Auth [Postman](https://learning.postman.com/docs/sending-requests/managing-environments/). 
  Následující proměnné je třeba definovat:
  - `BASE_URL` by měla obsahovat základní URL vašeho SeaCat API, například `https://my-domain.int/seacat/api/seacat_auth` 
  - `AUTH_URL` by měla obsahovat základní URL vašeho SeaCat Auth, například `https://my-domain.int/auth`. 
    Používá se pro autentizaci vaší relace.

## Vytvoření autorizované relace OAuth2

- V panelu **Collections** otevřete kontextové menu vaší kolekce SeaCat Auth a zvolte **Edit**. 
- Přejděte na kartu **Authorization**.
- Pro **Authorization type** vyberte **OAuth 2.0**
- [Požádejte o nový přístupový token](https://learning.postman.com/docs/sending-requests/authorization/#requesting-an-oauth-20-token) 
  a přihlaste se do vaší SeaCat Auth WebUI
- Vaše relace Postman je nyní autentizována!

### Detaily přístupového tokenu Postman

 * Typ udělení: "Authorization Code"
 * URL pro zpětné volání: http://localhost:8080/???? (???)
 * Auth URL: http://localhost:8080/openidconnect/authorize
 * URL přístupového tokenu: http://localhost:8080/openidconnect/token
 * Client Id: [jakýkoli řetězec]
 * Client Secret: [jakýkoli řetězec]
 * Scope: `openid`
 * State: [prázdný řetězec]
 * Autentizace klienta: Odeslat přihlašovací údaje klienta v těle


**`POZNÁMKA`** Některé API požadavky budou splněny pouze v případě, že máte přístup k specifickým administrátorským zdrojům 
(`authz:superuser` nebo `authz:tenant:admin`). 
Zkontrolujte popis těchto volání, abyste zjistili, zda existují nějaká omezení přístupu.