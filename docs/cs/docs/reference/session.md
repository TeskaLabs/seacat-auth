---
title: Session
---

# Session

- Objekt session představuje autentizaci a autorizaci uživatele nebo stroje.
- Dva základní typy session jsou *root* a *client*. 
  Klientské session mohou být buď *na základě přístupového tokenu*, nebo *na základě cookie*. 
  Dále existují speciální typy session: *machine-to-machine* a *anonymní* session.

## Single Sign-On session (alias "root session")

- Vytváří se při přihlášení uživatele. 
- Používá se jako důkaz autentizace uživatele (Single Sign-On) pro požadavky na autorizaci OAuth.
- Unikátně identifikována pomocí cookie prohlížeče (ve výchozím nastavení nazývána `SeaCatSCI`).

## Klientská session (subsession)

- Používá se jako důkaz autorizace uživatele a klienta.
- Vytváří se jako výsledek úspěšného požadavku na autorizaci OAuth na koncovém bodě `/openidconnect/authorize`.
- Odvozuje se od root session; uživatelská root session je předpokladem pro vytvoření klientské session pro toho uživatele.
- Unikátně identifikována buď pomocí tokenů OAuth 2.0, nebo pomocí HTTP cookie.

### Klientská session na základě přístupového tokenu

- Vytváří se požadavkem na autorizaci na `/openidconnect/authorize` s `openid` ve scopě.
- Vhodná pro klienty, kteří podporují protokol OAuth 2.0.
- Unikátně identifikována pomocí přístupového tokenu OAuth 2.0.

### Klientská session na základě cookie

- Vytváří se požadavkem na autorizaci na `/openidconnect/authorize` s `cookie` ve scopě.
- Vhodná pro klienty, kteří nepodporují protokol OAuth 2.0.
- Unikátně identifikována pomocí cookie prohlížeče.

## Machine-to-machine (M2M) session

- Speciální typ root session, který zahrnuje autentizaci a autorizaci klienta.
- Slouží jako důkaz autentizace a autorizace v komunikaci stroj-stroj (bez zapojení lidského uživatele).

## Anonymní session

- Speciální typ session, která identifikuje neautentizovaného uživatele.
- Používá se pro sledování návštěvníků na klientských místech, která lze navštívit bez autentizace.
- Je to klientská session, která může existovat bez root session. Anonymní root session se vytváří pouze tehdy, když
  je potřeba propojit více anonymních klientských session.

## Životní cyklus session

- Když se koncový uživatel úspěšně přihlásí, vytvoří se Single Sign-On (root) session. 
  Obsahuje identifikátor uživatele a podrobnosti o procesu autentizace uživatele: kdy k autentizaci došlo, 
  jaké prostředky autentizace byly použity atd. Obvykle má dlouhou životnost (několik dní až měsíců).
  Uživatel obdrží HTTP cookie, které identifikuje tuto SSO session.
- Když chce uživatel přistupovat k aplikaci klienta, aplikace požádá server Seacat Auth o autorizaci 
  k přístupu k datům koncového uživatele a dalším zdrojům, což se obvykle provádí pomocí toku autorizačního kódu OAuth 2.0. 
  Prvním krokem toku je požadavek na autorizaci, který, pokud je úspěšný, produkuje krátkodobou (ne déle 
  než několik minut) klientskou session a autorizační kód, který slouží jako identifikátor session. 
  Session obsahuje odkaz na Single Sign-On session koncového uživatele a podrobnosti o autorizaci, 
  jako je identifikátor aplikace klienta (client ID) a požadovaný rozsah autorizace.
- Klientská aplikace poté používá autorizační kód k provedení požadavku na token. 
  Pokud je úspěšný, tento požadavek spotřebovává autorizační kód a produkuje sadu dlouhodobějších tokenů - přístupový token 
  a ID token, které jsou platné několik hodin, a refresh token, který je platný několik dní až týdnů.
  Klientská session je prodloužena tak, aby trvala tak dlouho, jak refresh token, a aktualizována tak, aby obsahovala aktuální informace o uživateli
  a jejich autorizovaném tenantovi a zdrojích.
- Klientská aplikace poté neustále používá přístupový token jako důkaz autorizace pro aplikace vlastníka zdrojů. Například frontendová aplikace Web UI (klient) posílá přístupový token s každým požadavkem REST API 
  na backendovou aplikaci (vlastník zdrojů). Vlastník zdrojů může požádat autorizační server o ověření 
  přístupového tokenu v tzv. _introspekčním požadavku_.
- Když přístupový token vyprší, klientská aplikace může požádat o nový pomocí refresh tokenu. 
  Tento požadavek vede k vydání nové sady tokenů (přístupový, refresh a ID) a klientská session je 
  opět prodloužena, aby odpovídala novému refresh tokenu.
- Když klientská session vyprší nebo když klient požádá o její ukončení, session je smazána spolu se 
  všemi jejími aktivními tokeny.
- Když vyprší Single Sign-On session nebo když se koncový uživatel odhlásí, session je neplatná a smazána 
  spolu se svým cookie, spolu se všemi klientskými session, které byly otevřeny pod touto Single Sign-On session 
  a jejich tokeny.