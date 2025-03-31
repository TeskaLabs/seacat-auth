---
title: Komponenty
---

# Komponenty SeaCat Auth

Tato sekce objasňuje role různých komponent v ekosystému SeaCat Auth.

### Webové uživatelské rozhraní

Existují dvě samostatná webová uživatelská rozhraní (uživatelské rozhraní):

* [SeaCat WebUI](http://gitlab.teskalabs.int/seacat/seacat-webui) poskytuje grafické rozhraní pro správu SeaCat Auth.
* [SeaCat Auth WebUI](http://gitlab.teskalabs.int/seacat/seacat-auth-webui) poskytuje přihlašovací formulář, obrazovku pro resetování hesla a další obrazovky pro běžné uživatele.

### Docker a Docker Compose

Celá instalace webu může být dockerizována a nasazena pomocí docker-compose, viz [rychlý start](../getting-started/quick-start).

### Nginx

Nginx se používá k přesměrování požadavků přicházejících zvenčí prostředí na chráněná místa. Tyto požadavky jsou nejprve přesměrovány na SeaCat Auth, kde je vyhodnocen jejich stav autentizace. Pokud je již autentizován, je požadavek povolen do chráněného prostoru.

### MongoDB

Je používán SeaCat Auth pro ukládání známých uživatelů a dalších souvisejících trvalých dat.