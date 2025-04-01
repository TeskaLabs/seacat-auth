---
title: Rychlý start
---

# Rychlý start

Toto je příručka pro rychlý start pro **TeskaLabs SeaCat Auth**, která vás rychle uvede do problematiky.


## Požadavky

Následující seznam obsahuje všechny požadavky pro úspěšné nasazení _SeaCat Auth_:

* [Docker](https://www.docker.com)
* [docker-compose](https://docs.docker.com/compose/)
* Neomezené připojení k internetu

_Poznámka: Tato příručka je určena pro Windows (s použitím WSL2 a Docker), Mac OS (s použitím Docker Desktop) a Linux._


## Krok 1: Vytvoření nasazovacího adresáře

V této příručce předpokládáme, že _SeaCat Auth_ bude nasazen do `/opt/site-auth`.

_Poznámka: Nasazovací adresář také nazýváme "web"._

Struktura nasazovacího adresáře:

```
/opt/site-auth
  seacatauth-conf/
    seacatauth.conf
  mongodb-data/
  nginx-conf/
    nginx.conf
  nginx-root/
    index.html
  seacat-auth-webui/
  seacat-webui/
  log/
  docker-compose.yml
```

[Repozitář SeaCat Auth na GitHubu](https://github.com/TeskaLabs/seacat-auth) obsahuje šablonu nasazovacího adresáře v adresáři `./doc/docker`.
Tuto šablonu nasazovacího adresáře lze také stáhnout [zde](https://nightly.link/TeskaLabs/seacat-auth/workflows/ci/main/seacat-auth-docker-starter.zip).


## Krok 2: Úprava konfigurace SeaCat Auth

  - **[Nastavte SMTP server](../config/mail-server).**  
    Nastavení uživatelského účtu v SeaCat Auth vyžaduje odeslání e-mailu s aktivačním odkazem.


## Krok 3: Instalace webových uživatelských rozhraní

- Nainstalujte **SeaCat Auth Web UI** do `./seacat-auth-webui/` z https://asabwebui.z16.web.core.windows.net/seacat-auth/master/seacat-auth-webui.tar.lzma 

- Nainstalujte **SeaCat Web UI** do `./seacat-webui/` z https://asabwebui.z16.web.core.windows.net/seacat-auth/master/seacat-auth-webui.tar.lzma 


## Krok 4: Spuštění SeaCat Auth

Proveďte `docker-compose up -d` v adresáři `/opt/site-auth`.

Nyní _SeaCat Auth_ běží v takzvaném režimu provisioning.
Můžete použít _SeaCat Web UI_ k dokončení nastavení vytvořením uživatelů atd.
Pro tento krok, prosím [pokračujte k nastavení SeaCat Auth v režimu provisioning](../config/provisioning).


## Další kroky

### Nasazení SeaCat Auth s vlastním hostname a HTTPS

Tato část příručky předpokládá, že váš server má správné veřejné doménové jméno.

- **Získejte SSL certifikát** (např. pomocí Let's Encrypt a ACME).

- Šablona konfigurace Nginx pro HTTPS se nachází v [`nginx-conf/nginx-https.conf`](https://github.com/TeskaLabs/seacat-auth/tree/main/doc/docker/nginx-conf/nginx-https.conf).

- Zkontrolujte, že cesty k SSL klíči a certifikátu v konfiguraci Nginx ukazují na místa, kde se nachází váš SSL certifikát a klíč.

- V [`seacatauth-conf/seacatauth.conf`](https://github.com/TeskaLabs/seacat-auth/tree/main/doc/docker/seacatauth-conf/seacatauth.conf):
  - Změňte hostname `public_api_base_url` a `auth_webui_base_url`.
  - Volitelně můžete také nastavit `[seacatauth:cookie] domain`, aby odpovídalo vašemu hostname.

- Spusťte služby pomocí `docker-compose up -d` a [pokračujte k nastavení SeaCat Auth v režimu provisioning](../config/provisioning).


#### Vlastní hostname na localhostu

Pro spuštění SeaCat Auth lokálně s vlastním hostname jednoduše přidejte hostname do `/etc/hosts` na vašem stroji, například

```
127.0.0.1  auth.test.loc
```

Protože nemůžete získat důvěryhodný SSL certifikát prostřednictvím ACME challenge pro interní hostname, 
musíte vygenerovat **self-signed SSL certifikát**:

```sh
openssl req -x509 -newkey rsa:4096 -keyout nginx-conf/key.pem -out nginx-conf/cert.pem -days 365 -nodes
```

*Poznámka, že **self-signed certifikáty nejsou důvěryhodné** a na většině zařízení vyvolávají varování.*
*Měly by být používány pouze pro vývojové účely v místních prostředích.*

### Režim provisioning

Dále pokračujte k [režimu provisioning](./provisioning.md).