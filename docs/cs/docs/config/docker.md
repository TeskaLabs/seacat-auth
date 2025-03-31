---
title: Nasazení SeaCat Auth v Docker prostředí
---

# Nasazení SeaCat Auth v Docker prostředí

... pomocí Docker Compose

1. Vytvořte adresář pro web na cílovém stroji (nebo LXC kontejneru, nebo jiném místě) v `/opt`.

Doporučená struktura:
```
/opt/site-[name]
  seacatauth-conf/
    seacatauth.conf
  nginx-conf/
    nginx.conf
  nginx-root/
    index.html
  seacat-auth-webui/
  seacat-webui/
  log/
  docker-compose.yml
```

2. Zkopírujte [`docker-compose.yml`](./docker-compose.yml) z této dokumentace do kořenového adresáře webu: `/opt/site-[name]/docker-compose.yml`
3. Upravte soubor `docker-compose.yml`, abyste v případě potřeby specifikovali verze Docker obrazů
4. Nainstalujte Web UIs (TODO: stáhnout z GitLab, umístit do správného adresáře)
5. Zkopírujte a upravte [`seacatauth-conf/seacatauth.conf` soubor](./seacatauth-conf/seacatauth.conf) (příklad je uveden v adresáři dokumentace)
5. Nakonfigurujte NGINX v `nginx-conf/nginx.conf`
6. Spusťte `docker-compose up -d` v adresáři `/opt/site-[name]`.
7. Volitelně nastavte automatické spuštění po restartu hostitelského systému

Nakonec pokračujte k [průvodci provisioningem SeaCat Auth](/doc/provisioning) pro pokyny, jak nastavit počáteční uživatele, nájemce atd.

(TODO - zkontrolovat a upravit na základě praktického cvičení)


## Vytvoření self-signed certifikátů pro NGINX

Pokud je potřeba self-signed certifikát, můžete jej vygenerovat v adresáři `/opt/site-[name]` 
vykonáním následujícího příkazu:

```sh
openssl req -x509 -newkey rsa:4096 -keyout nginx-conf/key.pem -out nginx-conf/cert.pem -days 365 -nodes
```

Poznámka: OpenSSL musí být nainstalován na hostitelském systému.