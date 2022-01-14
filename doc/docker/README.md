# Deploying Seacat Auth in Docker environment

... using Docker Compose

1. Create a site directory in `/opt` on the target machine (or LXC container, or other site).

Recommended structure:
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

2. Copy [`docker-compose.yml`](./docker-compose.yml) from this documentation into the root of site directory: `/opt/site-[name]/docker-compose.yml`
3. Adjust the `docker-compose.yml` file to specify Docker image versions if necessary
4. Install Web UIs (TODO: download from GitLab, place in the proper folder)
5. Copy and adjust the [`seacatauth-conf/seacatauth.conf` file](./seacatauth-conf/seacatauth.conf) (example provided in the documentation directory)
5. Configure NGINX in `nginx-conf/nginx.conf`
6. Run `docker-compose up -d` in the `/opt/site-[name]` directory.
7. Optionally, setup auto-start after host system reboot

Finally, proceed to the [Seacat Auth provisioning guide](/doc/provisioning.md) for instructions on how to set up initial users, tenants etc.

(TODO - review and adjust based on the practical exercise)


## Generate self-signed certificates for NGINX

If a self-signed certificate is needed, you can generate it in the `/opt/site-[name]` directory 
by executing the following command:

```sh
openssl req -x509 -newkey rsa:4096 -keyout nginx-conf/key.pem -out nginx-conf/cert.pem -days 365 -nodes
```

Note: OpenSSL has to be installed on the host system.

