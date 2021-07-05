# SAML and Auth0 sample
## Set up Auth0
Add to `Addon: SAML2 Web App` next `Application Callback URL`:
```
http://auth.aquasec.com/saml/acs
```
## Set up domain names
Add domains to `/etc/hosts`:
```
127.0.0.1 nginx.aquasec.com
127.0.0.1 auth.aquasec.com
```
## Run custom proxy
1. Add `Auth0 Id`  to `docker-compose.yml`.
2. Run docker compose:
```shell
docker-compose up --build --remove-orphans
```
## Test
go to [http://nginx.aquasec.com](http://nginx.aquasec.com/)
