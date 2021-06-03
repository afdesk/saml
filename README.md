# SAML and Auth0 sample
## Run custom proxy
1. Add `Auth0 Id`  to `docker-compose.yml`.
2. Run docker compose:
```shell
docker-compose up --build --remove-orphans
```
3. Set up to your browser next proxy server: `127.0.0.1`, port `8080`.
4. go to `http://google.com`