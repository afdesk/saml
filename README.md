# SAML and Auth0 sample
## Build
```shell
docker build -t samlauth0 .
```
## Run
```shell
docker run -it -e AUTH0_ID=<Auth0 Client ID> -p 8000:8000 --rm samlauth0:latest
```
## Usage
```
http://127.0.0.1:8000/hello
```