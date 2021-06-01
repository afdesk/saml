FROM golang:1.16.4-alpine as builder
ADD . /samlauth0/
WORKDIR /samlauth0/
RUN go build -o ./sauth0 main.go

FROM alpine
RUN apk update && apk add wget ca-certificates openssl
EXPOSE 8000
RUN mkdir /server
COPY --from=builder /samlauth0/sauth0 /server/
WORKDIR /server

RUN openssl req -x509 -newkey rsa:4096 -nodes -batch -keyout sessionkey -out sessioncert -days 365

RUN chmod +x sauth0
RUN addgroup -g 1099 sauth0
RUN adduser -D -g '' -G sauth0 -u 1099 sauth0
RUN chown -R sauth0:sauth0 /server
USER sauth0
ENTRYPOINT ["/server/sauth0"]

