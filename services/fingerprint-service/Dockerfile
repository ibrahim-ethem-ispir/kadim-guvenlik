# Kadim Güvenlik — fingerprint-service (wappalyzergo)
# Çok aşamalı: derleme aşamasında bağımlılık `go get` ile çözülür → bakım = `go get -u`.
FROM golang:1.25-alpine AS build
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod ./
COPY main.go ./
# Bağımlılığı derleme anında çöz (imza setini güncellemek için tek satır: go get -u).
RUN go get github.com/projectdiscovery/wappalyzergo@latest \
    && go mod tidy \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /fingerprint-service .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 kadim
USER kadim
COPY --from=build /fingerprint-service /usr/local/bin/fingerprint-service
EXPOSE 8013
ENTRYPOINT ["/usr/local/bin/fingerprint-service"]
