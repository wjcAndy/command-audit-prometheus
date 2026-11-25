FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/command-audit .

FROM scratch
COPY --from=build /out/command-audit /command-audit
