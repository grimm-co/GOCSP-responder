
FROM golang:1.16
WORKDIR /app
COPY . .
WORKDIR /app/cmd
ENV GOSUMDB=off
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o gocsp main.go

FROM alpine:3.14
COPY --from=0 /app/cmd/gocsp /
CMD ["/gocsp"]