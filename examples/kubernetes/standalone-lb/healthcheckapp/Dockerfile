FROM cgr.dev/chainguard/go AS builder
COPY . /app
RUN cd /app && CGO_ENABLED=0 go build -o healthcheckapp .

# FROM cgr.dev/chainguard/static:latest
FROM cgr.dev/chainguard/wolfi-base
RUN apk add curl
COPY --from=builder /app/healthcheckapp /usr/bin/
CMD ["/usr/bin/healthcheckapp"]
