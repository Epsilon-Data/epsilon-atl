FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /atl ./cmd/atl

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /atl /usr/local/bin/atl
ENTRYPOINT ["atl"]
CMD ["serve"]
