# Use the official builder image for Golang
FROM golang:1.23.4-alpine3.20 AS builder

# Set working directory
WORKDIR /app

# Copy your Go source code
COPY . .

# Build the Go binary (replace "your-binary-name" with your actual binary name)
RUN go build -o app .

# Use the official slim image for Alpine Linux as the final stage
FROM alpine:3.20

# Copy the binary from the builder stage
COPY --from=builder /app /app

WORKDIR /app

EXPOSE 9700
# Set the entrypoint to run your binary
CMD ./app
