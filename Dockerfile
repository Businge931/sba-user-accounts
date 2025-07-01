FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install git for private repositories and troubleshooting
RUN apk add --no-cache git

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./

# Set environment variables for module support and show verbose output for debugging
ENV GO111MODULE=on
ENV GOPROXY=https://proxy.golang.org,direct

# Download modules with verbose output to help debug any issues
RUN go mod download -x

# Copy the rest of the code
COPY . .

# Build the application with clear error output
RUN CGO_ENABLED=0 GOOS=linux go build -v -o /user-accounts ./cmd/api/main.go

# Use a minimal alpine image for the final stage
FROM alpine:3.17

WORKDIR /app

# Install CA certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Copy the binary from the builder stage
COPY --from=builder /user-accounts .

# Expose the port the service runs on
EXPOSE 50051

# Run the service
CMD ["./user-accounts"]
