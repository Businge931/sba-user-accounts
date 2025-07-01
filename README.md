# User Authentication Microservice

This microservice handles user authentication and account management using hexagonal architecture.

## Project Structure

```
├── cmd/
│   └── api/            # Application entry points
├── internal/
│   ├── core/          # Domain layer
│   │   ├── domain/    # Domain models and business logic
│   │   ├── ports/     # Ports (interfaces) definition
│   │   └── services/  # Application services
│   ├── adapters/      # Adapters implementation
│   │   ├── primary/   # Primary/Driving adapters (HTTP handlers, gRPC)
│   │   └── secondary/ # Secondary/Driven adapters (DB, external services)
│   └── config/        # Configuration
└── pkg/               # Public packages
```

## Features

- User registration
- User authentication (login)
- Password reset
- Email verification
- User profile management

## Technologies

- PostgreSQL
- JWT for authentication
- bcrypt for password hashing
