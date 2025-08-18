# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an authentication service built with Rust and Axum, featuring JWT-based authentication with optional 2FA via email. The service provides a web UI for login/signup and REST API endpoints for authentication operations.

## Tech Stack

- **Framework**: Axum web framework
- **Runtime**: Tokio async runtime  
- **Frontend**: Vanilla JavaScript with Bootstrap CSS
- **Protocol**: HTTP REST API with JSON payloads
- **Authentication**: JWT tokens with optional 2FA
- **Port**: 8001 (changed from default 3000)

## Architecture

### Core Components

- `src/lib.rs`: Main `Application` struct that encapsulates server setup and configuration
- `src/routes.rs`: Route handlers (currently contains placeholder hello handler)
- `src/main.rs`: Entry point that binds to 0.0.0.0:8001 and runs the application
- `assets/`: Static web assets served at root path
  - `index.html`: Complete auth UI with login, signup, and 2FA forms
  - `app.js`: Frontend JavaScript handling form submissions and API calls
  - `lgr_logo.png`: Let's Get Rusty logo

### Test Structure

- `tests/api/mod.rs`: Test module entry point
- `tests/api/helpers.rs`: `TestApp` struct for integration testing (incomplete with TODOs)
- `tests/api/routes.rs`: Route integration tests (basic root endpoint test exists)

## Development Commands

### Building and Running

```bash
# Run the auth service locally on port 8001
cargo run

# Build the project
cargo build

# Build for release
cargo build --release

# Check code compilation without building
cargo check
```

### Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run a specific test
cargo test test_name

# Run tests in a specific module
cargo test api::routes
```

### Docker

```bash
# Build Docker image
docker build -t auth-service .

# Run containerized service
docker run -p 8001:8001 auth-service
```

## API Schema

The service implements the API defined in `api_schema.yml` with these endpoints:

- `GET /`: Serves the authentication UI
- `POST /signup`: User registration with optional 2FA
- `POST /login`: User authentication (returns JWT or requires 2FA)
- `POST /verify-2fa`: Verify 2FA code and complete login
- `POST /logout`: User logout (invalidates JWT)
- `POST /verify-token`: Validate JWT token

## Current Development State

The codebase is in early development with basic structure in place:

- ✅ Project structure and dependencies configured
- ✅ Basic Axum application setup
- ✅ Static asset serving for auth UI
- ✅ Complete frontend UI implementation
- ✅ Docker containerization
- ✅ Basic test infrastructure setup
- ❌ Route handlers not implemented (only hello placeholder exists)
- ❌ JWT authentication logic missing
- ❌ 2FA email functionality missing
- ❌ Database integration missing
- ❌ Test helpers incomplete (contain TODOs)

## Known Issues

- Compilation errors in `src/lib.rs:32` and `src/lib.rs:38` due to mismatched types in server configuration
- Test helper `TestApp::new()` has incomplete implementation with `todo!()` macros
- Missing route implementations for all auth endpoints defined in API schema

## Code Patterns

- Uses `Result<T, Box<dyn Error>>` for error handling in main application code
- Follows Rust 2021 edition conventions
- Test utilities use `TestApp` pattern for integration testing
- Frontend uses vanilla JavaScript with fetch API for HTTP requests
- Static assets served via tower-http ServeDir middleware