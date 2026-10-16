# Architecture

## Current shape

```text
Vite + React starter
       |
       | no implemented integration
       v
Spring Boot API scaffold
  |-- authentication and JWT-oriented classes
  |-- user and role persistence scaffolding
  +-- PostgreSQL runtime dependency / H2 test dependency
```

The backend has a Spring Security-oriented authentication skeleton, user/role classes, OpenAPI configuration, and basic controller/test files. The frontend currently contains the default Vite/React application shell. There is no implemented investigation-domain connection between the two layers.

## Configuration boundary

The repository includes application configuration and security-related classes that must be reviewed before any revival. This documentation does not reproduce sensitive configuration values or alter runtime behavior.
