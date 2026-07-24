# SIMRS

Hospital/clinic information system — modular monolith for independent practice (MVP stage 1).

## Stack

- Java 25 + Spring Boot 4.1.0
- Spring Modulith 2.0.0 (modular monolith, modules communicate via public API / application events)
- PostgreSQL
- Gradle

## Architecture

Modular monolith, layered per module:

- Controller — HTTP request handling
- Service — business logic
- Repository — data access only

Modules communicate only through public APIs or Spring application events, never direct cross-module access.

## Running

```bash
./gradlew build
./gradlew test
./gradlew bootRun
```

## Security Note

NIK and medical record data are sensitive. Ensure HTTPS and database encryption from the start (Indonesia's UU PDP applies even at MVP scale).
