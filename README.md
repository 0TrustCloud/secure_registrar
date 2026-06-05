# Secure Registrar Engine

The `secure_registrar` package provides a robust governance and administrative layer for domain management within the `0TrustCloud` ecosystem. It implements a zero-trust architecture where ownership of namespaces (TLDs, root domains, and subdomains) is cryptographically verified and enforced via a centralized registry engine.

## Core Features

* **Hierarchical Ownership:** Enforces strict parent-child relationships. Subdomain registration is only permitted if the caller proves ownership of the parent domain.
* **Cryptographic Identity:** Every state-changing operation (domain registration, DNS updates, UI configuration) requires an `X-Identity-Public-Key` header, ensuring only authorized owners can modify their respective namespaces.
* **Transactional Integrity:** Utilizes `ultimate_db` transactional handles to ensure atomic state changes and avoid race conditions.
* **Dynamic UI Customization:** Allows domain owners to persist custom branding (colors, logos, form actions) associated with their domain, which can be retrieved for portal bootstrap loading.
* **TLD Governance:** Prevents namespace collisions and enforces normalized domain formatting through standardized registration boundaries.

## Architecture

The system operates as an engine sitting between an external identity provider and the core database:

## Usage

### Engine Initialization

The engine requires an existing `ultimate_db.DB` instance and a `secure_dns.SecureDNS` service to function.

```go
engine := secure_registrar.NewRegistrarEngine(dbInstance, dnsService)

```

### Routing

The package exports a helper to mount standard HTTP routes to your web framework:

```go
// Assuming 'module' implements the RouteModule interface
secure_registrar.MountRegistrarRoutes(module, engine)

```

### Identity-Based Operations

All secure endpoints expect the owner's public key in the request header. Here is an example of updating a domain's UI configuration:

```go
// POST /registry/ui/layout
// Header: X-Identity-Public-Key: <your-public-key>
// Body: { "brand_name": "My Company", "primary_color": "#000000", ... }

```

## Data Schema

The system relies on JSON-serialized metadata for governance:

* **`DomainMetadata`**: Tracks the ownership, hierarchy, and registration timestamp for any given domain.
* **`UIConfig`**: Stores dynamic branding information, including custom UI fields and button behaviors.

## Testing

The package includes an extensive test suite in `engine_test.go` that utilizes a mock database to simulate various scenarios, including:

* **Boundaries:** Validation of TLD normalization and dot-character restrictions.
* **Hierarchy:** Verification that root domains cannot be registered without a pre-configured parent TLD.
* **Security:** Assertion that unauthorized keys cannot branch subdomains or modify configurations of domains they do not own.

To run the tests:

```bash
go test -v ./secure_registrar/...

```

## License

This project is licensed under the MIT License.
