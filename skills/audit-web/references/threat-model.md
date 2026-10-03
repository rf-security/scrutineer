# Web application and API threat model

## Reference and limits

This is original, source-review guidance informed by [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0/en), not a reproduction of the standard or an ASVS compliance assessment. Use the versioned chapter links below; applicability depends on the implemented application. Browser controls do not automatically apply to machine-to-machine clients. Source review cannot establish deployed TLS, reverse-proxy configuration, identity-provider policy, production secrets, hardware isolation or actual browser behavior without additional evidence.

## Actors and assets

Distinguish an unauthenticated remote caller, a low-privilege authenticated user, a different tenant, an attacker-controlled browser origin, an uploader and a privileged operator. Do not silently grant administrator, infrastructure or victim-session access to the attacker. Protect session identity, tenant data, user-controlled configuration, transaction integrity, upload namespaces and the origin that renders content.

Inventory each relevant boundary as an entry point, attacker-controlled value, effective guard chain and sensitive effect. Include middleware mounted on parent routers, framework defaults pinned by dependencies, reverse-proxy identity headers and background jobs started by a request. Record a component outside the scoped checkout as unavailable evidence rather than treating it as unguarded.

## Authentication and sessions

References: [V6 Authentication](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x15-V6-Authentication.md), [V7 Session Management](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x16-V7-Session-Management.md), [V9 Tokens](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x18-V9-Self-contained-Tokens.md), [V10 OAuth and OIDC](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x19-V10-OAuth-and-OIDC.md).

Trace credential or external-identity verification into session creation, rotation, expiry, revocation and recovery. Check whether session identifiers or identity claims cross from attacker-controlled input into a trusted principal without the necessary verification. For login and callback flows, establish binding to the initiating browser, intended issuer/audience and redirect destination. Separate a stolen-secret prerequisite from an attack that obtains or fixes the secret. A stateless session's documented revocation tradeoff is not automatically a vulnerability. Missing identity-provider configuration belongs in assumptions unless reachable unsafe defaults or first-party behavior prove the failure.

## Tenant and authorization boundaries

Reference: [V8 Authorization](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x17-V8-Authorization.md).

Use `audit-authz` for the detailed ownership, role and tenant audit. Here, map the principal carried by sessions and browser workflows to the resource selector and final state change. Do not assume that a route lacking a local check is unprotected: follow inherited middleware and scoped storage helpers. Do not mistake intentionally public resources or operator-authorized sharing for cross-tenant access. A browser-origin flaw remains distinct from IDOR when the victim is authorized but the attacker can induce the victim's action.

## Browser origins and API protocols

References: [V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x12-V3-Web-Frontend-Security.md), [V4 API and Web Service](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x13-V4-API-and-Web-Service.md).

For cross-site request forgery, show a sensitive effect, ambient credentials and a browser-sendable method/content type that reaches it despite effective token, Origin, Fetch Metadata or SameSite controls. Distinguish navigation from subresource requests and state-changing GET from protected POST. CORS controls response access, not whether every request can be sent; a permissive response header alone does not prove a confidential cross-origin read. Trace credential mode, allowed origin, preflight behavior and the sensitive response. Check WebSocket handshake identity and Origin validation independently of ordinary HTTP CORS. In frontend-only applications, trace actual DOM or navigation sinks but leave unknown server controls unresolved.

## Uploads and content serving

Reference: [V5 File Handling](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x14-V5-File-Handling.md).

Trace names, types, archive entries and contents from upload acceptance through normalization, storage, processing and download/rendering. Establish path containment, tenant namespace ownership, size/resource bounds and the origin and content type used when serving uploaded bytes. A permitted HTML upload is not necessarily a script-execution flaw when served as an attachment on an isolated origin. Conversely, extension filtering alone does not prove safety if the response renders attacker-controlled content in the authenticated application's origin. Record deployment-dependent execution or proxy size limits as assumptions unless the first-party path establishes them.

## Business workflows

Reference: [V2 Validation and Business Logic](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x11-V2-Validation-and-Business-Logic.md).

Trace state transitions such as approval, payment, invitation, recovery and privilege-sensitive updates. Identify server-owned prices, eligibility, authorization and ordering constraints. Check replay handling, idempotency, atomic updates and concurrency where a concrete invariant can be violated. Do not infer a race from the absence of a visible lock alone: inspect database constraints, transaction isolation and conditional writes. Distinguish an intentionally repeatable action from duplicated financial or privileged effects. Use `audit-injection` for interpreter flaws rather than duplicating its checklist.

## Evidence discipline

Every vulnerability needs a reachable first-party source-to-effect path and a concrete security consequence under stated attacker prerequisites. Record checked enforcement points as negative results, intentional semantics as design properties and unknown operational guarantees as unverified assumptions. Static review establishes a source argument, not an executed reproduction, ASVS certification or comprehensive browser/deployment testing.
