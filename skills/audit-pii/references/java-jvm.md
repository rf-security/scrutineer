# Java And JVM PII Review Notes

## Logging And Diagnostic Context

SLF4J facades inherit behavior from the selected backend and configuration.
Resolve the bound implementation, appenders, encoders, and environment files.

- Logback, Log4j2, and structured encoders can serialize arguments, markers,
  exceptions, key-value pairs, and MDC values. A harmless-looking message may
  still carry bound user or tenant context through MDC.
- Inspect servlet filters, Spring interceptors, WebFlux filters, and exception
  handlers that capture request headers, query strings, bodies, principals, or
  response objects.
- Redaction converters and turbo filters protect only the paths they actually
  process. Direct console appenders, alternate profiles, audit appenders, or
  vendor agents can bypass them.
- Thread pools and reactive execution make MDC propagation and cleanup
  significant. Stale context can misattribute data, but report only when a
  concrete personal/customer value reaches an observable sink.

## Jackson, Spring, And API Models

- Jackson serializes visible properties according to annotations, modules,
  visibility settings, views, mix-ins, and custom serializers. Resolve the
  configured `ObjectMapper`, not only annotations on the model.
- `@JsonIgnore`, access modes, DTOs, projections, and explicit response records
  can prevent exposure. Entity return types and broad bean serialization merit
  tracing but are not findings without an emitted sensitive field.
- Spring MVC `ResponseEntity`, WebFlux responses, GraphQL data fetchers, and
  exception handlers can use different mappers or advice. Follow the reachable
  route and active profile.
- Bean Validation constrains values; it does not control which fields are
  serialized.

## Monitoring

- SentryOptions and SDK integrations can collect request and user context and
  run a `beforeSend` callback. Confirm the active initialization, event
  processors, and final returned event.
- Micrometer tag values become metric dimensions and commonly reach external
  monitoring systems. Treat email, account IDs, raw URLs, and customer slugs as
  suspect high-cardinality tags, but prove the tag expression receives them.
- OpenTelemetry instrumentation and agent settings may add HTTP, database, or
  custom attributes. Inspect custom span enrichment and collector processors;
  do not infer personal data from instrumentation presence alone.
