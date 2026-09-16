# Go PII Review Notes

## HTTP And Serialization

- `net/http` handlers often pass `*http.Request`, URL values, or decoded structs
  into middleware loggers. Trace the exact fields selected; logging a request
  method and route template is different from logging `RequestURI`, headers, or
  the body.
- `encoding/json` serializes exported fields unless tags, custom marshalers, or
  deliberate response structs narrow the shape. Follow the concrete value
  passed to `Encoder.Encode` or a framework response helper.
- Struct tags describe shape, not audience. A personal field with a JSON tag is
  not a finding unless a reachable response, export, log, or vendor sink emits
  it to an unnecessary audience.
- Error wrappers and `%+v` formatting can include embedded request or domain
  values. Resolve custom `Error`, `Format`, and marshaling methods.

## Structured Logging

- `log/slog` handlers receive attributes from the call, logger-level `With`
  bindings, groups, and values implementing `LogValuer`. Inspect handler
  replacement/filtering and whether source values are expanded before it.
- zap fields can be attached directly or through child loggers; object and
  array marshalers decide their final contents. Check cores and sampling only
  after proving the field value.
- logrus entries can retain `WithField(s)` data across later calls. Middleware
  and context helpers may bind account data once per request.
- Do not assume a key named `user`, `customer`, or `email` contains production
  data. Trace the assigned expression and deployed log destination.

## Telemetry And Monitoring

- OpenTelemetry span attributes, events, baggage, and metric labels can leave
  the process through an exporter. Inspect custom instrumentation and resource
  attributes as well as auto-instrumentation.
- Prefer route templates and low-cardinality operation names over raw URLs or
  user/customer identifiers. Confirm the actual value assigned to each
  attribute or label.
- Sentry Go scope and event processors can add user, request, tags, contexts,
  and breadcrumbs. Resolve scope lifetime and the final event processor chain.
- A scrubber in an OpenTelemetry collector or logging backend can mitigate an
  application-side emission only when repository configuration proves that
  every relevant export path passes through it.
