# Observability PII Review Notes

## Establish The Real Export Path

Observability libraries are sinks only when data reaches an enabled exporter,
transport, appender, or hosted service. Resolve the active environment,
sampling, processors, and final destination. Do not report a dependency or an
unused initialization example by itself.

Trace all enrichment layers:

    request or domain value
      -> logger/span/error/analytics context binding
      -> processors, filters, and redaction
      -> exporter or durable local sink
      -> operator/vendor audience and retention

Context may be attached far from the eventual emission through child loggers,
MDC, request-local storage, scopes, baggage, global tags, or resource
attributes.

## Sentry

- SDKs commonly expose a `send_default_pii`/`sendDefaultPii` option, but option
  spelling and collected defaults vary by SDK and version. Use manifests and
  local initialization code to resolve behavior.
- `before_send`/`beforeSend` is a final event hook in many SDKs. Confirm it is
  registered, returns the scrubbed event, and removes the relevant value from
  nested request, user, context, extra, breadcrumb, replay, and exception data.
- Scope calls that set user or custom context can make one identifier appear on
  every later event in that scope. Check scope lifetime and cleanup.
- Data-scrubbing configuration outside the repository is not a proven
  mitigation. Repository-managed relay or server configuration is relevant
  only when the export path demonstrably uses it.

See https://docs.sentry.io/platforms/ for the installed SDK's current options.

## OpenTelemetry

- Span attributes, events, links, baggage, resource attributes, log records,
  and metric attributes can all cross the process boundary through exporters.
- OpenTelemetry semantic conventions favor low-cardinality operation and route
  values. Raw `url.full` and query data can contain sensitive information and
  need scrubbing; a route template is generally different from a raw URL.
- Attributes that may contain PII or other sensitive data should be treated as
  opt-in. Custom instrumentation does not become safe merely because it uses a
  semantic-looking key.
- Metric labels/attributes are durable dimensions in many backends. Email,
  customer ID, request ID tied to a person, raw URL, or account slug can create
  both privacy and unbounded-cardinality problems.
- Collector processors can redact or drop attributes. Confirm all relevant
  exporters pass through the processor and that its key/value matching covers
  the concrete data shape.

See https://opentelemetry.io/docs/specs/semconv/.

## Logs, URLs, And Analytics

- Structured log redaction is shape-sensitive. Verify nested paths, arrays,
  renamed fields, exception serialization, and context merged after the
  redaction stage.
- URLs can propagate into access logs, traces, browser history, referrers,
  analytics, caches, and support tooling. Prefer opaque non-personal keys and
  route templates; prove the concrete URL contains identifying data before
  reporting.
- Analytics identify/group/profile APIs are designed to receive identity data.
  Determine consent and product intent, destination, field minimization, and
  whether unnecessary personal/customer fields are sent. The API name alone
  is not evidence of a vulnerability.
