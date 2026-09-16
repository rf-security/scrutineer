# PHP PII Review Notes

## Framework Logging And Exceptions

- Laravel middleware, exception handlers, Telescope, debug tooling, and custom
  Monolog processors may capture request, user, session, job, or model data.
  Resolve environment gates and the active logging channel stack.
- Symfony request listeners, error controllers, profiler configuration, and
  Monolog processors/formatters can enrich records before handlers persist
  them. Follow channel routing and excluded routes.
- PSR-3 context values are not necessarily rendered the same way by every
  handler. Inspect normalization and structured JSON output before deciding a
  nested object is emitted.
- Production debug settings matter, but a development-only exception page is
  not reachable evidence unless deployment configuration enables it.

## Serialization And API Resources

- Laravel API Resources, `JsonSerializable`, model `toArray`, `$hidden`,
  `$visible`, appended attributes, and relationship loading determine response
  shape. Inspect the actual resource returned by the route.
- Symfony Serializer metadata, groups, ignored attributes, callbacks, and a
  custom `NormalizerInterface` can narrow or expand output. Resolve the
  normalization context passed at the call site.
- Validation and request DTOs constrain input; they do not prove response
  minimization.
- A broad model contains PII by design. Report only a concrete response or
  export that gives fields to an audience that does not need them.

## Monitoring

- Sentry PHP integrations can attach request, user, and custom context. Inspect
  SDK options, scope configuration, event processors, and `before_send`.
- A `before_send` callback is effective only for the event returned on the
  active initialization path. Check nested extras, contexts, breadcrumbs, and
  exception data.
- Monolog processors can bind customer context once and affect many later log
  calls. Confirm both processor order and handler destination.
- Analytics and telemetry clients frequently accept arbitrary arrays. Trace
  the populated properties rather than reporting the client package itself.
