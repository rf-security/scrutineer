# Node.js PII Review Notes

## Request And Error Logging

Node applications often attach request data in middleware before a handler is
reached. Resolve registration order and the effective logger configuration.

- Express, Fastify, NestJS, and Next.js middleware can log URL query strings,
  headers, bodies, authenticated principals, and error objects. Identify the
  concrete serializer or formatter and whether the route runs through it.
- Pino serializers and `redact` paths operate on the object shape supplied to
  the logger. Confirm path syntax, wildcard coverage, censor/remove behavior,
  and child-logger bindings. A field renamed or nested after redaction can
  escape the intended rule.
- Winston formats can merge metadata, errors, and default metadata. Follow the
  entire format pipeline, including custom transforms and transports, before
  deciding what is persisted.
- AsyncLocalStorage, request-context packages, and child loggers can bind user
  or tenant data far from the eventual log statement. Search bindings as well
  as calls such as `info`, `error`, and `fatal`.

## Serialization And API Responses

- Plain `res.json(object)` and JSON serialization include enumerable
  properties unless application code projects them first. ORM model behavior
  varies; inspect `toJSON`, selected columns, scopes, DTO mapping, and hidden
  field configuration.
- NestJS `ClassSerializerInterceptor`, class-transformer decorators, and custom
  interceptors matter only when active on the route. Resolve global,
  controller, and handler registration.
- GraphQL returns selected schema fields, but a field resolver can still expose
  another principal's data. Prove both the field value and the caller audience;
  schema presence alone is not a leak.
- Validation libraries constrain input and do not minimize output unless the
  same schema is explicitly used for serialization.

## Monitoring And Analytics

- Sentry JavaScript SDKs expose options such as `sendDefaultPii` and hooks such
  as `beforeSend`. Check the installed SDK version, integration list, scope
  enrichment, and final hook output.
- `setUser`, `setContext`, `setExtra`, breadcrumbs, replay, and custom event
  processors can add personal data even when the captured exception is clean.
- Analytics clients frequently accept arbitrary property maps. Trace the
  concrete event properties and destination; a call to `track` alone is not a
  finding.
- URL telemetry should prefer route templates over raw URLs. Confirm whether
  query strings, userinfo, customer slugs, or record IDs survive normalization
  before reporting.
