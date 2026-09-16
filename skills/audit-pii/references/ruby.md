# Ruby PII Review Notes

## Rails Parameters, Errors, And Logs

Rails provides filtering primitives, but the effective protection depends on
the configured keys and the path used to emit data.

- `config.filter_parameters` filters matching request parameters in Rails
  logs and affects inspected Active Record attributes. It uses partial key
  matching for symbols/strings and can also accept regular expressions or
  callables. Confirm the application list covers its personal-data field names.
- Filtering the normal parameter log does not prove that custom logs,
  exception metadata, job arguments, analytics properties, or manually
  serialized hashes are filtered. Trace the value to each concrete sink.
- `config.filter_redirect` handles logged redirect URLs separately. Review
  redirects and query strings that carry email addresses, customer IDs, or
  other identifiers.
- Development exception pages and production error reporters have different
  audiences. Resolve environment configuration and deployed middleware before
  treating a debug path as reachable.

See https://guides.rubyonrails.org/action_controller_advanced_topics.html#log-filtering.

## Active Model Serialization

- `as_json`, `serializable_hash`, Jbuilder, Blueprinter, and serializer gems
  can expose every selected attribute or a deliberate projection. Inspect the
  actual options, views, and adapter.
- ActiveModel::Serializer classes define attributes and associations, but
  inheritance, conditional attributes, and per-action serializers can change
  the output. Establish which serializer the endpoint invokes.
- Active Record scopes and authorization to the parent object do not imply
  that every personal field is appropriate for the response. Conversely, a
  model with personal columns is not exposed when the response projects a safe
  subset.

## Sentry And Structured Context

- Sentry Ruby configuration and event processing can attach user, request, and
  custom context. Inspect `send_default_pii`, `before_send`, scope enrichment,
  breadcrumbs, and any Rails integration configuration in the active
  environment.
- A `before_send` callback is a mitigation only when it returns a scrubbed
  event or `nil` for the relevant path. Check nested hashes and exception data.
- Tagged logging, request stores, and logger context can make a user or account
  identifier persist across many events. Follow where context is bound and
  cleared, especially around background jobs and thread reuse.
