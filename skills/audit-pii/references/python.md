# Python PII Review Notes

## Django Error Reports And Logging

Django's normal request handling and its exception-reporting path have
different privacy controls. Resolve settings, decorators, middleware, and the
actual reporting sink before deciding that request data is exposed.

- `DEFAULT_EXCEPTION_REPORTER_FILTER` selects the filter used to cleanse
  exception reports. The default `SafeExceptionReporterFilter` uses
  `sensitive_post_parameters` and `sensitive_variables` annotations, but those
  protections must cover the function and fields on the reachable error path.
- The default filter's POST and local-variable cleansing is active when
  `DEBUG` is false. A production deployment with `DEBUG = true`, a permissive
  custom reporter filter, or a custom exception serializer can bypass that
  expectation.
- Django's hidden-setting name matching is not a general PII scrubber. Fields
  such as email, phone, address, customer slug, or support text need explicit
  handling when they enter exception reports or application logs.
- Inspect logging `Filter` and `Formatter` classes, middleware that records
  request bodies, and exception integrations. Do not infer a leak merely from
  `logger.exception`; prove which contextual values are attached.

See https://docs.djangoproject.com/en/stable/howto/error-reporting/.

## Django REST Framework And Marshmallow

Serializer validation does not automatically minimize response data.

- For DRF `ModelSerializer`, resolve `fields`, `exclude`, `read_only_fields`,
  nested serializers, `SerializerMethodField`, and custom `to_representation`.
  `fields = "__all__"` deserves review, but report only a personal/customer
  field that reaches a broader response or export than the caller needs.
- Viewsets can select different serializers by action. Follow
  `get_serializer_class`, mixins, pagination, and renderer configuration before
  deciding which representation is returned.
- Marshmallow schemas expose declared dump fields and can add data in
  `post_dump`; `load_only` excludes a field from serialization and `dump_only`
  excludes it from input. Resolve schema inheritance and `only`/`exclude`
  arguments at the call site.
- A serializer containing an email or customer ID is not itself a finding.
  Establish the endpoint audience, authorization scope, and exact emitted
  representation.

See https://www.django-rest-framework.org/api-guide/serializers/ and
https://marshmallow.readthedocs.io/en/stable/quickstart.html.

## Sentry And Structured Logging

- Python Sentry SDK configuration may use `send_default_pii` and `before_send`.
  Resolve the installed SDK, integration defaults, event processors, and the
  final event mutation; enabling PII collection is not proof that a concrete
  personal value is sent.
- `before_send` can scrub or drop an event, but only the returned event is
  authoritative. Confirm the callback is registered in the active environment
  and handles the relevant nested field.
- `structlog`, Loguru, and stdlib logging can bind request/customer context once
  and include it in many later events. Follow processors, filters, contextvars,
  and formatter output rather than reviewing only the final log call.
- Treat test and development logging separately from production paths unless
  a committed real value is itself the exposure.
