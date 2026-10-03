# Account service

The service in `services/site` maintains account contact settings. Start it with `python services/site/server.py`. Sign in through `POST /login` with form fields `username` and `password`, then use the account API. The sample account is `demo` with password `demo-password`. `GET /api/account` returns the current account and a form token. `GET /api/email` updates the contact email, and `POST /api/display-name` updates the display name.

`tools/client` is a standalone reporting client, not a server. It can be distributed separately from the service.
