# Telegram MiniApp InitData Validator Middleware

**Telegram MiniApp InitData Validator** is a middleware plugin for [Traefik](https://github.com/traefik/traefik) that validates Telegram MiniApp user InitData payloads and injects the decoded payload as a header to the request. This is particularly useful for applications that need to verify the integrity of requests originating from Telegram.

The middleware checks if the `InitData` (user authentication data) is provided in the specified authorization header. If present, it validates the payload by calculating an HMAC using the Telegram bot token. If the validation passes, the decoded payload is injected as a header into the request.

If you want to verify that a request is authenticated by Telegram, look for the `authHeader` in your request. Upon successful validation, the payload is available in the header specified by `proxyHeaderName`.

> This plugin is inspired by [jwt-middleware](https://github.com/23deg/jwt-middleware).


## Configuration

Start with command
```yaml
command:
  - "--experimental.plugins.traefik-telegram-initdata-introspector.modulename=github.com/savyjs/traefik-telegram-initdata-introspector"
  - "--experimental.plugins.traefik-telegram-initdata-introspector.version=v0.0.15"
```

Activate plugin in your config  

```yaml
http:
  middlewares:
    my-telegram-middleware:
      plugin:
        traefik-telegram-initdata-introspector:
          proxyHeaderName: injectedPayload
          authHeader: Telegram
          optional: true
          botToken: <BOT_TOKEN>
```

- **proxyHeaderName**: The header name where the validated Telegram InitData payload will be injected after validation. Default: `injectedPayload`.
- **authHeader**: Specifies the incoming header name that contains the InitData payload, typically customized for Telegram.
- **optional**: When set to `true`, InitData validation is optional, allowing requests without the authorization header to proceed.
- **botToken**: The Telegram bot token used to generate a secret key for authenticating the InitData payload.


Use as docker-compose label  
```yaml
  labels:
        - "traefik.http.routers.my-service.middlewares=my-telegram-middleware@file"
```



### Schema of `injectedPayload`

The `injectedPayload` is a JSON string containing user information and other metadata extracted from the Telegram InitData. Below is an example schema and a sample of the stringified payload:

#### Example Schema

```json
{
  "user": {
    "id": 139999999999,
    "first_name": "Ehsan",
    "last_name": "Afshari",
    "username": "savvyversa",
    "language_code": "en",
    "allows_write_to_pm": true
  },
  "chat_instance": "-5555555555555",
  "chat_type": "sender",
  "auth_date": 1730408115
}
```

Example of Stringified injectedPayload
```json
"{\"user\":{\"id\":139999999999,\"first_name\":\"Ehsan\",\"last_name\":\"Afshari\",\"username\":\"savvyversa\",\"language_code\":\"en\",\"allows_write_to_pm\":true},\"chat_instance\":\"-5555555555555\",\"chat_type\":\"sender\",\"auth_date\":1730408115}"
```