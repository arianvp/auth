

# Idempotent tokens

The following function should be deterministic:
```
generate: (code, code_verifier) -> token
```

## Resource Servers

Resource Servers register themselves with the Authorization Server using the client_credentials flow.

They can then call /introspect to figure out if a token is still valid.


`urn:ietf:params:oauth:grant-type:webauthn-assertion`

* `client_assertion`:  AppAttest
* `assertion`: First party scenario, an actual user sending a webauthn assertion!


Client authenticating on behalf of itself:
```
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:webauthn
client_assertion=<AppAttest payload>
grant_type=client_credentials
```

Client authenticating on behalf of a user, using a user agent:
```
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:webauthn
client_assertion=<AppAttest payload>
grant_type=authorization_code
code=<code>
code_verifier=<code_verifier>
```

Client authentication on behalf of a user, using the user's webauthn assertion (e.g. native client):
```
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:webauthn
client_assertion=<Webauthn payload>
grant_type=urn:ietf:params:oauth:grant-type:webauthn
assertion=<Webauthn Payload>
```
