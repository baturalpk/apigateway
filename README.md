## @baturalpk/api-gateway ⛩️

### ✈ Getting started

```
go get github.com/baturalpk/apigateway
```

See `examples/` folder for sample `config.yaml` and `main.go` files.

> 🔥 Works well with [@baturalpk/auth-service](https://github.com/baturalpk/auth-service.git) as intended to be.

### ⚙ How does it work?

1. Each request that matches with `/auth/:intent` schema, is forwarded to the auth service endpoints depending on the intents (i.e., signin, signout, signup).

2. Each request that begins with `/api/...`, is evaluated to match with predefined paths (`matchPaths[].value` property in config.yaml):
   - If matching occurs, the gateway determines whether end-user is authorized by interacting with the auth service endpoint
   - If claimed authorization is valid:

     - Binds the unique identifier `(i.e., ID)` of verified user to the predefined header (`auth.internal.idHeader` property in config.yaml). By that way, internal services can trust this header to recognize the authenticated end-user.
     - Ultimately, the request of end-user is forwarded to the target service by reverse proxy.

### 😒 Some limitations

- All auth service paths _(e.g., signupPath)_ must allow _HTTP POST_ method

- After the successful validation of an end-user session, auth service must return a JSON response with the following property:<br>

  `id`: "System-wide strictly unique identifier" of an end-user.

- All requests, which are going towards internal services, must be fully authorized. For the time being, different paths that belong to same service cannot be excluded from authorization process conditionally. _In brief, no public API endpoints yet!_
