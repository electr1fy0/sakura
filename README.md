# Sakura OAuth Demo

Small OAuth provider server in Go.

## Run

```bash
go run .
```

Server listens on `http://localhost:8080` by default.

## End-to-end usage

Use repeated `scopes` query params, for example:
`...&scopes=sub&scopes=username`

1. Signup user:

```bash
curl -i -X POST "http://localhost:8080/signup" \
  -H "Content-Type: application/json" \
  -d '{"username":"human","password":"meow"}'
```

2. Register client (save `clientID` and `clientSecret` from response JSON):

```bash
curl -i -X POST "http://localhost:8080/register-client" \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-app","redirect_uris":["http://localhost:3000/callback"],"scope":["sub","username","email"]}'
```

3. Start authorize while not signed in (will redirect to signin):

```bash
curl -i "http://localhost:8080/authorize?response_type=code&client_id=<CLIENT_ID>&redirect_uri=http://localhost:3000/callback&scopes=sub&scopes=username"
```

4. Sign in and store cookie:

```bash
curl -i -c cookies.txt -X POST \
  "http://localhost:8080/signin?return_to=http://localhost:8080/authorize&response_type=code&client_id=<CLIENT_ID>&redirect_uri=http://localhost:3000/callback&scopes=sub&scopes=username" \
  -H "Content-Type: application/json" \
  -d '{"username":"human","password":"meow"}'
```

5. Call authorize again with cookie (returns `auth_request_id`):

```bash
curl -i -b cookies.txt \
  "http://localhost:8080/authorize?response_type=code&client_id=<CLIENT_ID>&redirect_uri=http://localhost:3000/callback&scopes=sub&scopes=username"
```

6. Approve selected scopes (replace `<AUTH_REQUEST_ID>`):

```bash
curl -i -X POST -b cookies.txt \
  "http://localhost:8080/authorize/approve" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "auth_request_id=<AUTH_REQUEST_ID>&scopes=sub"
```

Response is a redirect to callback with `?code=...`.

7. Exchange code for access token (replace placeholders):

```bash
curl -i "http://localhost:8080/token?client_id=<CLIENT_ID>&client_secret=<CLIENT_SECRET>&code=<AUTH_CODE>"
```

8. Access resource with bearer token:

```bash
curl -i "http://localhost:8080/resource" \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```
