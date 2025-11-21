# bi_pii_tokenizer

A small Go service to tokenize and detokenize Personally Identifiable Information (PII) such as PAN and AADHAR, using AES-GCM encryption and optional Redis cache.

## Features

- Tokenize PII values (PAN, AADHAR) into FPT tokens
- Detokenize FPT back to original PII (requires AES key)
- Optional Redis cache for fast lookups
- Clear JSON API with structured error responses

## Requirements

- Go
- PostgreSQL (or the DB configured in models.Store)
- Optional: Redis cluster for cache

## Environment Variables

- `AES_KEY_BASE64 - base64-encoded AES key used for AES-GCM encryption/decryption (required)`
- `HMAC_KEY_BASE64 - base64-encoded HMAC key used for blind indexes / signing (required)`
- `REDIS_* - Redis cluster configuration used by cache (optional); see NewCacheFromEnv() for details`
- `PORT - server port (optional, default 8081)`
## Build & Run

```bash
# extract and build
go build ./...
# set required env vars
export DATABASE_URL=""
export AES_KEY_BASE64="<base64 aes key>"
export HMAC_KEY_BASE64="<base64 hmac key>"
# optional redis envs for cache
export PORT=8081
# run
./bi_pii_tokenizer
```

## HTTP API

All endpoints accept and respond with JSON. Errors are returned with the structure:

```json
{ "error": "description" }
```

### POST /tokenize

Request:
```json
{ "pii_type": "PAN|AADHAR", "pii_value": "<value>" }
```

Success response (200):
```json
{ "fpt": "<token>" }
```

Error examples:

- 400 `{"error":"pii_type and pii_value are required"}`
- 400 `{"error":"invalid PAN format"}`
- 500 `{"error":"internal error"}`

### POST /detokenize

Request:
```json
{ "fpt": "<token>" }
```

Success response (200):
```json
{ "pii_value": "<original value>" }
```

Error examples:

- 400 `{"error":"invalid body"}`
- 400 `{"error":"fpt required"}`
- 404 `{"error":"token not found"}`
- 500 `{"error":"internal error"}`

### GET /health

Returns JSON status (e.g., `{"status":"ok","cache":true}`)

## Logging

- The service logs warnings when cache initialization or preload fails and logs errors on handler failures.

## Testing / QA use-cases

Below are curl commands to validate error handling and success flows:

1. Missing fields
```bash
curl -i -X POST http://localhost:8081/tokenize -H "Content-Type: application/json" -d '{}'
```

2. Invalid PAN
```bash
curl -i -X POST http://localhost:8081/tokenize -H "Content-Type: application/json" -d '{"pii_type":"PAN","pii_value":"INVALID"}'
```

3. Empty FPT
```bash
curl -i -X POST http://localhost:8081/detokenize -H "Content-Type: application/json" -d '{"fpt":""}'
```

4. Token not found
```bash
curl -i -X POST http://localhost:8081/detokenize -H "Content-Type: application/json" -d '{"fpt":"nonexistent-token"}'
```

5. Health check
```bash
curl -i http://localhost:8081/health
```

6. Redis
```bash
redis-cli -h remote-ip -p 6379 ping
redis-cli -h remote-ip -p 6379 dbsize
```
