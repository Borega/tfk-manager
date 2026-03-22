# Reverse Proxy Hardening for Delegated Operations

This guide covers secure internet-facing deployment for the TFK server when using delegated proxy operations (`/api/proxy/execute`).

## Threat model and trust boundary

- Desktop clients authenticate with JWT (`Authorization: Bearer ...`).
- Delegated operations also require request signing (`X-Proxy-Signature`) using `TFK_PROXY_HMAC_SHARED_SECRET`.
- The reverse proxy is the only internet-exposed component.
- The TFK server should be reachable only from trusted internal networks / proxy host IPs.

## Required server environment

Set these on the server container:

```env
TFK_PROXY_HMAC_SHARED_SECRET=replace-with-long-random-secret
TFK_PROXY_REQUEST_AUDIENCE=tfk-manager-server
TFK_PROXY_MAX_SKEW_SECONDS=120
TFK_PROXY_NONCE_TTL_SECONDS=300
```

Recommended:

```env
TFK_SERVER_ALLOWED_PROXY_IPS=127.0.0.1/32,10.0.0.0/24
```

## Baseline hardened NGINX profile

Use this profile when you terminate TLS at NGINX and forward plain HTTP to the internal TFK server.

```nginx
# Rate-limit bucket for API calls
limit_req_zone $binary_remote_addr zone=tfk_api_rate:10m rate=10r/s;

server {
    listen 443 ssl http2;
    server_name tfk.example.com;

    ssl_certificate /etc/letsencrypt/live/tfk.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tfk.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    client_max_body_size 1m;

    location /api/ {
        limit_req zone=tfk_api_rate burst=20 nodelay;

        proxy_pass http://tfk-manager-server:8080;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;

        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 120s;

        proxy_request_buffering on;
        proxy_buffering off;
    }

    location /health {
        proxy_pass http://tfk-manager-server:8080/health;
        allow 127.0.0.1;
        deny all;
    }
}
```

## High-security mTLS profile

Use this profile for environments where desktop clients have managed certificates.

```nginx
limit_req_zone $binary_remote_addr zone=tfk_api_rate:10m rate=8r/s;

server {
    listen 443 ssl http2;
    server_name tfk.example.com;

    ssl_certificate /etc/letsencrypt/live/tfk.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tfk.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    ssl_client_certificate /etc/nginx/ca/client-ca.pem;
    ssl_verify_client on;
    ssl_verify_depth 2;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    client_max_body_size 512k;

    location /api/ {
        limit_req zone=tfk_api_rate burst=10 nodelay;

        proxy_pass http://tfk-manager-server:8080;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;

        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 120s;

        proxy_request_buffering on;
        proxy_buffering off;

        if ($request_method !~ ^(GET|POST|OPTIONS)$) {
            return 405;
        }
    }
}
```

## SSE and long-polling notes

- Keep `proxy_buffering off` for stream-like endpoints to avoid delayed event delivery.
- Use `proxy_read_timeout` high enough for firewall/webfilter long-running calls.
- Avoid global low timeouts that can terminate in-flight delegated operations.

## Rollout checklist

1. Run server only on private network (`tfk-server` not publicly exposed).
2. Place NGINX as the only public ingress.
3. Configure strong `TFK_PROXY_HMAC_SHARED_SECRET` and distribute securely to approved desktop clients.
4. Match desktop audience to `TFK_PROXY_REQUEST_AUDIENCE`.
5. Enforce TLS and optional mTLS profile.
6. Configure request rate-limits and body-size caps.
7. Monitor logs for repeated `proxy_security_validation_failed` and `forbidden` responses.
