# Security Policy — CyberGuard

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ Yes     |
| 1.x     | ❌ No      |

## Reporting a Vulnerability

**Please do NOT file a public GitHub issue for security vulnerabilities.**

To report a security issue, email **security@cyberguard.io** with:
1. A description of the vulnerability and its potential impact
2. Steps to reproduce (proof-of-concept code, if applicable)
3. Affected versions and components
4. Your suggested fix (optional)

We will acknowledge your report within **48 hours** and aim to release a patch within **14 days** for critical issues.

## Scope

In-scope for this policy:
- Authentication bypass and privilege escalation
- SQL injection / NoSQL injection
- Cross-site scripting (XSS) and CSRF
- Insecure direct object references (IDOR)
- Sensitive data exposure via API endpoints
- Remote code execution (RCE)
- Rate limit bypass on the login endpoint

Out-of-scope:
- Social engineering attacks on our team
- Physical security
- Third-party services (Stripe, Slack, etc.)
- Issues in dependencies that are already publicly disclosed

## Security Hardening

CyberGuard applies the following defences by default:

| Control | Implementation |
|---|---|
| Authentication | JWT (HS256) with short-lived access tokens + revocable refresh tokens |
| Password hashing | PBKDF2-SHA256 via werkzeug (600,000 rounds) |
| Rate limiting | 5 requests/min on login, 60 req/min on telemetry ingest |
| Security headers | X-Content-Type-Options, X-Frame-Options, HSTS (production), X-XSS-Protection |
| CORS | Configurable via ALLOWED_ORIGINS env var; blocked by default in production |
| Input validation | Pydantic models with max_length constraints on all API inputs |
| SQL injection | SQLAlchemy ORM with parameterised queries (no raw SQL) |
| API docs | Disabled in production (DEBUG=false) |

## Disclosure Policy

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). After a fix is released, we aim to publish a public advisory within 30 days.
