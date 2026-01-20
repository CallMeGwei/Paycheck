# Paycheck

**Get paid for the software you build. Get back to building.**

We're in an era where you can ship real software in a weekend. But when it comes time to actually charge for it? Suddenly you're knee-deep in payment integrations, license key management, and activation flows. That's a weekend you're not building.

Paycheck is licensing infrastructure for developers who move fast. One integration to accept payments and manage licenses. Validate licenses offline—no phone-home required. Built for the honest majority who just want a convenient way to pay and prove it.

## How It Works

```
Customer pays → Webhook creates license → User activates → JWT stored locally
```

After activation, the JWT contains everything needed for offline validation: tier, features, expiration—all signed with Ed25519. Your app validates locally. No server contact needed.

## Features

- **Offline by default** — Signed JWTs validate locally, no phone-home
- **Email-based recovery** — Lost access? Request activation code via email
- **Multi-tenant** — One server, many customers, isolated keys per project
- **Payment provider agnostic** — Stripe and LemonSqueezy supported
- **Device limits** — Optional concurrent device tracking
- **Audit logging** — Every action tracked in separate immutable database

This repo includes the API server and SDKs. Build your own admin UI, or use the hosted service at [paycheck.dev](https://paycheck.dev).

## Quick Start

```bash
# Build
cargo build --release

# Configure master key (required for encryption)
openssl rand -base64 32 > master.key
chmod 400 master.key
export PAYCHECK_MASTER_KEY_FILE=./master.key

# Set bootstrap operator
export BOOTSTRAP_OPERATOR_EMAIL=you@example.com

# Run
cargo run --release
```

On first run, check the logs for your operator API key:

```
============================================
BOOTSTRAP OPERATOR CREATED
Email: you@example.com
API Key: pc_a1b2c3d4e5f6...
============================================
SAVE THIS API KEY - IT WILL NOT BE SHOWN AGAIN
============================================
```

### Dev Mode

```bash
# Seed with test data
PAYCHECK_ENV=dev cargo run -- --seed

# Delete databases on exit
PAYCHECK_ENV=dev cargo run -- --ephemeral

# Both
PAYCHECK_ENV=dev cargo run -- --seed --ephemeral
```

The `--seed` flag creates test data (operator, org, member, project, product) and prints credentials for testing.

## Architecture

```
Operators (Paycheck platform admins)
├── Organizations (your customers)
│   ├── Org Members (owner, admin, member)
│   ├── Payment Config (Stripe/LemonSqueezy keys - org level)
│   └── Projects (each software product)
│       ├── Products (pricing tiers)
│       │   ├── Payment Config (price per provider)
│       │   └── Licenses → Devices
│       └── Ed25519 key pair (auto-generated)
└── Audit Logs (immutable, separate database)
```

## SDK Usage

> **Note:** SDKs are in development and not yet production-ready. See `sdk/` for current status.

### TypeScript

```typescript
import { Paycheck } from '@paycheck/sdk';

// Initialize with project's public key
const paycheck = new Paycheck('base64-ed25519-public-key', {
  baseUrl: 'https://pay.yourapp.com',
});

// Check license (offline - verifies Ed25519 signature locally)
if (await paycheck.isLicensed()) {
  console.log('Tier:', paycheck.getTier());
  console.log('Has export?', paycheck.hasFeature('export'));
}

// Start purchase flow
const { checkoutUrl } = await paycheck.checkout('product-uuid');
window.location.href = checkoutUrl;

// Activate with code (from callback redirect)
const result = await paycheck.activateWithCode('PREFIX-XXXX-XXXX');
```

### Rust

```rust
use paycheck_sdk::{Paycheck, PaycheckOptions, DeviceType};

let paycheck = Paycheck::new("base64-public-key", PaycheckOptions {
    base_url: Some("https://pay.yourapp.com".into()),
    device_type: Some(DeviceType::Machine),
    ..Default::default()
})?;

// Offline validation
if paycheck.is_licensed() {
    println!("Tier: {:?}", paycheck.get_tier());
}

// Activate with code
let result = paycheck.activate_with_code("PREFIX-XXXX-XXXX", None).await?;
```

## Public API

All public endpoints use `public_key` to identify the project.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/buy` | Initiate payment, returns checkout URL |
| GET | `/callback` | Post-payment redirect, returns activation code |
| POST | `/redeem` | Exchange activation code for JWT |
| POST | `/activation/request-code` | Request code sent to purchase email |
| POST | `/refresh` | Refresh JWT (even if expired) |
| POST | `/validate` | Online license validation (for revocation) |
| GET | `/license` | Get license info (JWT in header, public_key in query) |
| POST | `/devices/deactivate` | Self-deactivate current device |

### Purchase Flow

```bash
# 1. Start checkout
curl -X POST https://pay.example.com/buy \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "base64-ed25519-public-key",
    "product_id": "prod_xxx",
    "provider": "stripe"
  }'
# Returns: { "checkout_url": "https://checkout.stripe.com/...", "session_id": "..." }

# 2. User completes payment, redirected to callback
# Callback returns: ?code=PREFIX-XXXX-XXXX&status=success

# 3. Activate with code
curl -X POST https://pay.example.com/redeem \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "base64-ed25519-public-key",
    "code": "PREFIX-XXXX-XXXX",
    "device_id": "uuid-here",
    "device_type": "uuid"
  }'
# Returns: { "token": "eyJ...", "tier": "pro", ... }
```

### Recovery Flow

```bash
# User lost access - request code via email
curl -X POST https://pay.example.com/activation/request-code \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "base64-ed25519-public-key",
    "email": "customer@example.com"
  }'
# Activation code sent to email (if license exists for that email)
```

## Admin API

### Operator Endpoints

Manage the platform. Requires operator API key.

| Method | Endpoint | Description |
|--------|----------|-------------|
| CRUD | `/operators` | Operator management (owner only) |
| CRUD | `/operators/users` | User management (admin+) |
| CRUD | `/operators/organizations` | Organization management (admin+) |
| GET | `/operators/audit-logs` | Query audit logs (view+) |

### Organization Endpoints

Manage products and licenses. Requires org member API key.

| Method | Endpoint | Description |
|--------|----------|-------------|
| CRUD | `/orgs/{org}/members` | Org member management |
| CRUD | `/orgs/{org}/projects` | Project management |
| CRUD | `/orgs/{org}/projects/{proj}/members` | Project member management |
| CRUD | `/orgs/{org}/projects/{proj}/products` | Product management |
| CRUD | `/orgs/{org}/projects/{proj}/products/{prod}/provider-links` | Provider link per provider |
| GET | `/orgs/{org}/projects/{proj}/licenses` | List licenses (filter by email or order ID) |
| POST | `/orgs/{org}/projects/{proj}/licenses` | Create license(s) directly |
| GET | `/orgs/{org}/projects/{proj}/licenses/{id}` | Get license with devices |
| PATCH | `/orgs/{org}/projects/{proj}/licenses/{id}` | Update license (fix email) |
| POST | `/orgs/{org}/projects/{proj}/licenses/{id}/revoke` | Revoke license |
| POST | `/orgs/{org}/projects/{proj}/licenses/{id}/send-code` | Generate activation code |
| DELETE | `/orgs/{org}/projects/{proj}/licenses/{id}/devices/{dev}` | Remote deactivate device |
| GET | `/orgs/{org}/audit-logs` | Query org's audit logs |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Bind address | `127.0.0.1` |
| `PORT` | Bind port | `4242` |
| `BASE_URL` | Public URL for callbacks | `http://{HOST}:{PORT}` |
| `DATABASE_PATH` | SQLite database | `paycheck.db` |
| `AUDIT_DATABASE_PATH` | Audit log database | `paycheck_audit.db` |
| `PAYCHECK_ENV` | Set to `dev` for dev mode | — |
| `PAYCHECK_MASTER_KEY_FILE` | Master encryption key file | Required |
| `PAYCHECK_CONSOLE_ORIGINS` | CORS origins for admin UI | `localhost:3001` (dev) |
| `PAYCHECK_RESEND_API_KEY` | System-level Resend API key | — |
| `PAYCHECK_DEFAULT_FROM_EMAIL` | Default "from" email | — |
| `RATE_LIMIT_STRICT_RPM` | Rate limit for /buy, /activation/request-code | `10` |
| `RATE_LIMIT_STANDARD_RPM` | Rate limit for most public endpoints | `30` |
| `RATE_LIMIT_RELAXED_RPM` | Rate limit for /health | `60` |
| `RATE_LIMIT_ORG_OPS_RPM` | Rate limit for /orgs/* endpoints | `3000` |
| `MIGRATION_BACKUP_COUNT` | DB backups to keep (-1 = all, 0 = none) | `3` |

### Payment Setup

**Stripe** (org-level config):
```json
PUT /operators/organizations/{id}
{
  "stripe_secret_key": "sk_live_...",
  "stripe_webhook_secret": "whsec_..."
}
```

**LemonSqueezy** (org-level config):
```json
PUT /operators/organizations/{id}
{
  "ls_api_key": "...",
  "ls_store_id": "...",
  "ls_webhook_secret": "..."
}
```

**Product provider links** (per product, per provider):
```json
POST /orgs/{org}/projects/{proj}/products/{prod}/provider-links
{
  "provider": "stripe",
  "linked_id": "price_1ABC..."
}
```

Note: `linked_id` is the provider's price/variant ID (Stripe Price ID or LemonSqueezy Variant ID).
Product pricing (`price_cents`, `currency`) is stored on the Product for display purposes.

### Database Migrations

Migrations run automatically on server startup:

1. **Version check**: Compares `PRAGMA user_version` against latest migration
2. **Backup**: Creates `paycheck.db.backup_v{N}_{timestamp}` before any changes
3. **Apply**: Runs pending migrations in transactions (rollback on failure)
4. **Cleanup**: Removes old backups based on `MIGRATION_BACKUP_COUNT`

```bash
# Keep 3 backups (default)
MIGRATION_BACKUP_COUNT=3

# Keep all backups
MIGRATION_BACKUP_COUNT=-1

# Disable backups (not recommended for production)
MIGRATION_BACKUP_COUNT=0
```

**Manual version check:**
```bash
sqlite3 paycheck.db "PRAGMA user_version"
```

**Recovery:** If migration fails, the transaction rolls back and the server exits with an error message pointing to the backup file.

## JWT Structure

```json
{
  "iss": "paycheck",
  "sub": "license-uuid",
  "aud": "project-uuid",
  "jti": "device-token-uuid",
  "iat": 1703302025,
  "exp": 1703305625,

  "license_exp": null,
  "updates_exp": 1766448000,
  "tier": "pro",
  "features": ["export", "api"],
  "device_id": "uuid-or-machine-id",
  "device_type": "uuid",
  "product_id": "product-uuid"
}
```

### Understanding Expiration Times

Paycheck JWTs have **three expiration-related claims** that serve different purposes:

| Claim | Typical Value | Purpose | Check When |
|-------|---------------|---------|------------|
| `exp` | ~1 hour | Token freshness | Auto-refresh trigger |
| `license_exp` | null or future date | License validity | "Is user licensed?" |
| `updates_exp` | null or future date | Version access | "Can user use this version?" |

**`exp` — JWT Expiration (~1 hour)**

The standard JWT `exp` controls token freshness, not license validity. It exists for:
- **Revocation propagation**: If a license is revoked, the JWT remains locally valid until `exp`. Shorter = faster revocation.
- **Claims freshness**: Periodic refresh picks up plan upgrades, feature changes, renewed subscriptions.

**Key point:** Expired JWTs can still be refreshed via `/refresh` as long as the underlying license is valid.

**`license_exp` — License Expiration (business logic)**

This is the actual license expiration. Check this for "is the user licensed?"
- `null` = perpetual license (one-time purchases)
- Future timestamp = subscription end date or time-limited license

**`updates_exp` — Version Access**

Controls which versions the user can access. Compare against your app's build timestamp.
- `null` = lifetime updates
- Future timestamp = updates until that date

See [`sdk/CORE.md`](sdk/CORE.md) for detailed SDK documentation.

## Security Model

- **Activation codes, not license keys in URLs** — Codes expire in 30 minutes
- **Email hash storage** — No PII, just SHA-256 hash for recovery lookup
- **Self-deactivation requires JWT** — Prevents griefing with leaked license key
- **Per-project key isolation** — Compromise of one project doesn't affect others
- **Envelope encryption** — Private keys and payment credentials encrypted at rest

## Philosophy

1. **Offline-first** — Customers shouldn't need internet to use software they paid for
2. **Honest majority** — Design for the 95% who just want to pay
3. **No security theater** — Unencrypted JWT in localStorage is fine
4. **Simple to start** — One JWT, local validation, done
5. **Powerful to scale** — Online checks and device limits when you need them

## License

[Elastic License 2.0](LICENSE)
