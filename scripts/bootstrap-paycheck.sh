#!/usr/bin/env bash
#
# bootstrap-paycheck.sh
# =====================
#
# Bootstrap the Paycheck organization and project for dogfooding.
# This sets up Paycheck to use itself for its own SaaS subscriptions.
#
# Run this ONCE after initial deployment to create the Paycheck org.
#
# Prerequisites:
#   - Paycheck server running
#   - Operator account created (via BOOTSTRAP_OPERATOR_EMAIL or --seed)
#   - jq installed (for JSON parsing)
#
# What this creates:
#   1. Organization: "Paycheck" with owner admin@paycheck.dev
#   2. Project: "Paycheck" (domain: paycheck.dev, prefix: PC)
#   3. Products:
#      - Free:       perpetual, 1 device, basic features
#      - Pro:        30-day subscription, 5 devices, priority support
#      - Enterprise: annual, unlimited devices, SSO, audit logs, etc.
#
# Usage:
#   OPERATOR_API_KEY=your-key ./scripts/bootstrap-paycheck.sh
#
# Environment variables:
#   OPERATOR_API_KEY  (required) - Your operator API key
#   BASE_URL          (optional) - Paycheck server URL (default: http://localhost:3000)
#
# Example:
#   # Local development
#   OPERATOR_API_KEY=abc123 ./scripts/bootstrap-paycheck.sh
#
#   # Production
#   BASE_URL=https://api.paycheck.dev OPERATOR_API_KEY=abc123 ./scripts/bootstrap-paycheck.sh
#
# Output:
#   On success, prints the org ID, owner API key, project ID, public key,
#   and product IDs. SAVE THE OWNER API KEY - it is only shown once.
#
# Idempotency:
#   This script is NOT idempotent. Running it twice will fail (duplicate org).
#   If you need to re-run, delete the Paycheck org first via the operator API.
#

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:3000}"

if [ -z "${OPERATOR_API_KEY:-}" ]; then
    echo "Error: OPERATOR_API_KEY environment variable is required"
    echo "Usage: OPERATOR_API_KEY=your-key ./scripts/bootstrap-paycheck.sh"
    exit 1
fi

echo "Bootstrapping Paycheck org at $BASE_URL..."
echo ""

# 1. Create the Paycheck organization
echo "Creating organization..."
ORG_RESPONSE=$(curl -s -X POST "$BASE_URL/operators/organizations" \
    -H "Authorization: Bearer $OPERATOR_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Paycheck",
        "owner_email": "admin@paycheck.dev",
        "owner_name": "Paycheck Admin"
    }')

ORG_ID=$(echo "$ORG_RESPONSE" | jq -r '.organization.id')
ORG_API_KEY=$(echo "$ORG_RESPONSE" | jq -r '.owner_api_key')

if [ "$ORG_ID" = "null" ] || [ -z "$ORG_ID" ]; then
    echo "Failed to create organization:"
    echo "$ORG_RESPONSE" | jq .
    exit 1
fi

echo "  Organization ID: $ORG_ID"
echo "  Owner API Key: $ORG_API_KEY"
echo ""

# 2. Create the Paycheck project
echo "Creating project..."
PROJECT_RESPONSE=$(curl -s -X POST "$BASE_URL/orgs/$ORG_ID/projects" \
    -H "Authorization: Bearer $ORG_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Paycheck",
        "domain": "paycheck.dev",
        "license_key_prefix": "PC"
    }')

PROJECT_ID=$(echo "$PROJECT_RESPONSE" | jq -r '.id')
PUBLIC_KEY=$(echo "$PROJECT_RESPONSE" | jq -r '.public_key')

if [ "$PROJECT_ID" = "null" ] || [ -z "$PROJECT_ID" ]; then
    echo "Failed to create project:"
    echo "$PROJECT_RESPONSE" | jq .
    exit 1
fi

echo "  Project ID: $PROJECT_ID"
echo "  Public Key: $PUBLIC_KEY"
echo ""

# 3. Create products (Free, Pro, Enterprise)
echo "Creating products..."

# Free tier
FREE_RESPONSE=$(curl -s -X POST "$BASE_URL/orgs/$ORG_ID/projects/$PROJECT_ID/products" \
    -H "Authorization: Bearer $ORG_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Free",
        "tier": "free",
        "license_exp_days": null,
        "updates_exp_days": null,
        "activation_limit": 0,
        "device_limit": 1,
        "features": ["1-project", "community-support"]
    }')
FREE_ID=$(echo "$FREE_RESPONSE" | jq -r '.id')
echo "  Free tier: $FREE_ID"

# Pro tier (monthly subscription)
PRO_RESPONSE=$(curl -s -X POST "$BASE_URL/orgs/$ORG_ID/projects/$PROJECT_ID/products" \
    -H "Authorization: Bearer $ORG_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Pro",
        "tier": "pro",
        "license_exp_days": 30,
        "updates_exp_days": 30,
        "activation_limit": 0,
        "device_limit": 5,
        "features": ["unlimited-projects", "priority-support", "api-access"]
    }')
PRO_ID=$(echo "$PRO_RESPONSE" | jq -r '.id')
echo "  Pro tier: $PRO_ID"

# Enterprise tier
ENTERPRISE_RESPONSE=$(curl -s -X POST "$BASE_URL/orgs/$ORG_ID/projects/$PROJECT_ID/products" \
    -H "Authorization: Bearer $ORG_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Enterprise",
        "tier": "enterprise",
        "license_exp_days": 365,
        "updates_exp_days": 365,
        "activation_limit": 0,
        "device_limit": 0,
        "features": ["unlimited-projects", "dedicated-support", "api-access", "sso", "audit-logs", "custom-integrations"]
    }')
ENTERPRISE_ID=$(echo "$ENTERPRISE_RESPONSE" | jq -r '.id')
echo "  Enterprise tier: $ENTERPRISE_ID"

echo ""
echo "============================================"
echo "PAYCHECK BOOTSTRAP COMPLETE"
echo "============================================"
echo ""
echo "Organization:"
echo "  ID: $ORG_ID"
echo "  Owner API Key: $ORG_API_KEY"
echo ""
echo "Project:"
echo "  ID: $PROJECT_ID"
echo "  Public Key: $PUBLIC_KEY"
echo ""
echo "Products:"
echo "  Free: $FREE_ID"
echo "  Pro: $PRO_ID"
echo "  Enterprise: $ENTERPRISE_ID"
echo ""
echo "SAVE THE OWNER API KEY - IT WILL NOT BE SHOWN AGAIN"
echo "============================================"
