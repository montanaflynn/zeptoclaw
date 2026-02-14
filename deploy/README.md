# Deployment Guide

Pre-built templates for deploying ZeptoClaw to various platforms.

## Prerequisites

- Docker installed (for building the image)
- A Telegram bot token (from @BotFather) or other channel credentials
- An LLM provider API key (Anthropic or OpenAI)

## Quick Start (Any VPS)

The simplest deployment — a single Docker container on any VPS.

```bash
# 1. Clone and build
git clone https://github.com/qhkm/zeptoclaw.git
cd zeptoclaw
docker build -t zeptoclaw .

# 2. Configure
cp deploy/.env.example .env
nano .env  # Set your API keys and bot token

# 3. Run
docker compose -f deploy/docker-compose.single.yml up -d

# 4. Check logs
docker compose -f deploy/docker-compose.single.yml logs -f

# 5. Stop
docker compose -f deploy/docker-compose.single.yml down
```

Resources: ~6MB RAM, ~4MB disk for binary.

## Platforms

### Docker Compose (Single Tenant)

**File:** `docker-compose.single.yml`

Best for: Personal VPS, single-agent deployments.

```bash
cp deploy/.env.example .env
nano .env
docker compose -f deploy/docker-compose.single.yml up -d
```

### Docker Compose (Multi-Tenant)

**File:** `docker-compose.multi.yml`

Best for: Running multiple tenants on one VPS with shared infrastructure.

```bash
cp deploy/.env.example .env
nano .env
docker compose -f deploy/docker-compose.multi.yml up -d
```

### Fly.io

**File:** `fly.toml`

Best for: Zero-ops deployment with auto-scaling. Free tier available.

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Deploy
cd deploy
fly auth login
fly launch --no-deploy --dockerfile ../Dockerfile

# Set secrets
fly secrets set ZEPTOCLAW_PROVIDERS_ANTHROPIC_API_KEY=sk-ant-...
fly secrets set ZEPTOCLAW_CHANNELS_TELEGRAM_BOT_TOKEN=...

# Deploy
fly deploy --dockerfile ../Dockerfile
```

Default region: Singapore (`sin`). Edit `primary_region` in `fly.toml` to change.

### Railway

**File:** `railway.json`

Best for: One-click deploy from GitHub.

1. Push your repo to GitHub
2. Go to [railway.com/new](https://railway.com/new)
3. Select your repository
4. Set environment variables in the dashboard:
   - `ZEPTOCLAW_PROVIDERS_ANTHROPIC_API_KEY`
   - `ZEPTOCLAW_CHANNELS_TELEGRAM_BOT_TOKEN`
5. Deploy

### Render

**File:** `render.yaml`

Best for: Auto-deploy on push with managed infrastructure.

1. Push your repo to GitHub
2. Go to [dashboard.render.com](https://dashboard.render.com)
3. New > Web Service > Connect your repo
4. Set root directory to project root
5. Set environment variables in dashboard
6. Deploy

## Environment Variables

See `.env.example` for all available variables. Key ones:

| Variable | Required | Description |
|---|---|---|
| `ZEPTOCLAW_PROVIDERS_ANTHROPIC_API_KEY` | Yes* | Anthropic API key |
| `ZEPTOCLAW_PROVIDERS_OPENAI_API_KEY` | Yes* | OpenAI API key |
| `ZEPTOCLAW_CHANNELS_TELEGRAM_BOT_TOKEN` | For Telegram | Telegram bot token |
| `ZEPTOCLAW_CHANNELS_SLACK_BOT_TOKEN` | For Slack | Slack bot token |
| `ZEPTOCLAW_CHANNELS_DISCORD_BOT_TOKEN` | For Discord | Discord bot token |
| `RUST_LOG` | No | Log level (default: `zeptoclaw=info`) |

*At least one LLM provider API key is required.

## Health Checks

All templates include health check configuration pointing to `/healthz` on port 9090.

```bash
# Manual check
curl http://localhost:9090/healthz
```

## Persistent Data

All templates mount a `/data` volume for session persistence and memory storage. Data survives container restarts and redeployments.

## Updating

```bash
# Pull latest code
git pull

# Rebuild and restart
docker build -t zeptoclaw .
docker compose -f deploy/docker-compose.single.yml up -d
```

On Fly.io: `fly deploy --dockerfile ../Dockerfile`
On Railway/Render: Push to GitHub — auto-deploys on push.
