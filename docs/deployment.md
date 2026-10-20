# SecScan AI Deployment Guide

This guide details the production deployment architecture, configuration, containerization, and hosting options for **SecScan AI**.

---

## 1. Architecture & Hosting Requirements

### Why Frontend-Only Hosting is Insufficient
SecScan AI is an agentic security engineering system, not a static single-page app:
- **Rust Static & Taint Engine:** The authoritative vulnerability detection engine runs compiled Rust AST Tree-Sitter parsers.
- **Server-Side AI Inference:** Nebius Token Factory inference requests must occur server-side to protect `NEBIUS_API_KEY` from client exposure.
- **Context Sanitization & Secret Redaction:** Code sent to Nemotron is pre-filtered and sanitized server-side before leaving the boundary.
- **Verification Sandbox:** The autonomous verification loop requires a host runtime with Python 3 to execute test suites and verify patch diffs in an ephemeral workspace.

### Unified Binary Model
`secscan-server` embeds the web interface and serves both static assets and API routes (`/api/scan`, `/api/explain`, `/api/patch`, `/api/verify`, `/api/health`) on port `3000`. Deploying `secscan-server` deploys both the frontend and backend together.

---

## 2. Environment Variables

Configure these variables via your cloud provider's secret management or a `.env` file in the root directory:

| Variable | Required | Default | Description |
|---|---|---|---|
| `NEBIUS_API_KEY` | Recommended | *(Offline Mode)* | Bearer token for Nebius Token Factory. Kept strictly server-side. |
| `NEBIUS_BASE_URL` | No | `https://api.tokenfactory.nebius.ai/v1` | OpenAI-compatible endpoint for Nebius. |
| `NEBIUS_MODEL` | No | `nvidia/llama-3.1-nemotron-70b-instruct` | NVIDIA Nemotron model ID hosted on Nebius. |
| `PORT` | No | `3000` | Port for the Axum HTTP server. |
| `RUST_LOG` | No | `info` | Logging verbosity (`error`, `warn`, `info`, `debug`). |

> **Security Note:** Never commit `.env` or API credentials to version control. Use `.env.example` as a template.

---

## 3. Container Deployment (Docker)

SecScan AI includes a multi-stage `Dockerfile` that builds the optimized Rust binary and bundles Python 3 runtime dependencies for sandbox verification.

### Building the Image
```bash
docker build -t secscan-ai:latest .
```

### Running with Docker
```bash
docker run -d \
  -p 3000:3000 \
  -e NEBIUS_API_KEY="your-token-factory-key" \
  -e NEBIUS_MODEL="nvidia/llama-3.1-nemotron-70b-instruct" \
  --name secscan-ai \
  secscan-ai:latest
```

### Running with Docker Compose
```bash
# Copy and edit your .env file
cp .env.example .env
# Start the container stack
docker compose up -d
```

---

## 4. Cloud Platform Hosting Options

### Option A: Railway / Render / Fly.io (Container Deploy)
1. Link your GitHub repository (`maishaa555/ai-code-security-agent`).
2. Select **Docker** as the deployment build method (it will detect `Dockerfile`).
3. Set the environment variable `NEBIUS_API_KEY` in the service settings.
4. Set the port to `3000`.
5. Deploy.

### Option B: AWS ECS / Google Cloud Run
1. Push the Docker image to AWS ECR or Google Artifact Registry:
   ```bash
   docker tag secscan-ai:latest <registry-url>/secscan-ai:latest
   docker push <registry-url>/secscan-ai:latest
   ```
2. Deploy as a container service with 1 vCPU and 1GB RAM minimum.
3. Inject `NEBIUS_API_KEY` via AWS Secrets Manager or GCP Secret Manager.

### Option C: Bare Linux VM (Ubuntu / Debian / systemd)
1. Install prerequisites:
   ```bash
   sudo apt-get update && sudo apt-get install -y python3 python3-pip curl
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
2. Clone repository and build:
   ```bash
   git clone https://github.com/maishaa555/ai-code-security-agent.git
   cd ai-code-security-agent
   cargo build --release --bin secscan-server
   ```
3. Create systemd service (`/etc/systemd/system/secscan.service`):
   ```ini
   [Unit]
   Description=SecScan AI Server
   After=network.target

   [Service]
   Type=simple
   User=www-data
   WorkingDirectory=/opt/secscan
   EnvironmentFile=/opt/secscan/.env
   ExecStart=/opt/secscan/target/release/secscan-server
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```
4. Start and enable service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now secscan
   ```

---

## 5. Health Check & Validation

Verify deployment health:
```bash
curl http://localhost:3000/api/health
```
Expected response:
```json
{
  "status": "healthy",
  "engine": "SecScan Rust AST & Taint Core v1.0",
  "inference_provider": "Nebius Token Factory",
  "recommended_model": "nvidia/llama-3.1-nemotron-70b-instruct"
}
```
