# MobSF MCP Server

Model Context Protocol server for driving a local MobSF instance. Use it with Claude/OpenAI MCP to upload apps, trigger scans, poll status, fetch reports, and pull focused artifacts.

## Prerequisites
- Node.js 18+ and npm
- Running MobSF and API key (see “Run MobSF”)

## Quick Start
```bash
git clone https://github.com/KevinMitchell-OSWP-CISSP/Mobile-Security-Framework-MobSF-MCP.git
cd Mobile-Security-Framework-MobSF-MCP
npm install
cp .env.example .env  # set MOBSF_API_KEY and MOBSF_BASE_URL

# build + run
npm run build
MOBSF_API_KEY=your_key MOBSF_BASE_URL=http://127.0.0.1:8000 npm start

# dev (ts-node)
MOBSF_API_KEY=your_key MOBSF_BASE_URL=http://127.0.0.1:8000 npm run dev
```

## Run MobSF (Docker)
```bash
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -d --name mobsf -p 8000:8000 \
  -v mobsf-data:/home/mobsf/.MobSF \
  opensecurity/mobile-security-framework-mobsf:latest

docker logs -f mobsf  # watch startup
```
Open http://127.0.0.1:8000, get the API key from Settings, and use it in `MOBSF_API_KEY`.

## Environment Variables
- `MOBSF_BASE_URL` – MobSF URL (default `http://127.0.0.1:8000`)
- `MOBSF_API_KEY` – MobSF API key (required)

## Tools (MCP)
- `upload_mobile_app` – upload APK/IPA/ZIP
- `scan_mobile_app` – trigger scan for a hash
- `wait_for_report` – poll until report is ready
- `get_scan_status` – lightweight readiness check
- `get_scan_report_json` – fetch full JSON report
- `get_scan_report_pdf` – download PDF
- `view_source_code` – fetch a specific source file
- `compare_apps` – compare two scans
- `list_uploaded_apps` / `get_recent_scans` – recent uploads/scans
- `get_scan_metadata` – hashes/package/version/file info
- `get_scan_artifacts` – manifest/permissions/binaries/malware/entitlements/files (configurable)
- `pipeline_scan` – upload → scan → wait → return metadata/artifacts (optional PDF)
- `get_app_scorecard` – scorecard summary
- `suppress_finding` – suppress a finding
- `delete_scan` / `cancel_scan` – delete/cancel by hash
- `health_check` – connectivity/API key sanity

## Using with MCP Clients (Claude/OpenAI)
- Ensure the server is running with correct env vars.
- Configure your MCP client to launch:  
  `bash -c "cd /home/ && MOBSF_API_KEY=... MOBSF_BASE_URL=http://127.0.0.1:8000 node dist/server.js"`
- In chat, call tools with JSON args (example):  
  `pipeline_scan` → `{"file_path":"/abs/path/app.apk","scan_type":"apk","timeout_ms":90000,"save_pdf":true}`

## Notes
- Keep this repository private; do not commit `.env` or secrets.
- `dist/` and `node_modules/` are generated and ignored.
- Error handling: startup validates env; MobSF HTTP errors are returned with details for easier troubleshooting in chat UIs.
