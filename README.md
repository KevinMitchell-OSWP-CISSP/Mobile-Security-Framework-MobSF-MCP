# MobSF MCP Server

Model Context Protocol server for driving a local MobSF instance. Includes tools to upload apps, trigger scans, fetch reports, and manage findings.

## Prerequisites
- Node.js 18+ and npm
- Running MobSF instance and API key

## Setup
1) Install dependencies:
```bash
npm install
```
2) Copy `.env.example` to `.env` and set your values:
```bash
cp .env.example .env
```

## Environment Variables
- `MOBSF_BASE_URL` – MobSF URL (e.g., `http://127.0.0.1:8000`)
- `MOBSF_API_KEY` – MobSF API key

## Build & Run
```bash
npm run build
npm start
# or for development
MOBSF_API_KEY=your_api_key_here MOBSF_BASE_URL=http://127.0.0.1:8000 npm run dev
```

## Notes
- Keep this repository **private**; do not commit `.env` or other secrets.
- `dist/` and `node_modules/` are generated and ignored.

## Using with MCP Clients (Claude/OpenAI)
- Build and start the MCP server (`npm run build && npm start`), or run via `npm run dev`.
- Configure your MCP-compatible client (Claude Desktop, Model Context Protocol integrations, etc.) to launch this server process and set env vars `MOBSF_BASE_URL` and `MOBSF_API_KEY`.
- Tools exposed:
  - `upload_mobile_app` (file upload)
  - `scan_mobile_app`
  - `get_scan_report_json`
  - `get_scan_report_pdf`
  - `wait_for_report` (polls until report is ready)
  - `health_check` (connectivity/API key sanity)
  - `view_source_code`
  - `compare_apps`
  - `get_recent_scans`
  - `delete_scan`
  - `get_app_scorecard`
  - `suppress_finding`

Error handling: The server validates configuration at startup (missing `MOBSF_API_KEY` will error) and returns detailed HTTP errors from MobSF for easier troubleshooting in chat UIs.
