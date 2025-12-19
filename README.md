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
npm run dev
```

## Notes
- Keep this repository **private**; do not commit `.env` or other secrets.
- `dist/` and `node_modules/` are generated and ignored.
