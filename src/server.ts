import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';
import FormData from 'form-data';
import fs from 'fs-extra';
import path from 'path';

const MOBSF_BASE_URL = process.env.MOBSF_BASE_URL || 'http://127.0.0.1:8000';
const MOBSF_API_KEY = process.env.MOBSF_API_KEY || '';

const server = new Server({ name: 'mobsf-security-suite', version: '1.0.0' }, { capabilities: { tools: {} } });

const tools = [
  {
    name: 'upload_mobile_app',
    description: 'Upload mobile app (APK/IPA/ZIP) for security analysis',
    inputSchema: {
      type: 'object',
      properties: {
        file_path: { type: 'string', description: 'Path to APK/IPA/ZIP file to upload' }
      },
      required: ['file_path']
    },
    handler: async (args: any) => {
      if (!await fs.pathExists(args.file_path)) throw new Error(`File not found: ${args.file_path}`);
      const form = new FormData();
      form.append('file', fs.createReadStream(args.file_path), path.basename(args.file_path));
      const response = await axios.post(`${MOBSF_BASE_URL}/api/v1/upload`, form, {
        headers: { 'Authorization': MOBSF_API_KEY, ...form.getHeaders() }
      });
      return response.data;
    }
  },
  {
    name: 'scan_mobile_app',
    description: 'Perform security scan on uploaded mobile app using hash',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'File hash from upload response' },
        scan_type: { type: 'string', enum: ['apk', 'ipa', 'zip'], default: 'apk', description: 'Type of app' }
      },
      required: ['hash']
    },
    handler: async (args: any) => {
      const response = await axios.post(`${MOBSF_BASE_URL}/api/v1/scan`, {
        hash: args.hash,
        scan_type: args.scan_type || 'apk'
      }, {
        headers: { 'Authorization': MOBSF_API_KEY }
      });
      return response.data;
    }
  },
  {
    name: 'get_scan_report_json',
    description: 'Get detailed JSON scan report',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'File hash of the analyzed app' }
      },
      required: ['hash']
    },
    handler: async (args: any) => {
      const response = await axios.post(`${MOBSF_BASE_URL}/api/v1/report_json`, { hash: args.hash }, {
        headers: { 'Authorization': MOBSF_API_KEY }
      });
      return response.data;
    }
  },
  {
    name: 'get_scan_report_pdf',
    description: 'Download PDF report of security analysis',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'File hash of the analyzed app' },
        output_path: { type: 'string', description: 'Local path to save PDF report', default: './mobsf_report.pdf' }
      },
      required: ['hash']
    },
    handler: async (args: any) => {
      const response = await axios.post(`${MOBSF_BASE_URL}/api/v1/download_pdf`, { hash: args.hash }, {
        headers: { 'Authorization': MOBSF_API_KEY },
        responseType: 'stream'
      });
      const outputPath = args.output_path || './mobsf_report.pdf';
      const writer = fs.createWriteStream(outputPath);
      response.data.pipe(writer);
      return new Promise((resolve, reject) => {
        writer.on('finish', () => resolve({ message: `PDF report saved to: ${outputPath}` }));
        writer.on('error', reject);
      });
    }
  },
  {
    name: 'view_source_code',
    description: 'View source code of specific file from analyzed app',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'File hash of the analyzed app' },
        file: { type: 'string', description: 'Relative path to source file within the app' },
        type: { type: 'string', enum: ['apk', 'ipa', 'zip'], description: 'App type' }
      },
      required: ['hash', 'file', 'type']
    },
    handler: async (args: any) => {
      const response = await axios.post(`${MOBSF_BASE_URL}/api/v1/view_source`, {
        hash: args.hash,
        file: args.file,
        type: args.type
      }, {
        headers: { 'Authorization': MOBSF_API_KEY }
      });
      return response.data;
    }
  },
  {
    name: 'compare_apps',
    description: 'Compare security analysis of two mobile apps',
    inputSchema: {
      type: 'object',
      properties: {
        hash1: { type: 'string', description: 'Hash of first app' },
        hash2: { type: 'string', description: 'Hash of second app' }
      },
      required: ['hash1', 'hash2']
    },
    handler: async (args: any) => {
      const response = await axios.post(`${MOBSF_BASE_URL}/api/v1/compare`, {
        hash1: args.hash1,
        hash2: args.hash2
      }, {
        headers: { 'Authorization': MOBSF_API_KEY }
      });
      return response.data;
    }
  },
  {
    name: 'get_recent_scans',
    description: 'Get list of recent scans and their metadata',
    inputSchema: {
      type: 'object',
      properties: {
        page: { type: 'number', default: 1, description: 'Page number for pagination' }
      }
    },
    handler: async (args: any) => {
      const response = await axios.get(`${MOBSF_BASE_URL}/api/v1/recent_scans`, {
        headers: { 'Authorization': MOBSF_API_KEY },
        params: { page: args.page || 1 }
      });
      return response.data;
    }
  },
  {
    name: 'delete_scan',
    description: 'Delete scan results and associated files',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'File hash of scan to delete' }
      },
      required: ['hash']
    },
    handler: async (args: any) => {
      const response = await axios.post(`${MOBSF_BASE_URL}/api/v1/delete_scan`, { hash: args.hash }, {
        headers: { 'Authorization': MOBSF_API_KEY }
      });
      return response.data;
    }
  },
  {
    name: 'get_app_scorecard',
    description: 'Get security scorecard summary for analyzed app',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'File hash of the analyzed app' }
      },
      required: ['hash']
    },
    handler: async (args: any) => {
      const response = await axios.post(`${MOBSF_BASE_URL}/api/v1/scorecard`, { hash: args.hash }, {
        headers: { 'Authorization': MOBSF_API_KEY }
      });
      return response.data;
    }
  },
  {
    name: 'suppress_finding',
    description: 'Suppress/ignore a specific security finding',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'File hash of the analyzed app' },
        finding_id: { type: 'string', description: 'ID of the finding to suppress' },
        reason: { type: 'string', description: 'Reason for suppressing this finding' }
      },
      required: ['hash', 'finding_id']
    },
    handler: async (args: any) => {
      const response = await axios.post(`${MOBSF_BASE_URL}/api/v1/suppress_finding`, {
        hash: args.hash,
        finding_id: args.finding_id,
        reason: args.reason
      }, {
        headers: { 'Authorization': MOBSF_API_KEY }
      });
      return response.data;
    }
  }
];

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: tools.map(tool => ({
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema
  }))
}));

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const tool = tools.find(t => t.name === name);
  if (!tool) throw new Error(`Unknown tool: ${name}`);
  try {
    const result = await tool.handler(args || {});
    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
    };
  } catch (error: any) {
    return {
      content: [{ type: 'text', text: `Error executing ${name}: ${error.message}` }],
      isError: true
    };
  }
});

const transport = new StdioServerTransport();
server.connect(transport);
