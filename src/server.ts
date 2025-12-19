import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import axios, { AxiosError } from 'axios';
import FormData from 'form-data';
import fs from 'fs-extra';
import path from 'path';
import { z } from 'zod';

const envSchema = z.object({
  MOBSF_BASE_URL: z.string().url().default('http://127.0.0.1:8000'),
  MOBSF_API_KEY: z.string().min(1, 'MOBSF_API_KEY is required')
});

const env = envSchema.parse({
  MOBSF_BASE_URL: process.env.MOBSF_BASE_URL,
  MOBSF_API_KEY: process.env.MOBSF_API_KEY
});

const client = axios.create({
  baseURL: env.MOBSF_BASE_URL,
  headers: { Authorization: env.MOBSF_API_KEY }
});

const formatAxiosError = (error: AxiosError) => {
  const status = error.response?.status;
  const data = error.response?.data;
  const summary = status ? `HTTP ${status}` : 'Network/unknown error';
  if (data) return `${summary}: ${JSON.stringify(data)}`;
  return `${summary}: ${error.message}`;
};

const safePick = (obj: any, keys: string[]) =>
  keys.reduce<Record<string, unknown>>((acc, key) => {
    if (obj && obj[key] !== undefined) acc[key] = obj[key];
    return acc;
  }, {});

type ToolDef = {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  schema: z.ZodTypeAny;
  handler: (args: any) => Promise<any>;
};

const server = new Server({ name: 'mobsf-security-suite', version: '1.0.0' }, { capabilities: { tools: {} } });

const tools: ToolDef[] = [
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
    schema: z.object({
      file_path: z.string().min(1, 'file_path is required')
    }),
    handler: async (args) => {
      if (!await fs.pathExists(args.file_path)) throw new Error(`File not found: ${args.file_path}`);
      const form = new FormData();
      form.append('file', fs.createReadStream(args.file_path), path.basename(args.file_path));
      const response = await client.post('/api/v1/upload', form, { headers: { ...form.getHeaders() } });
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
    schema: z.object({
      hash: z.string().min(1, 'hash is required'),
      scan_type: z.enum(['apk', 'ipa', 'zip']).optional()
    }),
    handler: async (args) => {
      const response = await client.post('/api/v1/scan', {
        hash: args.hash,
        scan_type: args.scan_type || 'apk'
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
    schema: z.object({
      hash: z.string().min(1, 'hash is required')
    }),
    handler: async (args) => {
      const response = await client.post('/api/v1/report_json', { hash: args.hash });
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
    schema: z.object({
      hash: z.string().min(1, 'hash is required'),
      output_path: z.string().min(1).optional()
    }),
    handler: async (args) => {
      const response = await client.post('/api/v1/download_pdf', { hash: args.hash }, { responseType: 'stream' });
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
    schema: z.object({
      hash: z.string().min(1, 'hash is required'),
      file: z.string().min(1, 'file is required'),
      type: z.enum(['apk', 'ipa', 'zip'])
    }),
    handler: async (args) => {
      const response = await client.post('/api/v1/view_source', {
        hash: args.hash,
        file: args.file,
        type: args.type
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
    schema: z.object({
      hash1: z.string().min(1, 'hash1 is required'),
      hash2: z.string().min(1, 'hash2 is required')
    }),
    handler: async (args) => {
      const response = await client.post('/api/v1/compare', {
        hash1: args.hash1,
        hash2: args.hash2
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
    schema: z.object({
      page: z.number().int().positive().optional()
    }),
    handler: async (args) => {
      const response = await client.get('/api/v1/recent_scans', { params: { page: args.page || 1 } });
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
    schema: z.object({
      hash: z.string().min(1, 'hash is required')
    }),
    handler: async (args) => {
      const response = await client.post('/api/v1/delete_scan', { hash: args.hash });
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
    schema: z.object({
      hash: z.string().min(1, 'hash is required')
    }),
    handler: async (args) => {
      const response = await client.post('/api/v1/scorecard', { hash: args.hash });
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
    schema: z.object({
      hash: z.string().min(1, 'hash is required'),
      finding_id: z.string().min(1, 'finding_id is required'),
      reason: z.string().optional()
    }),
    handler: async (args) => {
      const response = await client.post('/api/v1/suppress_finding', {
        hash: args.hash,
        finding_id: args.finding_id,
        reason: args.reason
      });
      return response.data;
    }
  },
  {
    name: 'health_check',
    description: 'Verify MobSF API connectivity and API key',
    inputSchema: {
      type: 'object',
      properties: {}
    },
    schema: z.object({}),
    handler: async () => {
      const response = await client.get('/api/v1/recent_scans', { params: { page: 1 } });
      const recentCount = Array.isArray(response.data) ? response.data.length : undefined;
      return { status: 'ok', recent_scans_count: recentCount };
    }
  },
  {
    name: 'wait_for_report',
    description: 'Poll until scan report is ready or timeout',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'File hash of the analyzed app' },
        interval_ms: { type: 'number', description: 'Polling interval in milliseconds', default: 3000 },
        timeout_ms: { type: 'number', description: 'Timeout in milliseconds', default: 60000 }
      },
      required: ['hash']
    },
    schema: z.object({
      hash: z.string().min(1, 'hash is required'),
      interval_ms: z.number().int().positive().optional().default(3000),
      timeout_ms: z.number().int().positive().optional().default(60000)
    }),
    handler: async (args) => {
      const start = Date.now();
      const interval = args.interval_ms ?? 3000;
      const timeout = args.timeout_ms ?? 60000;

      /* Poll report_json until it succeeds or times out. */
      while (Date.now() - start < timeout) {
        try {
          const response = await client.post('/api/v1/report_json', { hash: args.hash });
          return { status: 'ready', report: response.data };
        } catch (err) {
          const axErr = err as AxiosError;
          const status = axErr.response?.status;
          if (status && [400, 404, 425, 429, 503].includes(status)) {
            await new Promise(res => setTimeout(res, interval));
            continue;
          }
          throw err;
        }
      }
      throw new Error(`Timed out waiting for report for hash ${args.hash}`);
    }
  },
  {
    name: 'get_scan_status',
    description: 'Check if scan report is ready without downloading the full report',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'File hash of the analyzed app' }
      },
      required: ['hash']
    },
    schema: z.object({
      hash: z.string().min(1, 'hash is required')
    }),
    handler: async (args) => {
      try {
        const response = await client.post('/api/v1/report_json', { hash: args.hash });
        const meta = safePick(response.data, [
          'package_name',
          'app_name',
          'version_name',
          'version_code',
          'md5',
          'sha1',
          'sha256'
        ]);
        return { status: 'ready', meta };
      } catch (err) {
        const axErr = err as AxiosError;
        const status = axErr.response?.status;
        if (status && [400, 404, 425, 429, 503].includes(status)) {
          return { status: 'pending', message: formatAxiosError(axErr) };
        }
        throw err;
      }
    }
  },
  {
    name: 'cancel_scan',
    description: 'Cancel and delete a scan by hash',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'File hash of scan to cancel/delete' }
      },
      required: ['hash']
    },
    schema: z.object({
      hash: z.string().min(1, 'hash is required')
    }),
    handler: async (args) => {
      const response = await client.post('/api/v1/delete_scan', { hash: args.hash });
      return { status: 'deleted', response: response.data };
    }
  },
  {
    name: 'list_uploaded_apps',
    description: 'List recent uploaded apps with hashes and metadata',
    inputSchema: {
      type: 'object',
      properties: {
        page: { type: 'number', default: 1, description: 'Page number for pagination' }
      }
    },
    schema: z.object({
      page: z.number().int().positive().optional()
    }),
    handler: async (args) => {
      const response = await client.get('/api/v1/recent_scans', { params: { page: args.page || 1 } });
      return response.data;
    }
  },
  {
    name: 'get_scan_metadata',
    description: 'Return basic metadata for a scan (hashes, package, version, file info)',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'File hash of the analyzed app' }
      },
      required: ['hash']
    },
    schema: z.object({
      hash: z.string().min(1, 'hash is required')
    }),
    handler: async (args) => {
      const response = await client.post('/api/v1/report_json', { hash: args.hash });
      const meta = safePick(response.data, [
        'file_name',
        'size',
        'scan_type',
        'md5',
        'sha1',
        'sha256',
        'package_name',
        'app_name',
        'version_name',
        'version_code',
        'sdk_version',
        'target_sdk_version'
      ]);
      return meta;
    }
  },
  {
    name: 'get_scan_artifacts',
    description: 'Return key report sections (manifest, permissions, binaries, malware checks, entitlements)',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'File hash of the analyzed app' },
        sections: {
          type: 'array',
          items: { type: 'string' },
          description: 'Report sections to include',
          default: ['manifest_analysis', 'permissions', 'binaries', 'malware', 'entitlements', 'files']
        }
      },
      required: ['hash']
    },
    schema: z.object({
      hash: z.string().min(1, 'hash is required'),
      sections: z.array(z.string()).optional()
    }),
    handler: async (args) => {
      const response = await client.post('/api/v1/report_json', { hash: args.hash });
      const sections = args.sections || ['manifest_analysis', 'permissions', 'binaries', 'malware', 'entitlements', 'files'];
      const data = safePick(response.data, sections);
      return data;
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
    const parsedArgs = tool.schema ? tool.schema.parse(args || {}) : args || {};
    const result = await tool.handler(parsedArgs);
    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
    };
  } catch (error: any) {
    if (error instanceof AxiosError) {
      return {
        content: [{ type: 'text', text: `Error executing ${name}: ${formatAxiosError(error)}` }],
        isError: true
      };
    }
    if (error instanceof z.ZodError) {
      return {
        content: [{ type: 'text', text: `Invalid configuration: ${error.errors.map(e => e.message).join(', ')}` }],
        isError: true
      };
    }
    return {
      content: [{ type: 'text', text: `Error executing ${name}: ${error.message}` }],
      isError: true
    };
  }
});

const transport = new StdioServerTransport();
server.connect(transport);
