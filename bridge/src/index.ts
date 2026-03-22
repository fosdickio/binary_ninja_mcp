#!/usr/bin/env node

/**
 * Binary Ninja MCP Server - Main entry point
 * 
 * This MCP server connects to a running Binary Ninja instance with the MCP plugin
 * and exposes its capabilities through the Model Context Protocol.
 * 
 * Usage:
 *   npx @binary-ninja/mcp-server [options]
 *   
 * Options:
 *   --host <host>     Binary Ninja MCP server host (default: localhost)
 *   --port <port>     Binary Ninja MCP server port (default: 9009)
 *   --help            Show this help message
 * 
 * Environment variables:
 *   BINJA_MCP_HOST    Binary Ninja MCP server host
 *   BINJA_MCP_PORT    Binary Ninja MCP server port
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createClient } from "./client.js";
import { registerTools } from "./tools.js";

// Parse command line arguments
function parseArgs(): { host: string; port: number } {
  const args = process.argv.slice(2);
  let host = "localhost";
  let port = 9009;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case "--host":
        if (i + 1 < args.length) {
          host = args[++i];
        }
        break;
      case "--port":
        if (i + 1 < args.length) {
          port = parseInt(args[++i], 10);
        }
        break;
      case "--help":
      case "-h":
        console.log(`Binary Ninja MCP Server

Usage: npx binary-ninja-mcp [options]

Options:
  --host <host>     Binary Ninja MCP server host (default: localhost)
  --port <port>     Binary Ninja MCP server port (default: 9009)
  --help, -h        Show this help message

Environment variables:
  BINJA_MCP_HOST    Binary Ninja MCP server host
  BINJA_MCP_PORT    Binary Ninja MCP server port
`);
        process.exit(0);
        break;
    }
  }

  // Environment variables override defaults
  if (process.env.BINJA_MCP_HOST) {
    host = process.env.BINJA_MCP_HOST;
  }
  if (process.env.BINJA_MCP_PORT) {
    port = parseInt(process.env.BINJA_MCP_PORT, 10) || port;
  }

  return { host, port };
}

// Main entry point
async function main(): Promise<void> {
  const { host, port } = parseArgs();

  console.error(`Binary Ninja MCP Server connecting to ${host}:${port}`);

  // Create MCP server
  const server = new McpServer({
    name: "binary-ninja-mcp",
    version: "1.0.0",
  });

  // Create HTTP client for Binary Ninja
  const client = createClient(host, port);

  // Register all tools
  registerTools(server, client);

  // Create stdio transport
  const transport = new StdioServerTransport();

  // Connect and run
  await server.connect(transport);
  console.error("Binary Ninja MCP Server ready");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
