#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer, VERSION } from "./server.js";

if (process.argv.includes("--version")) {
  process.stdout.write(`${VERSION}\n`);
  process.exit(0);
}

try {
  const { server } = createServer();
  await server.connect(new StdioServerTransport());
} catch (e) {
  // Config errors only; never echo the environment.
  process.stderr.write(`fabric-verify-mcp: ${e.message}\n`);
  process.exit(2);
}
