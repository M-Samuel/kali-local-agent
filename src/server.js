import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const execFileAsync = promisify(execFile);

const TOOL_TIMEOUT_MS = 60_000;
const MAX_OUTPUT_CHARS = 12_000;
const HOST = process.env.HOST ?? "0.0.0.0";
const PORT = Number(process.env.PORT ?? "3000");

function clampOutput(text = "") {
  if (text.length <= MAX_OUTPUT_CHARS) {
    return text;
  }

  return `${text.slice(0, MAX_OUTPUT_CHARS)}\n\n[truncated output]`;
}

async function runCommand(command, args, { timeoutMs = TOOL_TIMEOUT_MS } = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024
    });

    const merged = [stdout?.trim(), stderr?.trim()].filter(Boolean).join("\n\n");
    return clampOutput(merged || "(no output)");
  } catch (error) {
    if (error?.code === "ENOENT") {
      return `${command} is not installed in this runtime environment.`;
    }

    if (error?.killed && error?.signal === "SIGTERM") {
      return `${command} exceeded timeout (${timeoutMs}ms).`;
    }

    const merged = [error?.stdout?.trim(), error?.stderr?.trim(), error?.message?.trim()]
      .filter(Boolean)
      .join("\n\n");

    return clampOutput(merged || `Failed to run ${command}.`);
  }
}

function createServer() {
  const server = new McpServer({
    name: "kali-tools-mcp",
    version: "1.0.0"
  });

  server.tool(
    "nmap_scan",
    "Run nmap against a host or CIDR range.",
    {
      target: z.string().min(1),
      options: z.array(z.enum(["-sV", "-sS", "-Pn", "-A", "-F"]))
        .max(4)
        .optional()
    },
    async ({ target, options = [] }) => {
      const output = await runCommand("nmap", [...options, target]);
      return {
        content: [{ type: "text", text: output }]
      };
    }
  );

  server.tool(
    "sqlmap_url_scan",
    "Run a basic sqlmap check against a URL.",
    {
      url: z.string().url(),
      batch: z.boolean().optional(),
      crawlDepth: z.number().int().min(0).max(2).optional()
    },
    async ({ url, batch = true, crawlDepth = 0 }) => {
      const args = ["-u", url, "--smart", "--level", "2", "--risk", "1"];

      if (batch) {
        args.push("--batch");
      }

      if (crawlDepth > 0) {
        args.push("--crawl", String(crawlDepth));
      }

      const output = await runCommand("sqlmap", args);
      return {
        content: [{ type: "text", text: output }]
      };
    }
  );

  server.tool(
    "dig_lookup",
    "Resolve DNS records with dig.",
    {
      domain: z.string().min(1),
      recordType: z.enum(["A", "AAAA", "CNAME", "MX", "TXT", "NS"]).optional()
    },
    async ({ domain, recordType = "A" }) => {
      const output = await runCommand("dig", [domain, recordType, "+short"]);
      return {
        content: [{ type: "text", text: output }]
      };
    }
  );

  server.tool(
    "whois_lookup",
    "Get WHOIS information for a domain.",
    {
      domain: z.string().min(1)
    },
    async ({ domain }) => {
      const output = await runCommand("whois", [domain]);
      return {
        content: [{ type: "text", text: output }]
      };
    }
  );

  server.tool(
    "http_headers_check",
    "Fetch HTTP response headers for a URL.",
    {
      url: z.string().url(),
      followRedirects: z.boolean().optional(),
      insecureTls: z.boolean().optional()
    },
    async ({ url, followRedirects = true, insecureTls = false }) => {
      const args = ["-sS", "-I", "--max-time", "30"];

      if (followRedirects) {
        args.push("-L", "--max-redirs", "5");
      }

      if (insecureTls) {
        args.push("-k");
      }

      args.push(url);

      const output = await runCommand("curl", args);
      return {
        content: [{ type: "text", text: output }]
      };
    }
  );

  server.tool(
    "tls_certificate_check",
    "Inspect TLS certificate and handshake details for a host.",
    {
      host: z.string().min(1),
      port: z.number().int().min(1).max(65535).optional()
    },
    async ({ host, port = 443 }) => {
      const output = await runCommand(
        "openssl",
        [
          "s_client",
          "-connect",
          `${host}:${port}`,
          "-servername",
          host,
          "-brief",
          "-showcerts"
        ],
        { timeoutMs: 45_000 }
      );

      return {
        content: [{ type: "text", text: output }]
      };
    }
  );

  server.tool(
    "nmap_vuln_scan",
    "Run nmap vulnerability NSE scripts against a host with bounded scope.",
    {
      target: z.string().min(1),
      topPorts: z.number().int().min(10).max(2000).optional(),
      skipHostDiscovery: z.boolean().optional()
    },
    async ({ target, topPorts = 100, skipHostDiscovery = false }) => {
      const args = ["-sV", "--script", "vuln", "--top-ports", String(topPorts)];

      if (skipHostDiscovery) {
        args.push("-Pn");
      }

      args.push(target);

      const output = await runCommand("nmap", args, { timeoutMs: 120_000 });
      return {
        content: [{ type: "text", text: output }]
      };
    }
  );

  server.tool(
    "nmap_ssl_cipher_scan",
    "Enumerate supported TLS ciphers on a target using nmap ssl-enum-ciphers.",
    {
      target: z.string().min(1),
      port: z.number().int().min(1).max(65535).optional(),
      skipHostDiscovery: z.boolean().optional()
    },
    async ({ target, port = 443, skipHostDiscovery = false }) => {
      const args = ["-sV", "-p", String(port), "--script", "ssl-enum-ciphers"];

      if (skipHostDiscovery) {
        args.push("-Pn");
      }

      args.push(target);

      const output = await runCommand("nmap", args, { timeoutMs: 120_000 });
      return {
        content: [{ type: "text", text: output }]
      };
    }
  );

  return server;
}

async function main() {
  const app = createMcpExpressApp({ host: HOST });

  app.get("/health", (_req, res) => {
    res.status(200).json({ status: "ok" });
  });

  app.post("/mcp", async (req, res) => {
    const server = createServer();

    try {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined
      });

      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);

      res.on("close", () => {
        transport.close().catch(() => undefined);
        server.close().catch(() => undefined);
      });
    } catch (error) {
      console.error("Error handling MCP request:", error);

      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: {
            code: -32603,
            message: "Internal server error"
          },
          id: null
        });
      }
    }
  });

  app.get("/mcp", (_req, res) => {
    res.status(405).json({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed"
      },
      id: null
    });
  });

  app.delete("/mcp", (_req, res) => {
    res.status(405).json({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed"
      },
      id: null
    });
  });

  app.listen(PORT, HOST, () => {
    console.log(`MCP server listening on http://${HOST}:${PORT}/mcp`);
  });
}

main().catch((error) => {
  console.error("MCP server failed:", error);
  process.exit(1);
});
