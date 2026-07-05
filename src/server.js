import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import { mkdir } from "node:fs/promises";
import { promisify } from "node:util";

import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { chromium } from "playwright";
import { z } from "zod";

const execFileAsync = promisify(execFile);

const TOOL_TIMEOUT_MS = 60_000;
const MAX_OUTPUT_CHARS = 12_000;
const PLAYWRIGHT_CLI_DEFAULT_TIMEOUT_MS = 90_000;
const HOST = process.env.HOST ?? "0.0.0.0";
const PORT = Number(process.env.PORT ?? "3000");
const PLAYWRIGHT_CLI_ALLOWED_COMMANDS = new Set([
  "--help",
  "-h",
  "--version",
  "install",
  "screenshot",
  "pdf",
  "show-trace"
]);
const COMMON_CHROMIUM_PATHS = process.platform === "darwin"
  ? [
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/Applications/Chromium.app/Contents/MacOS/Chromium"
    ]
  : [
      "/usr/bin/chromium",
      "/usr/bin/chromium-browser",
      "/usr/bin/google-chrome",
      "/usr/bin/google-chrome-stable"
    ];

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

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function resolveChromiumExecutablePath() {
  const envPath = process.env.PLAYWRIGHT_CHROMIUM_PATH;

  if (envPath && await fileExists(envPath)) {
    return envPath;
  }

  for (const candidate of COMMON_CHROMIUM_PATHS) {
    if (await fileExists(candidate)) {
      return candidate;
    }
  }

  return null;
}

function truncateText(text, maxLength) {
  const normalized = text.trim().replace(/\s+/g, " ");

  if (normalized.length <= maxLength) {
    return normalized;
  }

  return `${normalized.slice(0, maxLength)}…`;
}

async function launchChromium() {
  const executablePath = await resolveChromiumExecutablePath();

  const runtimeDirs = [
    "/tmp/.chromium-config",
    "/tmp/.chromium-cache",
    "/tmp/.chromium-runtime"
  ];

  for (const dir of runtimeDirs) {
    await mkdir(dir, { recursive: true }).catch(() => undefined);
  }

  const launchOptions = {
    headless: true,
    env: {
      ...process.env,
      HOME: "/tmp",
      XDG_CONFIG_HOME: "/tmp/.chromium-config",
      XDG_CACHE_HOME: "/tmp/.chromium-cache",
      XDG_RUNTIME_DIR: "/tmp/.chromium-runtime"
    },
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-crash-reporter",
      "--disable-crashpad"
    ]
  };

  try {
    // Prefer Playwright-managed Chromium for maximum runtime compatibility.
    return await chromium.launch(launchOptions);
  } catch {
    if (!executablePath) {
      return null;
    }

    return chromium.launch({
      ...launchOptions,
      executablePath
    });
  }
}

function validatePlaywrightCliArgs(args) {
  const firstArg = args[0] ?? "--help";

  if (!PLAYWRIGHT_CLI_ALLOWED_COMMANDS.has(firstArg)) {
    return `Unsupported Playwright CLI command: ${firstArg}. Allowed: ${Array.from(PLAYWRIGHT_CLI_ALLOWED_COMMANDS).join(", ")}`;
  }

  if (firstArg === "install") {
    const installArgs = args.slice(1);
    const allowedInstallArgs = new Set([
      "chromium",
      "firefox",
      "webkit",
      "--help",
      "--with-deps",
      "--dry-run"
    ]);

    for (const installArg of installArgs) {
      if (!allowedInstallArgs.has(installArg)) {
        return `Unsupported playwright install arg: ${installArg}`;
      }
    }
  }

  return null;
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
      options: z.array(z.enum(["-sV", "-sT", "-Pn", "-A", "-F"]))
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
    "website_explore",
    "Open a website in Playwright and return a structured page summary.",
    {
      url: z.string().url(),
      waitMs: z.number().int().min(0).max(10_000).optional(),
      maxLinks: z.number().int().min(1).max(50).optional(),
      maxTextChars: z.number().int().min(100).max(10_000).optional()
    },
    async ({ url, waitMs = 1_000, maxLinks = 10, maxTextChars = 2_000 }) => {
      const browser = await launchChromium();

      if (!browser) {
        return {
          content: [{
            type: "text",
            text: "No Chromium executable was found. Set PLAYWRIGHT_CHROMIUM_PATH or install Chromium/Google Chrome."
          }]
        };
      }

      try {
        const page = await browser.newPage({
          viewport: { width: 1440, height: 1600 }
        });

        const response = await page.goto(url, {
          waitUntil: "domcontentloaded",
          timeout: 45_000
        });

        if (waitMs > 0) {
          await page.waitForTimeout(waitMs);
        }

        const [title, description, headings, links, bodyText] = await Promise.all([
          page.title(),
          page.locator('meta[name="description"]').getAttribute("content").catch(() => null),
          page.locator("h1, h2, h3").evaluateAll((elements) =>
            elements
              .map((element) => element.textContent?.trim())
              .filter(Boolean)
              .slice(0, 20)
          ),
          page.locator("a[href]").evaluateAll((elements, limit) =>
            elements
              .map((element) => ({
                text: element.textContent?.trim() || "",
                href: element.getAttribute("href") || ""
              }))
              .filter((link) => link.href)
              .slice(0, limit),
            maxLinks
          ),
          page.locator("body").innerText({ timeout: 5_000 }).catch(() => "")
        ]);

        const result = {
          url: page.url(),
          status: response?.status() ?? null,
          title,
          description,
          headings,
          links,
          text: truncateText(bodyText, maxTextChars)
        };

        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2)
          }]
        };
      } catch (error) {
        return {
          content: [{
            type: "text",
            text: clampOutput(error?.message?.trim() || "Failed to explore the website.")
          }]
        };
      } finally {
        await browser.close().catch(() => undefined);
      }
    }
  );

  server.tool(
    "website_interact_form",
    "Open a website in Playwright, fill form fields, and optionally submit the form.",
    {
      url: z.string().url(),
      fields: z.array(z.object({
        selector: z.string().min(1),
        value: z.string().min(0),
        type: z.enum(["text", "checkbox", "radio", "select"]).optional()
      })).min(1).max(20),
      submitSelector: z.string().min(1).optional(),
      waitMs: z.number().int().min(0).max(10_000).optional(),
      maxTextChars: z.number().int().min(100).max(10_000).optional()
    },
    async ({ url, fields, submitSelector, waitMs = 1_000, maxTextChars = 2_000 }) => {
      const browser = await launchChromium();

      if (!browser) {
        return {
          content: [{
            type: "text",
            text: "No Chromium executable was found. Set PLAYWRIGHT_CHROMIUM_PATH or install Chromium/Google Chrome."
          }]
        };
      }

      try {
        const page = await browser.newPage({
          viewport: { width: 1440, height: 1600 }
        });

        const response = await page.goto(url, {
          waitUntil: "domcontentloaded",
          timeout: 45_000
        });
        let statusCode = response?.status() ?? null;

        for (const field of fields) {
          const locator = page.locator(field.selector).first();
          const fieldType = field.type ?? "text";

          try {
            if (fieldType === "checkbox") {
              const shouldCheck = ["true", "1", "yes", "on"].includes(field.value.toLowerCase());
              if (shouldCheck) {
                await locator.check({ timeout: 10_000 });
              } else {
                await locator.uncheck({ timeout: 10_000 });
              }
              continue;
            }

            if (fieldType === "radio") {
              const radioLocator = field.value
                ? page.locator(`${field.selector}[value=${JSON.stringify(field.value)}]`).first()
                : locator;
              await radioLocator.check({ timeout: 10_000 });
              continue;
            }

            if (fieldType === "select") {
              let selected = await locator.selectOption({ label: field.value }).catch(() => []);

              if (!selected.length) {
                selected = await locator.selectOption({ value: field.value }).catch(() => []);
              }

              if (!selected.length && /^\d+$/.test(field.value)) {
                selected = await locator.selectOption({ index: Number(field.value) }).catch(() => []);
              }

              if (!selected.length) {
                throw new Error("No matching select option found by label, value, or index.");
              }
              continue;
            }

            await locator.fill(field.value, { timeout: 10_000 });
          } catch (error) {
            throw new Error(
              `Field action failed for selector "${field.selector}" (type: ${fieldType}): ${error?.message || "unknown error"}`
            );
          }
        }

        if (submitSelector) {
          const navigationResponsePromise = page
            .waitForNavigation({ waitUntil: "domcontentloaded", timeout: 15_000 })
            .catch(() => null);

          await page.locator(submitSelector).first().click({ timeout: 10_000 });
          const navigationResponse = await navigationResponsePromise;

          if (navigationResponse) {
            statusCode = navigationResponse.status();
          }

          await page.waitForLoadState("networkidle", { timeout: 15_000 }).catch(() => undefined);
        }

        if (waitMs > 0) {
          await page.waitForTimeout(waitMs);
        }

        const [title, bodyText] = await Promise.all([
          page.title(),
          page.locator("body").innerText({ timeout: 5_000 }).catch(() => "")
        ]);

        const result = {
          url: page.url(),
          status: statusCode,
          title,
          text: truncateText(bodyText, maxTextChars)
        };

        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2)
          }]
        };
      } catch (error) {
        return {
          content: [{
            type: "text",
            text: clampOutput(error?.message?.trim() || "Failed to interact with the form.")
          }]
        };
      } finally {
        await browser.close().catch(() => undefined);
      }
    }
  );

  server.tool(
    "playwright_cli",
    "Run bounded Playwright CLI commands from the MCP server.",
    {
      args: z.array(z.string().min(1)).max(20).optional(),
      timeoutMs: z.number().int().min(1_000).max(180_000).optional()
    },
    async ({ args = ["--version"], timeoutMs = PLAYWRIGHT_CLI_DEFAULT_TIMEOUT_MS }) => {
      const validationError = validatePlaywrightCliArgs(args);

      if (validationError) {
        return {
          content: [{ type: "text", text: validationError }]
        };
      }

      const output = await runCommand("playwright", args, { timeoutMs });
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
