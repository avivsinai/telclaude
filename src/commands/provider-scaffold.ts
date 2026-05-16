import fs from "node:fs";
import path from "node:path";

const PROVIDER_ID_PATTERN = /^[a-z0-9][a-z0-9-]*$/;

export type ProviderScaffoldFile = {
	path: string;
	relativePath: string;
};

export type ProviderScaffoldResult = {
	providerId: string;
	serviceIds: string[];
	port: number;
	rootDir: string;
	files: ProviderScaffoldFile[];
	baseUrl: string;
};

export type ProviderScaffoldOptions = {
	providerId: string;
	services?: string[];
	port?: number;
	description?: string;
	outDir?: string;
	force?: boolean;
};

function normalizeProviderId(providerId: string): string {
	const trimmed = providerId.trim();
	if (!PROVIDER_ID_PATTERN.test(trimmed)) {
		throw new Error("Provider id must use lowercase letters, digits, and hyphens only.");
	}
	return trimmed;
}

function normalizeServices(providerId: string, services?: string[]): string[] {
	const normalized = Array.from(
		new Set((services ?? [providerId]).map((service) => service.trim()).filter(Boolean)),
	);
	if (normalized.length === 0) {
		throw new Error("At least one service is required.");
	}
	for (const service of normalized) {
		if (!PROVIDER_ID_PATTERN.test(service)) {
			throw new Error("Service ids must use lowercase letters, digits, and hyphens only.");
		}
	}
	return normalized;
}

function normalizePort(port?: number): number {
	const value = port ?? 3003;
	if (!Number.isInteger(value) || value < 1 || value > 65535) {
		throw new Error("Provider port must be an integer from 1 to 65535.");
	}
	return value;
}

function providerSidecarDirName(providerId: string): string {
	return providerId.endsWith("-services") ? providerId : `${providerId}-services`;
}

function writeScaffoldFile(filePath: string, body: string, force: boolean): void {
	if (!force && fs.existsSync(filePath)) {
		throw new Error(`Refusing to overwrite ${filePath}. Pass --force to replace scaffold files.`);
	}
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	const tmpPath = `${filePath}.tmp.${process.pid}.${Date.now()}`;
	fs.writeFileSync(tmpPath, body, "utf8");
	fs.renameSync(tmpPath, filePath);
}

function renderTypes(serviceIds: string[]): string {
	return [
		"export type ProviderActionRequest = {",
		"  service: string;",
		"  action: string;",
		"  params?: Record<string, unknown>;",
		"  actorUserId?: string;",
		"  subjectUserId?: string | null;",
		"  idempotencyKey?: string;",
		"};",
		"",
		"export type ProviderActionResponse = {",
		"  ok: true;",
		"  data: Record<string, unknown>;",
		"};",
		"",
		`export const SERVICE_IDS = ${JSON.stringify(serviceIds, null, 2)} as const;`,
		"export type ServiceId = (typeof SERVICE_IDS)[number];",
		"",
	].join("\n");
}

function renderActions(providerId: string, serviceIds: string[]): string {
	const services = JSON.stringify(serviceIds);
	return [
		'import type { ProviderActionRequest, ProviderActionResponse } from "./types.js";',
		"",
		`const SERVICES = new Set<string>(${services});`,
		"",
		"export async function handleProviderAction(",
		"  request: ProviderActionRequest,",
		"): Promise<ProviderActionResponse> {",
		"  if (!SERVICES.has(request.service)) {",
		'    throw new Error("Unknown service: " + request.service);',
		"  }",
		"",
		"  return {",
		"    ok: true,",
		"    data: {",
		`      provider: ${JSON.stringify(providerId)},`,
		"      service: request.service,",
		"      action: request.action,",
		'      status: "not_implemented",',
		"    },",
		"  };",
		"}",
		"",
	].join("\n");
}

function renderHealth(providerId: string, serviceIds: string[]): string {
	return [
		"export function getHealth() {",
		"  return {",
		"    ok: true,",
		`    providerId: ${JSON.stringify(providerId)},`,
		`    services: ${JSON.stringify(serviceIds)},`,
		'    version: "0.1.0",',
		"  };",
		"}",
		"",
	].join("\n");
}

function renderConfig(providerId: string, port: number): string {
	const envPrefix = providerId.replace(/-/g, "_").toUpperCase();
	return [
		`export const PROVIDER_ID = ${JSON.stringify(providerId)};`,
		`export const PORT = Number.parseInt(process.env.${envPrefix}_PORT ?? "${port}", 10);`,
		"",
	].join("\n");
}

function renderServer(description: string): string {
	return [
		'import http from "node:http";',
		'import { handleProviderAction } from "./actions.js";',
		'import { PORT, PROVIDER_ID } from "./config.js";',
		'import { getHealth } from "./health.js";',
		'import type { ProviderActionRequest } from "./types.js";',
		'import { SERVICE_IDS } from "./types.js";',
		"",
		"async function readJson(req: http.IncomingMessage): Promise<unknown> {",
		"  const chunks: Buffer[] = [];",
		"  for await (const chunk of req) {",
		"    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));",
		"  }",
		"  if (chunks.length === 0) return {};",
		'  return JSON.parse(Buffer.concat(chunks).toString("utf8"));',
		"}",
		"",
		"function writeJson(res: http.ServerResponse, status: number, body: unknown): void {",
		"  const payload = JSON.stringify(body);",
		"  res.writeHead(status, {",
		'    "content-type": "application/json; charset=utf-8",',
		'    "content-length": Buffer.byteLength(payload),',
		"  });",
		"  res.end(payload);",
		"}",
		"",
		"const server = http.createServer(async (req, res) => {",
		"  try {",
		'    if (req.method === "GET" && req.url === "/v1/health") {',
		"      writeJson(res, 200, getHealth());",
		"      return;",
		"    }",
		'    if (req.method === "GET" && req.url === "/v1/schema") {',
		"      writeJson(res, 200, {",
		"        providerId: PROVIDER_ID,",
		`        description: ${JSON.stringify(description)},`,
		"        services: SERVICE_IDS,",
		'        actions: SERVICE_IDS.map((service) => ({ service, action: "fetch", kind: "query" })),',
		"      });",
		"      return;",
		"    }",
		'    if (req.method === "POST" && req.url === "/v1/fetch") {',
		"      const body = (await readJson(req)) as ProviderActionRequest;",
		"      writeJson(res, 200, await handleProviderAction(body));",
		"      return;",
		"    }",
		'    writeJson(res, 404, { error: "not_found" });',
		"  } catch (error) {",
		"    writeJson(res, 500, { error: error instanceof Error ? error.message : String(error) });",
		"  }",
		"});",
		"",
		"server.listen(PORT, () => {",
		'  console.log(PROVIDER_ID + " provider listening on :" + PORT);',
		"});",
		"",
	].join("\n");
}

function renderIndex(): string {
	return ['import "./server.js";', ""].join("\n");
}

function renderDockerfile(sidecarDirName: string): string {
	return [
		"FROM node:22-alpine",
		"WORKDIR /app",
		"COPY package.json pnpm-lock.yaml ./",
		"RUN corepack enable && pnpm install --frozen-lockfile --prod=false",
		"COPY tsconfig.json ./",
		"COPY src ./src",
		`CMD ["pnpm", "tsx", "src/${sidecarDirName}/index.ts"]`,
		"",
	].join("\n");
}

export function scaffoldProviderSidecar(options: ProviderScaffoldOptions): ProviderScaffoldResult {
	const providerId = normalizeProviderId(options.providerId);
	const serviceIds = normalizeServices(providerId, options.services);
	const port = normalizePort(options.port);
	const rootDir = path.resolve(options.outDir ?? process.cwd());
	const description = options.description?.trim() || `${providerId} provider sidecar`;
	const sidecarDirName = providerSidecarDirName(providerId);
	const serviceDir = path.join(rootDir, "src", sidecarDirName);
	const dockerfile = path.join(rootDir, "docker", `Dockerfile.${providerId}`);
	const files = [
		{ path: path.join(serviceDir, "index.ts"), body: renderIndex() },
		{ path: path.join(serviceDir, "server.ts"), body: renderServer(description) },
		{ path: path.join(serviceDir, "actions.ts"), body: renderActions(providerId, serviceIds) },
		{ path: path.join(serviceDir, "types.ts"), body: renderTypes(serviceIds) },
		{ path: path.join(serviceDir, "health.ts"), body: renderHealth(providerId, serviceIds) },
		{ path: path.join(serviceDir, "config.ts"), body: renderConfig(providerId, port) },
		{ path: dockerfile, body: renderDockerfile(sidecarDirName) },
	];

	if (!options.force) {
		const existing = files.filter((file) => fs.existsSync(file.path));
		if (existing.length > 0) {
			throw new Error(
				`Refusing to overwrite ${path.relative(rootDir, existing[0].path)}. Pass --force to replace scaffold files.`,
			);
		}
	}

	for (const file of files) {
		writeScaffoldFile(file.path, file.body, options.force ?? false);
	}

	return {
		providerId,
		serviceIds,
		port,
		rootDir,
		baseUrl: `http://${sidecarDirName}:${port}`,
		files: files.map((file) => ({
			path: file.path,
			relativePath: path.relative(rootDir, file.path),
		})),
	};
}
