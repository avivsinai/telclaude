import fs from "node:fs";
import path from "node:path";

function resolveClaudeHome(): string | null {
	const raw = process.env.CLAUDE_CONFIG_DIR ?? process.env.TELCLAUDE_CLAUDE_HOME;
	if (!raw || !path.isAbsolute(raw)) {
		return null;
	}
	return raw;
}

export function toClaudeProjectSlug(cwd: string): string {
	const resolved = path.resolve(cwd).replace(/\\/g, "/");
	return resolved.replace(/[^a-zA-Z0-9._/-]/g, "-").replace(/\//g, "-");
}

export function resolveClaudeProjectMemoryPath(cwd: string): string | null {
	const claudeHome = resolveClaudeHome();
	if (!claudeHome) return null;
	return path.join(claudeHome, "projects", toClaudeProjectSlug(cwd), "memory", "MEMORY.md");
}

export function materializeClaudeProjectMemory(cwd: string, content: string): string | null {
	const targetPath = resolveClaudeProjectMemoryPath(cwd);
	if (!targetPath) return null;

	const finalContent = content.endsWith("\n") ? content : `${content}\n`;
	const current = fs.existsSync(targetPath) ? fs.readFileSync(targetPath, "utf-8") : null;
	if (current === finalContent) {
		return targetPath;
	}

	fs.mkdirSync(path.dirname(targetPath), { recursive: true });
	const tempPath = `${targetPath}.tmp-${process.pid}-${Date.now()}`;
	fs.writeFileSync(tempPath, finalContent, "utf-8");
	fs.renameSync(tempPath, targetPath);
	return targetPath;
}
