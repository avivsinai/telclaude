import fs from "node:fs";
import path from "node:path";

function resolveRoot(root: string): string {
	return fs.existsSync(root) ? fs.realpathSync(root) : path.resolve(root);
}

export function ensureInsideRoot(candidatePath: string, root: string, label: string): string {
	const resolvedRoot = resolveRoot(root);
	const candidate = fs.existsSync(candidatePath)
		? fs.realpathSync(candidatePath)
		: path.resolve(candidatePath);
	const rootWithSep = resolvedRoot.endsWith(path.sep) ? resolvedRoot : `${resolvedRoot}${path.sep}`;
	if (candidate !== resolvedRoot && !candidate.startsWith(rootWithSep)) {
		throw new Error(`${label} must stay inside the telclaude working directory`);
	}
	return candidate;
}

export function resolveInsideRoot(candidatePath: string, root: string, label: string): string {
	if (/[\0\r\n]/.test(candidatePath)) {
		throw new Error(`${label} must be a single-line path`);
	}
	const candidate = path.isAbsolute(candidatePath)
		? candidatePath
		: path.join(resolveRoot(root), candidatePath);
	return ensureInsideRoot(candidate, root, label);
}
