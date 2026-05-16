import fs from "node:fs";
import path from "node:path";

export type LogRotationResult = {
	rotated: boolean;
	rotatedPath?: string;
	pruned: number;
};

export type RotateLogFileOptions = {
	filePath: string;
	maxBytes: number;
	retainedFiles: number;
	now?: Date;
};

export type RotatedLogFile = {
	name: string;
	path: string;
	mtimeMs: number;
};

function timestampForRotation(now: Date): string {
	return now.toISOString().replace(/[:.]/g, "-");
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function rotatedLogNamePattern(filePath: string): RegExp {
	return new RegExp(
		`^${escapeRegExp(path.basename(filePath))}\\.\\d{4}-\\d{2}-\\d{2}T\\d{2}-\\d{2}-\\d{2}-\\d{3}Z(?:\\.\\d+)?$`,
	);
}

function allocateRotatedPath(filePath: string, now: Date): string {
	const basePath = `${filePath}.${timestampForRotation(now)}`;
	if (!fs.existsSync(basePath)) return basePath;

	for (let index = 2; index <= 999; index += 1) {
		const candidate = `${basePath}.${index}`;
		if (!fs.existsSync(candidate)) return candidate;
	}
	throw new Error(`Could not allocate rotated log path for ${filePath}.`);
}

export function listRotatedLogFiles(filePath: string): RotatedLogFile[] {
	const dir = path.dirname(filePath);
	const rotatedNamePattern = rotatedLogNamePattern(filePath);
	let entries: RotatedLogFile[] = [];

	try {
		entries = fs
			.readdirSync(dir, { withFileTypes: true })
			.filter((entry) => rotatedNamePattern.test(entry.name))
			.flatMap((entry) => {
				const entryPath = path.join(dir, entry.name);
				try {
					const stat = fs.lstatSync(entryPath);
					if (!stat.isFile() || stat.isSymbolicLink()) return [];
					return [{ name: entry.name, path: entryPath, mtimeMs: stat.mtimeMs }];
				} catch {
					return [];
				}
			});
	} catch {
		return [];
	}

	entries.sort((left, right) => {
		const byTime = right.mtimeMs - left.mtimeMs;
		return byTime === 0 ? right.name.localeCompare(left.name) : byTime;
	});
	return entries;
}

function pruneRotatedLogs(filePath: string, retainedFiles: number): number {
	if (retainedFiles < 0) return 0;
	let pruned = 0;
	for (const stale of listRotatedLogFiles(filePath).slice(retainedFiles)) {
		try {
			fs.rmSync(stale.path, { force: true });
			pruned += 1;
		} catch {
			// Best effort. Log rotation must not break the caller's primary write path.
		}
	}
	return pruned;
}

export function rotateLogFileIfNeeded(options: RotateLogFileOptions): LogRotationResult {
	const maxBytes = Math.max(1, options.maxBytes);
	const retainedFiles = Math.max(0, options.retainedFiles);
	let stat: fs.Stats;
	try {
		stat = fs.lstatSync(options.filePath);
	} catch {
		return {
			rotated: false,
			pruned: pruneRotatedLogs(options.filePath, retainedFiles),
		};
	}

	if (!stat.isFile() || stat.isSymbolicLink() || stat.size < maxBytes) {
		return {
			rotated: false,
			pruned: pruneRotatedLogs(options.filePath, retainedFiles),
		};
	}

	const rotatedPath = allocateRotatedPath(options.filePath, options.now ?? new Date());
	fs.renameSync(options.filePath, rotatedPath);
	return {
		rotated: true,
		rotatedPath,
		pruned: pruneRotatedLogs(options.filePath, retainedFiles),
	};
}
