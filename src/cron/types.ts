export type CronSchedule =
	| {
			kind: "at";
			at: string;
	  }
	| {
			kind: "every";
			everyMs: number;
	  }
	| {
			kind: "cron";
			expr: string;
	  };

export type CronAction =
	| {
			kind: "social-heartbeat";
			serviceId?: string;
	  }
	| {
			kind: "private-heartbeat";
	  };

export type CronJob = {
	id: string;
	name: string;
	enabled: boolean;
	running: boolean;
	schedule: CronSchedule;
	action: CronAction;
	nextRunAtMs: number | null;
	lastRunAtMs: number | null;
	lastStatus: "success" | "error" | "skipped" | null;
	lastError: string | null;
	createdAtMs: number;
	updatedAtMs: number;
};

export type CronAddInput = {
	id?: string;
	name: string;
	enabled?: boolean;
	schedule: CronSchedule;
	action: CronAction;
};

export type CronStatusSummary = {
	totalJobs: number;
	enabledJobs: number;
	runningJobs: number;
	nextRunAtMs: number | null;
};

export type CronCoverage = {
	allSocial: boolean;
	socialServiceIds: string[];
	hasPrivateHeartbeat: boolean;
};

export type CronActionResult = {
	ok: boolean;
	message: string;
};
