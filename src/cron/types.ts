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
	  }
	| {
			kind: "curator-scan";
	  }
	| {
			kind: "household-reminder";
			reminderId: string;
			revision: number;
	  }
	| {
			kind: "household-metrics-digest";
			atHour: number;
	  }
	| {
			kind: "agent-prompt";
			prompt: string;
			/**
			 * Explicit Hermes skill allowlist for scheduled prompts.
			 * Undefined uses the active profile policy. [] denies all skills.
			 */
			allowedSkills?: string[];
			preprocess?: CronPreprocessCommand;
	  };

export type CronPreprocessCommand = {
	command: string;
	args?: string[];
	cwd?: string;
	timeoutMs?: number;
	maxStdoutBytes?: number;
};

export type CronDeliveryTarget =
	| {
			kind: "home";
	  }
	| {
			kind: "origin";
			chatId?: number;
			threadId?: number;
	  }
	| {
			kind: "chat";
			chatId: number;
			threadId?: number;
	  };

export type CronJob = {
	id: string;
	name: string;
	enabled: boolean;
	running: boolean;
	ownerId: string | null;
	deliveryTarget: CronDeliveryTarget;
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
	ownerId?: string;
	deliveryTarget?: CronDeliveryTarget;
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
	retryAtMs?: number;
};
