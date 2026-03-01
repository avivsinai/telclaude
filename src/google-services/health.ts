/**
 * Health store — per-service state machine for health tracking.
 *
 * States: ok ↔ degraded, ok → auth_expired (sticky until re-auth).
 */

import type { HealthStatus, ServiceHealth, ServiceId } from "./types.js";

const SERVICES: ServiceId[] = ["gmail", "calendar", "drive", "contacts"];
const DEGRADED_THRESHOLD = 3; // failures before degraded

export class HealthStore {
	private services: Map<string, ServiceHealth> = new Map();

	constructor() {
		for (const svc of SERVICES) {
			this.services.set(svc, {
				status: "ok",
				failureCount: 0,
			});
		}
	}

	recordSuccess(service: string): void {
		const state = this.services.get(service);
		if (!state) return;
		// auth_expired is sticky — only cleared by explicit reset
		if (state.status === "auth_expired") return;
		state.status = "ok";
		state.failureCount = 0;
		state.lastSuccess = Date.now();
		state.lastAttempt = Date.now();
	}

	recordFailure(service: string): void {
		const state = this.services.get(service);
		if (!state) return;
		if (state.status === "auth_expired") return;
		state.failureCount++;
		state.lastAttempt = Date.now();
		if (state.failureCount >= DEGRADED_THRESHOLD) {
			state.status = "degraded";
		}
	}

	recordAuthExpired(service: string): void {
		const state = this.services.get(service);
		if (!state) return;
		state.status = "auth_expired";
		state.lastAttempt = Date.now();
	}

	resetAuth(service: string): void {
		const state = this.services.get(service);
		if (!state) return;
		state.status = "ok";
		state.failureCount = 0;
	}

	getStatus(service: string): ServiceHealth | undefined {
		return this.services.get(service);
	}

	/**
	 * Get coarse health response (default).
	 */
	getCoarseHealth(): { status: HealthStatus; services: Record<string, HealthStatus> } {
		const overall = this.getOverallStatus();
		const services: Record<string, HealthStatus> = {};
		for (const [id, state] of this.services) {
			services[id] = state.status;
		}
		return { status: overall, services };
	}

	/**
	 * Get detailed health response (debug mode).
	 */
	getDetailedHealth(): { status: HealthStatus; services: Record<string, ServiceHealth> } {
		const overall = this.getOverallStatus();
		const services: Record<string, ServiceHealth> = {};
		for (const [id, state] of this.services) {
			services[id] = { ...state };
		}
		return { status: overall, services };
	}

	private getOverallStatus(): HealthStatus {
		let hasAuthExpired = false;
		let hasDegraded = false;
		for (const state of this.services.values()) {
			if (state.status === "auth_expired") hasAuthExpired = true;
			if (state.status === "degraded") hasDegraded = true;
		}
		if (hasAuthExpired) return "auth_expired";
		if (hasDegraded) return "degraded";
		return "ok";
	}
}
