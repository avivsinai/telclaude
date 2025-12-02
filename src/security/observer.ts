/**
 * Security observer using Claude Agent SDK with circuit breaker.
 *
 * Analyzes incoming messages for security risks using:
 * 1. Fast-path regex patterns (instant, no API call)
 * 2. SDK + security-gate skill (LLM-based analysis)
 *
 * Circuit breaker prevents cascading failures when SDK is slow/failing.
 */

import { query } from "@anthropic-ai/claude-agent-sdk";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { isAssistantMessage } from "../sdk/message-guards.js";
import { CircuitBreaker } from "./circuit-breaker.js";
import { checkStructuralIssues, fastPathClassify } from "./fast-path.js";
import type { ObserverResult, SecurityClassification } from "./types.js";

const logger = getChildLogger({ module: "observer" });

export type ObserverConfig = {
	enabled: boolean;
	maxLatencyMs: number;
	dangerThreshold: number;
	fallbackOnTimeout: "allow" | "block" | "escalate";
	cwd?: string;
	circuitBreaker?: {
		failureThreshold?: number;
		resetTimeoutMs?: number;
		successThreshold?: number;
	};
};

export class SecurityObserver {
	private circuitBreaker: CircuitBreaker;

	constructor(private config: ObserverConfig) {
		this.circuitBreaker = new CircuitBreaker("observer", config.circuitBreaker);
	}

	async analyze(
		message: string,
		context: {
			permissionTier: PermissionTier;
			hasFlaggedHistory?: boolean;
		},
	): Promise<ObserverResult> {
		const startTime = Date.now();

		// 1. Check for structural issues (prompt injection patterns)
		const structuralIssues = checkStructuralIssues(message);
		if (structuralIssues.length > 0) {
			logger.warn({ issues: structuralIssues }, "structural issues detected");
			return {
				classification: "WARN",
				confidence: 0.8,
				reason: structuralIssues.join("; "),
				flaggedPatterns: structuralIssues,
				latencyMs: Date.now() - startTime,
			};
		}

		// 2. Try fast-path classification (regex-based, instant)
		const fastResult = fastPathClassify(message);
		if (fastResult) {
			logger.debug({ result: fastResult }, "fast-path classification");
			return {
				classification: fastResult.classification,
				confidence: 1.0,
				reason: fastResult.reason,
				latencyMs: Date.now() - startTime,
			};
		}

		// 3. If observer disabled, allow with low confidence
		if (!this.config.enabled) {
			return {
				classification: "ALLOW",
				confidence: 0.5,
				reason: "Observer disabled",
				latencyMs: Date.now() - startTime,
			};
		}

		// 4. Check circuit breaker before SDK call
		if (!this.circuitBreaker.canExecute()) {
			logger.warn("circuit breaker open, using fallback");
			return this.fallbackResult("Circuit breaker open", Date.now() - startTime);
		}

		// 5. Use SDK with security-gate skill for LLM analysis
		try {
			const result = await this.classifyWithSdk(message, context);
			this.circuitBreaker.recordSuccess();

			// Apply dangerThreshold adjustments
			let finalClassification = result.classification;
			let adjustedReason = result.reason;

			if (result.classification === "BLOCK" && result.confidence < this.config.dangerThreshold) {
				finalClassification = "WARN";
				adjustedReason = `Downgraded from BLOCK (confidence ${result.confidence.toFixed(2)} < ${this.config.dangerThreshold}): ${result.reason}`;
				logger.info(
					{ original: result.classification, confidence: result.confidence },
					"BLOCK downgraded to WARN",
				);
			}

			if (
				result.classification === "WARN" &&
				result.confidence < this.config.dangerThreshold * 0.5
			) {
				finalClassification = "ALLOW";
				adjustedReason = `Downgraded from WARN (confidence ${result.confidence.toFixed(2)}): ${result.reason}`;
				logger.info(
					{ original: result.classification, confidence: result.confidence },
					"WARN downgraded to ALLOW",
				);
			}

			return {
				...result,
				classification: finalClassification,
				reason: adjustedReason,
				latencyMs: Date.now() - startTime,
			};
		} catch (err) {
			this.circuitBreaker.recordFailure();
			logger.error({ error: String(err) }, "observer SDK error");
			return this.fallbackResult(String(err), Date.now() - startTime);
		}
	}

	private async classifyWithSdk(
		message: string,
		context: { permissionTier: PermissionTier; hasFlaggedHistory?: boolean },
	): Promise<Omit<ObserverResult, "latencyMs">> {
		const prompt = `Classify this message for security risks.

Message: """
${message}
"""

Context:
- Permission Tier: ${context.permissionTier}
- Flagged History: ${context.hasFlaggedHistory ? "yes" : "no"}

Respond with JSON only.`;

		const abortController = new AbortController();
		const timeout = setTimeout(() => abortController.abort(), this.config.maxLatencyMs);

		try {
			const q = query({
				prompt,
				options: {
					cwd: this.config.cwd ?? process.cwd(),
					settingSources: ["project"],
					allowedTools: ["Skill"],
					maxTurns: 1,
					abortController,
				},
			});

			let response = "";
			for await (const msg of q) {
				if (isAssistantMessage(msg)) {
					for (const block of msg.message.content) {
						if (block.type === "text") {
							response += block.text;
						}
					}
				}
			}

			return this.parseClassificationResponse(response);
		} finally {
			clearTimeout(timeout);
		}
	}

	private parseClassificationResponse(response: string): Omit<ObserverResult, "latencyMs"> {
		try {
			const jsonMatch = response.match(/\{[\s\S]*\}/);
			if (jsonMatch) {
				const parsed = JSON.parse(jsonMatch[0]) as {
					classification?: SecurityClassification;
					confidence?: number;
					reason?: string;
					flaggedPatterns?: string[];
					suggestedTier?: PermissionTier;
				};

				return {
					classification: parsed.classification ?? "BLOCK",
					confidence: parsed.confidence ?? 0,
					reason: parsed.reason ?? "No reason provided",
					flaggedPatterns: parsed.flaggedPatterns,
					suggestedTier: parsed.suggestedTier,
				};
			}
		} catch (err) {
			logger.warn({ error: String(err), response }, "failed to parse classification JSON");
		}

		return {
			classification: "BLOCK",
			confidence: 0,
			reason: "Failed to parse classification response",
		};
	}

	private fallbackResult(error: string, latencyMs: number): ObserverResult {
		logger.warn(
			{ error, fallbackMode: this.config.fallbackOnTimeout, latencyMs },
			"observer timeout/error, using fallback",
		);

		let classification: SecurityClassification;
		let confidence: number;

		switch (this.config.fallbackOnTimeout) {
			case "allow":
				classification = "ALLOW";
				confidence = 0.3;
				break;
			case "escalate":
				classification = "WARN";
				confidence = 0.5;
				break;
			default:
				classification = "BLOCK";
				confidence = 0.5;
				break;
		}

		return {
			classification,
			confidence,
			reason: `Observer error: ${error}. Fallback: ${this.config.fallbackOnTimeout}`,
			latencyMs,
		};
	}

	getCircuitBreakerStatus() {
		return this.circuitBreaker.getStatus();
	}

	resetCircuitBreaker() {
		this.circuitBreaker.reset();
	}
}

export function createObserver(config: ObserverConfig): SecurityObserver {
	return new SecurityObserver(config);
}
