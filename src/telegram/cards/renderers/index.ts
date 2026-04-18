import { cardRegistry } from "../registry.js";
import { CardKind } from "../types.js";
import { approvalRenderer } from "./approval.js";
import { authRenderer } from "./auth.js";
import { backgroundJobListRenderer, backgroundJobRenderer } from "./background-job.js";
import { heartbeatRenderer } from "./heartbeat.js";
import { pendingQueueRenderer } from "./pending-queue.js";
import { sessionRenderer } from "./session.js";
import { skillDraftRenderer } from "./skill-draft.js";
import { skillsMenuRenderer } from "./skills-menu.js";
import { socialMenuRenderer } from "./social-menu.js";
import { statusRenderer } from "./status.js";

export function registerAllCardRenderers(): void {
	cardRegistry.register(CardKind.Approval, approvalRenderer);
	cardRegistry.register(CardKind.PendingQueue, pendingQueueRenderer);
	cardRegistry.register(CardKind.Status, statusRenderer);
	cardRegistry.register(CardKind.Auth, authRenderer);
	cardRegistry.register(CardKind.Heartbeat, heartbeatRenderer);
	cardRegistry.register(CardKind.SkillDraft, skillDraftRenderer);
	cardRegistry.register(CardKind.SkillsMenu, skillsMenuRenderer);
	cardRegistry.register(CardKind.SocialMenu, socialMenuRenderer);
	cardRegistry.register(CardKind.Session, sessionRenderer);
	cardRegistry.register(CardKind.BackgroundJob, backgroundJobRenderer);
	cardRegistry.register(CardKind.BackgroundJobList, backgroundJobListRenderer);
}

export {
	approvalRenderer,
	authRenderer,
	backgroundJobListRenderer,
	backgroundJobRenderer,
	heartbeatRenderer,
	pendingQueueRenderer,
	sessionRenderer,
	skillDraftRenderer,
	skillsMenuRenderer,
	socialMenuRenderer,
	statusRenderer,
};
