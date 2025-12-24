/**
 * TOTP daemon entry point.
 *
 * This module exports the server functions and can also be run directly
 * as a standalone daemon process.
 */

export {
	type CheckResponse,
	type DisableResponse,
	getDefaultSocketPath,
	type SetupResponse,
	type TOTPRequest,
	type TOTPResponse,
	type VerifyResponse,
} from "./protocol.js";
export { type ServerHandle, type ServerOptions, startServer } from "./server.js";
