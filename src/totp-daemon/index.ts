/**
 * TOTP daemon entry point.
 *
 * This module exports the server functions and can also be run directly
 * as a standalone daemon process.
 */

export { startServer, type ServerHandle, type ServerOptions } from "./server.js";
export {
	type TOTPRequest,
	type TOTPResponse,
	type SetupResponse,
	type VerifyResponse,
	type CheckResponse,
	type DisableResponse,
	getDefaultSocketPath,
} from "./protocol.js";
