import type { EdgeChannel, EdgeChannelConnector } from "./edge-channel-connector.js";

/**
 * Registry of per-channel transports (CL-0). The outbound delivery dispatcher
 * looks a connector up by {@link EdgeChannel}; the inbound supervisor starts
 * listeners from the same set. One connector per channel (duplicate
 * registration is a configuration error and throws).
 */
export interface EdgeOutboundExecutorRegistry {
	register(connector: EdgeChannelConnector): void;
	get(channel: EdgeChannel): EdgeChannelConnector | undefined;
	has(channel: EdgeChannel): boolean;
	channels(): readonly EdgeChannel[];
	connectors(): readonly EdgeChannelConnector[];
}

export function createEdgeOutboundExecutorRegistry(
	initial: readonly EdgeChannelConnector[] = [],
): EdgeOutboundExecutorRegistry {
	const byChannel = new Map<EdgeChannel, EdgeChannelConnector>();

	function register(connector: EdgeChannelConnector): void {
		if (byChannel.has(connector.channel)) {
			throw new Error(`edge connector already registered for channel: ${connector.channel}`);
		}
		byChannel.set(connector.channel, connector);
	}

	for (const connector of initial) register(connector);

	return {
		register,
		get: (channel) => byChannel.get(channel),
		has: (channel) => byChannel.has(channel),
		channels: () => [...byChannel.keys()],
		connectors: () => [...byChannel.values()],
	};
}
