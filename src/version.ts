declare const __AGENTSHIELD_VERSION__: string | undefined;

export const AGENTSHIELD_VERSION =
  typeof __AGENTSHIELD_VERSION__ !== "undefined" ? __AGENTSHIELD_VERSION__ : "0.2.1";

export const AGENT_SHIELD_VERSION = AGENTSHIELD_VERSION;
