declare const __AGENTSHIELD_VERSION__: string | undefined;

export const AGENTSHIELD_VERSION =
  typeof __AGENTSHIELD_VERSION__ !== "undefined"
    ? __AGENTSHIELD_VERSION__
    : "0.1.4";

