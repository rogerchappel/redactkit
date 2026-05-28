import type { RedactionRule } from "./types.js";

function rule(
  name: string,
  description: string,
  pattern: RegExp,
  placeholder: string,
): RedactionRule {
  return {
    name,
    description,
    pattern,
    placeholder,
    source: "built-in",
  };
}

export const builtInRules: RedactionRule[] = [
  rule(
    "bearer",
    "Authorization bearer token header or value.",
    /\bBearer\s+([A-Za-z0-9._~+/=-]{12,})\b/g,
    "BEARER",
  ),
  rule(
    "token",
    "Common token or API key assignment.",
    /"?(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|token)"?\s*[:=]\s*["']?([A-Za-z0-9._~+/=-]{12,})["']?/gi,
    "TOKEN",
  ),
  rule(
    "email",
    "Email address.",
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    "EMAIL",
  ),
  rule(
    "url",
    "HTTP or HTTPS URL.",
    /\bhttps?:\/\/[^\s<>"')\]]+/gi,
    "URL",
  ),
  rule(
    "home-path",
    "Unix or macOS home directory path.",
    /(?:\/Users\/[A-Za-z0-9._-]+|\/home\/[A-Za-z0-9._-]+)(?:\/[^\s:"'<>]*)?/g,
    "HOME_PATH",
  ),
  rule(
    "ipv4",
    "IPv4 address.",
    /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    "IPV4",
  ),
];

export function cloneRule(ruleToClone: RedactionRule): RedactionRule {
  return {
    ...ruleToClone,
    pattern: new RegExp(ruleToClone.pattern.source, ruleToClone.pattern.flags),
  };
}
