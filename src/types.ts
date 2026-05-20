export type BuiltInRuleName =
  | "bearer"
  | "token"
  | "email"
  | "url"
  | "home-path"
  | "ipv4";

export type RuleSource = "built-in" | "custom";

export interface RedactionRule {
  name: string;
  description: string;
  pattern: RegExp;
  placeholder: string;
  source: RuleSource;
}

export interface SerializableRule {
  name: string;
  pattern: string;
  placeholder?: string;
  flags?: string;
  description?: string;
}

export interface RedactionMatch {
  file: string;
  line: number;
  column: number;
  rule: string;
  placeholder: string;
  fingerprint: string;
}

export interface PlaceholderRecord {
  rule: string;
  value: string;
  placeholder: string;
}

export interface PlaceholderMapFile {
  version: 1;
  entries: PlaceholderRecord[];
}

export interface ScanResult {
  files: string[];
  matches: RedactionMatch[];
}

export interface RedactResult extends ScanResult {
  outDir: string;
  mapPath: string;
  written: string[];
}

export interface RedactOptions {
  files: string[];
  outDir: string;
  mapPath: string;
  rules: RedactionRule[];
}

export interface ScanOptions {
  files: string[];
  rules: RedactionRule[];
}
