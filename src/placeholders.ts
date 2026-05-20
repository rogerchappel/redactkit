import type { PlaceholderMapFile, PlaceholderRecord, RedactionRule } from "./types.js";

export class PlaceholderMap {
  readonly records = new Map<string, PlaceholderRecord>();
  readonly counters = new Map<string, number>();

  constructor(existing?: PlaceholderMapFile) {
    for (const record of existing?.entries ?? []) {
      this.records.set(this.key(record.rule, record.value), record);
      const current = this.counters.get(record.rule) ?? 0;
      const suffix = Number(record.placeholder.match(/_(\d+)>$/)?.[1] ?? 0);
      this.counters.set(record.rule, Math.max(current, suffix));
    }
  }

  get(rule: RedactionRule, value: string): string {
    const key = this.key(rule.name, value);
    const existing = this.records.get(key);
    if (existing) {
      return existing.placeholder;
    }

    const next = (this.counters.get(rule.name) ?? 0) + 1;
    this.counters.set(rule.name, next);
    const placeholder = `<REDACTED_${rule.placeholder}_${String(next).padStart(3, "0")}>`;
    this.records.set(key, {
      rule: rule.name,
      value,
      placeholder,
    });
    return placeholder;
  }

  toJSON(): PlaceholderMapFile {
    return {
      version: 1,
      entries: [...this.records.values()].sort((a, b) =>
        a.placeholder.localeCompare(b.placeholder),
      ),
    };
  }

  private key(rule: string, value: string): string {
    return `${rule}\u0000${value}`;
  }
}
