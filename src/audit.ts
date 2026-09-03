import { appendFileSync } from "node:fs";
import { auditPath } from "./paths.js";

/**
 * Append-only local audit trail. One JSON object per line; never contains
 * secrets or released codes, only what was asked, by which tool, and how
 * it was decided.
 */

export interface AuditEvent {
  tool: string;
  domain?: string;
  action?: string;
  decision: "auto" | "approved" | "denied" | "timeout" | "error";
  detail?: string;
}

export function audit(event: AuditEvent): void {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...event });
  appendFileSync(auditPath(), line + "\n");
}
