/**
 * Kill-chain stage → MITRE ATT&CK tactic.
 *
 * The workflow stages were already named after ATT&CK tactics, so this is a
 * naming lookup, not an inference: nothing here claims a technique (Txxxx) was
 * observed, only which tactic the stage corresponds to. Enterprise reports are
 * routinely expected to reference the framework, and a wrong technique ID would
 * be worse than none — so tactics only.
 *
 * Reference: https://attack.mitre.org/tactics/enterprise/
 */
export interface MitreTactic {
  id: string;
  name: string;
  url: string;
}

const TACTICS: Record<string, { id: string; name: string }> = {
  reconnaissance:       { id: "TA0043", name: "Reconnaissance" },
  "initial access":     { id: "TA0001", name: "Initial Access" },
  exploitation:         { id: "TA0002", name: "Execution" },
  execution:            { id: "TA0002", name: "Execution" },
  "privilege escalation": { id: "TA0004", name: "Privilege Escalation" },
  "credential access":  { id: "TA0006", name: "Credential Access" },
  discovery:            { id: "TA0007", name: "Discovery" },
  "lateral movement":   { id: "TA0008", name: "Lateral Movement" },
  collection:           { id: "TA0009", name: "Collection" },
  exfiltration:         { id: "TA0010", name: "Exfiltration" },
  impact:               { id: "TA0040", name: "Impact" },
};

/** Returns the tactic for a stage label, or null when the stage has no ATT&CK
 *  equivalent (e.g. "Target", "Verification", "Break the chain"). */
export function tacticFor(stage: string | null | undefined): MitreTactic | null {
  if (!stage) return null;
  const t = TACTICS[stage.trim().toLowerCase()];
  return t ? { ...t, url: `https://attack.mitre.org/tactics/${t.id}/` } : null;
}
