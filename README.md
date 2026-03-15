# Agent Forensics

**Black box recorder for AI agents. Reconstruct what happened. Find where it went wrong.**

From [15 Research Lab](https://github.com/AUTHENSOR)

---

Agent Forensics reads Authensor receipt chains (or any structured agent logs) and reconstructs the full decision tree. It identifies anomalies like retry-after-denial loops, privilege escalation patterns, timing anomalies, and chain integrity breaks.

## Install

```bash
npm install agent-forensics
```

Or run directly:

```bash
npx agent-forensics analyze --receipts ./receipts.json
```

## Usage

### CLI

```bash
# Analyze a receipt chain for anomalies
npx agent-forensics analyze --receipts ./receipts.json

# Validate hash chain integrity
npx agent-forensics verify --receipts ./receipts.json

# Generate an incident report (markdown)
npx agent-forensics report --receipts ./receipts.json --format markdown

# Visualize as Mermaid DAG
npx agent-forensics visualize --receipts ./receipts.json
```

### Library

```typescript
import {
  parseReceipts,
  validateChain,
  buildTree,
  analyze,
  summarize,
  generateReport,
} from 'agent-forensics';

// Parse receipt data
const receipts = parseReceipts(jsonString);

// Validate chain integrity
const integrity = validateChain(receipts);

// Build the decision tree
const tree = buildTree(receipts);

// Detect anomalies
const anomalies = analyze(receipts, integrity);

// Generate a report
const summary = summarize(receipts, tree);
const report = { chain: receipts, integrity, tree, anomalies, summary };
const output = generateReport(report, 'terminal');

console.log(output);
```

## Example Output

```
Agent Forensics — Decision Tree Reconstruction
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Chain: 12 receipts │ Integrity: ✓ VALID │ Time span: 2m 34s

Timeline:
  14:02:01  ✓ ALLOW   file.read     /workspace/config.json     [0.2ms]
  14:02:02  ✓ ALLOW   http.get      api.example.com/users      [0.1ms]
  14:02:03  ✗ DENY    file.write    /etc/passwd                [0.1ms]  ← BLOCKED
  14:02:03  ✗ DENY    file.write    /etc/passwd                [0.1ms]  ← RETRY (suspicious)
  14:02:04  ⏳ REVIEW  email.send    smtp://mail.example.com    [0.2ms]
  14:02:15  ✓ ALLOW   email.send    smtp://mail.example.com    [0.1ms]  ← APPROVED by admin@
  14:02:16  ✗ DENY    code.execute  bash: curl | sh            [0.3ms]  ← AEGIS: exfiltration
  ...

⚠ Anomalies Detected:
  1. [HIGH] Retry after denial: file.write /etc/passwd attempted 2x (14:02:03)
  2. [LOW] Timing anomaly: 11s gap between email.send REVIEW and APPROVAL
  3. [CRITICAL] Escalation pattern: read(allow) -> write(denied) -> execute(denied)

Integrity: All 12 receipt hashes verified ✓
```

## Receipt Format

Agent Forensics reads receipts compatible with the [Authensor](https://github.com/AUTHENSOR/authensor) receipt format:

```typescript
interface Receipt {
  id: string;
  timestamp: string;
  receipt_hash: string;
  prev_receipt_hash: string | null;
  action: { type: string; resource: string; operation: string; parameters?: Record<string, unknown> };
  principal: { type: string; id: string };
  decision: { outcome: 'allow' | 'deny' | 'require_approval' | 'rate_limited'; reason?: string };
  matched_rule?: { id: string; name: string };
  evaluation_time_ms: number;
  parent_receipt_id?: string;
}
```

## Anomaly Detection

Agent Forensics detects the following anomaly types:

| Type | Severity | Description |
|------|----------|-------------|
| `retry_after_denial` | Medium/High | Same action attempted multiple times after denial |
| `timing_anomaly` | Low/Medium | Unusual gaps or bursts in action timing |
| `escalation_pattern` | High/Critical | Increasing privilege level in action sequence |
| `privilege_escalation` | High/Critical | Access to sensitive resources (credentials, /etc/passwd) |
| `rapid_fire` | Medium/High | Many actions in a very short time window |
| `chain_break` | Critical | Hash chain integrity failure (possible tampering) |

## Report Formats

| Format | Flag | Description |
|--------|------|-------------|
| Terminal | `--format terminal` | Colored ASCII tree with anomaly highlights |
| Markdown | `--format markdown` | Structured incident report |
| JSON | `--format json` | Machine-readable analysis output |
| Mermaid | `--format mermaid` | Visual DAG diagram |

## Part of the Authensor Ecosystem

This project is part of the [Authensor](https://github.com/AUTHENSOR/AUTHENSOR) open-source AI safety ecosystem, built by [15 Research Lab](https://github.com/AUTHENSOR).

| Project | Description |
|---------|-------------|
| [Authensor](https://github.com/AUTHENSOR/AUTHENSOR) | The open-source safety stack for AI agents |
| [Prompt Injection Benchmark](https://github.com/AUTHENSOR/prompt-injection-benchmark) | Standardized benchmark for safety scanners |
| [AI SecLists](https://github.com/AUTHENSOR/ai-seclists) | Security wordlists and payloads for AI/LLM testing |
| [ATT&CK ↔ Alignment Rosetta](https://github.com/AUTHENSOR/attack-alignment-rosetta) | Maps MITRE ATT&CK to AI alignment concepts |
| [Behavioral Fingerprinting](https://github.com/AUTHENSOR/behavioral-fingerprinting) | Statistical behavioral drift detection |

## Design

- **Zero runtime dependencies** — only Node.js built-ins
- **TypeScript, ESM, strict mode**
- **Synchronous core** — parsing and analysis are pure functions
- **Composable** — use the library functions individually or the full pipeline

## License

MIT
