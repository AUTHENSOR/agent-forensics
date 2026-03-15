/**
 * Reporter -- Generates reports in multiple formats.
 *
 * Formats: terminal (colored ASCII), markdown, JSON, mermaid.
 */

import {
  AnalysisReport,
  ReportFormat,
  TreeNode,
  Anomaly,
  Receipt,
  DecisionOutcome,
} from './types.js';

// ANSI color codes
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
};

/**
 * Generate a report in the specified format.
 */
export function generateReport(report: AnalysisReport, format: ReportFormat): string {
  switch (format) {
    case 'terminal':
      return generateTerminalReport(report);
    case 'markdown':
      return generateMarkdownReport(report);
    case 'json':
      return generateJsonReport(report);
    case 'mermaid':
      return generateMermaidReport(report);
  }
}

// ─── Terminal Report ────────────────────────────────────────────────────────────

function generateTerminalReport(report: AnalysisReport): string {
  const lines: string[] = [];
  const { summary, integrity, anomalies, chain } = report;

  // Header
  lines.push('');
  lines.push(`${C.bold}${C.cyan}Agent Forensics \u2014 Decision Tree Reconstruction${C.reset}`);
  lines.push(`${C.dim}\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501${C.reset}`);
  lines.push('');

  // Summary bar
  const integrityStatus = integrity.valid
    ? `${C.green}\u2713 VALID${C.reset}`
    : `${C.red}\u2717 BROKEN (${integrity.brokenLinks.length} breaks)${C.reset}`;
  const durationStr = formatDuration(summary.timeSpan.durationMs);

  lines.push(
    `${C.bold}Chain:${C.reset} ${summary.totalReceipts} receipts \u2502 ` +
    `${C.bold}Integrity:${C.reset} ${integrityStatus} \u2502 ` +
    `${C.bold}Time span:${C.reset} ${durationStr}`,
  );
  lines.push('');

  // Decision distribution
  const dc = summary.decisionCounts;
  lines.push(
    `${C.bold}Decisions:${C.reset} ` +
    `${C.green}\u2713${dc.allow} allow${C.reset}  ` +
    `${C.red}\u2717${dc.deny} deny${C.reset}  ` +
    `${C.yellow}\u23F3${dc.require_approval} review${C.reset}  ` +
    `${C.magenta}\u26A0${dc.rate_limited} rate-limited${C.reset}`,
  );
  lines.push('');

  // Timeline
  lines.push(`${C.bold}Timeline:${C.reset}`);

  const sorted = [...chain].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
  );

  // Track retries for annotations
  const actionCounts = new Map<string, number>();

  for (const receipt of sorted) {
    const actionKey = `${receipt.action.type}:${receipt.action.resource}:${receipt.action.operation}`;
    const prevCount = actionCounts.get(actionKey) ?? 0;
    actionCounts.set(actionKey, prevCount + 1);

    const time = formatTimestamp(receipt.timestamp);
    const icon = getOutcomeIcon(receipt.decision.outcome);
    const color = getOutcomeColor(receipt.decision.outcome);
    const evalTime = `[${receipt.evaluation_time_ms}ms]`;

    let annotation = '';
    if (receipt.decision.outcome === 'deny') {
      annotation = `  ${C.red}\u2190 BLOCKED${C.reset}`;
      if (prevCount > 0) {
        annotation = `  ${C.bgRed}${C.white} RETRY (suspicious) ${C.reset}`;
      }
    } else if (receipt.decision.outcome === 'require_approval') {
      annotation = `  ${C.yellow}\u2190 PENDING${C.reset}`;
    } else if (receipt.decision.outcome === 'allow' && prevCount > 0) {
      const reason = receipt.decision.approved_by
        ? `APPROVED by ${receipt.decision.approved_by}`
        : receipt.decision.reason ?? 'ALLOWED';
      annotation = `  ${C.green}\u2190 ${reason}${C.reset}`;
    }
    if (receipt.decision.reason && receipt.decision.outcome === 'deny') {
      const reason = receipt.decision.reason;
      if (reason.toLowerCase().includes('aegis') || reason.toLowerCase().includes('exfiltration') || reason.toLowerCase().includes('injection')) {
        annotation += `  ${C.bgRed}${C.white} AEGIS: ${reason} ${C.reset}`;
      }
    }

    const resource = truncate(receipt.action.resource, 35);
    const actionType = receipt.action.type.padEnd(14);

    lines.push(
      `  ${C.dim}${time}${C.reset}  ${color}${icon} ${receipt.decision.outcome.toUpperCase().padEnd(7)}${C.reset}  ` +
      `${actionType} ${resource.padEnd(37)} ${C.dim}${evalTime}${C.reset}${annotation}`,
    );
  }

  lines.push('');

  // Anomalies
  if (anomalies.length > 0) {
    lines.push(`${C.bold}${C.yellow}\u26A0 Anomalies Detected:${C.reset}`);

    for (let i = 0; i < anomalies.length; i++) {
      const a = anomalies[i];
      const severityColor =
        a.severity === 'critical' ? C.bgRed + C.white :
        a.severity === 'high' ? C.red :
        a.severity === 'medium' ? C.yellow :
        C.dim;

      lines.push(
        `  ${C.bold}${i + 1}. ${severityColor}[${a.severity.toUpperCase()}]${C.reset} ${a.description}`,
      );
    }

    lines.push('');
  } else {
    lines.push(`${C.green}No anomalies detected.${C.reset}`);
    lines.push('');
  }

  // Integrity footer
  if (integrity.valid) {
    lines.push(
      `${C.green}${C.bold}Integrity:${C.reset} ${C.green}All ${summary.totalReceipts} receipt hashes verified \u2713${C.reset}`,
    );
  } else {
    lines.push(
      `${C.red}${C.bold}Integrity:${C.reset} ${C.red}${integrity.brokenLinks.length} broken chain link(s) detected \u2717${C.reset}`,
    );
    for (const link of integrity.brokenLinks) {
      lines.push(
        `  ${C.red}\u2514 Receipt ${link.receiptId} at position ${link.position}${C.reset}`,
      );
    }
  }

  lines.push('');
  return lines.join('\n');
}

// ─── Markdown Report ────────────────────────────────────────────────────────────

function generateMarkdownReport(report: AnalysisReport): string {
  const lines: string[] = [];
  const { summary, integrity, anomalies, chain } = report;

  lines.push('# Agent Forensics - Incident Report');
  lines.push('');
  lines.push(`**Generated:** ${new Date().toISOString()}`);
  lines.push('');

  // Summary
  lines.push('## Summary');
  lines.push('');
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total Receipts | ${summary.totalReceipts} |`);
  lines.push(`| Time Span | ${formatDuration(summary.timeSpan.durationMs)} |`);
  lines.push(`| Start | ${summary.timeSpan.start} |`);
  lines.push(`| End | ${summary.timeSpan.end} |`);
  lines.push(`| Chain Integrity | ${integrity.valid ? 'VALID' : 'BROKEN'} |`);
  lines.push(`| Unique Agents | ${summary.uniqueAgents.join(', ')} |`);
  lines.push(`| Max Chain Depth | ${summary.maxChainDepth} |`);
  lines.push(`| Avg Evaluation Time | ${summary.avgEvaluationTimeMs}ms |`);
  lines.push('');

  // Decision distribution
  lines.push('### Decision Distribution');
  lines.push('');
  const dc = summary.decisionCounts;
  lines.push(`| Outcome | Count | Percentage |`);
  lines.push(`|---------|-------|-----------|`);

  for (const [outcome, count] of Object.entries(dc)) {
    const pct = summary.totalReceipts > 0
      ? ((count / summary.totalReceipts) * 100).toFixed(1)
      : '0.0';
    lines.push(`| ${outcome} | ${count} | ${pct}% |`);
  }

  lines.push('');

  // Timeline
  lines.push('## Timeline');
  lines.push('');
  lines.push('| Time | Decision | Action | Resource | Eval Time |');
  lines.push('|------|----------|--------|----------|-----------|');

  const sorted = [...chain].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
  );

  for (const receipt of sorted) {
    const time = formatTimestamp(receipt.timestamp);
    const icon =
      receipt.decision.outcome === 'allow' ? '`ALLOW`' :
      receipt.decision.outcome === 'deny' ? '**`DENY`**' :
      receipt.decision.outcome === 'require_approval' ? '`REVIEW`' :
      '`RATE_LIM`';

    lines.push(
      `| ${time} | ${icon} | ${receipt.action.type} | \`${receipt.action.resource}\` | ${receipt.evaluation_time_ms}ms |`,
    );
  }

  lines.push('');

  // Anomalies
  if (anomalies.length > 0) {
    lines.push('## Anomalies');
    lines.push('');

    for (let i = 0; i < anomalies.length; i++) {
      const a = anomalies[i];
      const severityBadge =
        a.severity === 'critical' ? '`CRITICAL`' :
        a.severity === 'high' ? '`HIGH`' :
        a.severity === 'medium' ? '`MEDIUM`' :
        '`LOW`';

      lines.push(`### ${i + 1}. ${severityBadge} ${a.type.replace(/_/g, ' ')}`);
      lines.push('');
      lines.push(a.description);
      lines.push('');
      lines.push(`- **Receipt IDs:** ${a.receiptIds.map((id) => `\`${id}\``).join(', ')}`);
      lines.push(`- **Timestamp:** ${a.timestamp}`);

      if (a.details) {
        lines.push(`- **Details:** \`${JSON.stringify(a.details)}\``);
      }

      lines.push('');
    }
  }

  // Chain integrity
  lines.push('## Chain Integrity');
  lines.push('');

  if (integrity.valid) {
    lines.push(`All ${summary.totalReceipts} receipt hashes verified successfully.`);
  } else {
    lines.push(`**${integrity.brokenLinks.length} broken chain link(s) detected.**`);
    lines.push('');

    for (const link of integrity.brokenLinks) {
      lines.push(`- Receipt \`${link.receiptId}\` at position ${link.position}`);
      lines.push(`  - Expected prev hash: \`${link.expectedPrevHash}\``);
      lines.push(`  - Actual prev hash: \`${link.actualPrevHash}\``);
    }
  }

  lines.push('');
  lines.push('---');
  lines.push('*Generated by [Agent Forensics](https://github.com/AUTHENSOR/agent-forensics) from 15 Research Lab*');

  return lines.join('\n');
}

// ─── JSON Report ────────────────────────────────────────────────────────────────

function generateJsonReport(report: AnalysisReport): string {
  return JSON.stringify(
    {
      generated_at: new Date().toISOString(),
      summary: report.summary,
      integrity: report.integrity,
      anomalies: report.anomalies,
      receipt_count: report.chain.length,
      receipts: report.chain,
    },
    null,
    2,
  );
}

// ─── Mermaid Diagram ────────────────────────────────────────────────────────────

function generateMermaidReport(report: AnalysisReport): string {
  const lines: string[] = [];
  const { chain, tree, anomalies } = report;

  lines.push('```mermaid');
  lines.push('graph TD');
  lines.push('');

  // Style definitions
  lines.push('  classDef allow fill:#22c55e,stroke:#16a34a,color:#fff');
  lines.push('  classDef deny fill:#ef4444,stroke:#dc2626,color:#fff');
  lines.push('  classDef review fill:#eab308,stroke:#ca8a04,color:#fff');
  lines.push('  classDef ratelimited fill:#a855f7,stroke:#9333ea,color:#fff');
  lines.push('  classDef anomaly fill:#ff6b6b,stroke:#c0392b,color:#fff,stroke-width:3px');
  lines.push('');

  // Create node IDs (sanitize for mermaid)
  const nodeId = (receipt: Receipt): string =>
    receipt.id.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 20);

  // Anomalous receipt IDs
  const anomalousIds = new Set<string>();
  for (const a of anomalies) {
    for (const id of a.receiptIds) {
      anomalousIds.add(id);
    }
  }

  // Add nodes
  const sorted = [...chain].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
  );

  for (const receipt of sorted) {
    const id = nodeId(receipt);
    const time = formatTimestamp(receipt.timestamp);
    const label = `${time}\\n${receipt.action.type}\\n${receipt.decision.outcome.toUpperCase()}`;
    lines.push(`  ${id}["${label}"]`);

    // Apply class
    const cssClass = anomalousIds.has(receipt.id) ? 'anomaly' : receipt.decision.outcome.replace('require_approval', 'review').replace('rate_limited', 'ratelimited');
    lines.push(`  class ${id} ${cssClass}`);
  }

  lines.push('');

  // Add edges from tree structure
  function addEdges(node: TreeNode): void {
    for (const child of node.children) {
      const parentId = nodeId(node.receipt);
      const childId = nodeId(child.receipt);
      const edgeLabel = child.receipt.parent_receipt_id ? 'delegates' : 'next';
      lines.push(`  ${parentId} -->|${edgeLabel}| ${childId}`);
      addEdges(child);
    }
  }

  for (const root of report.tree) {
    addEdges(root);
  }

  // If tree is flat (no parent relationships), connect sequentially
  if (report.tree.length === sorted.length) {
    for (let i = 0; i < sorted.length - 1; i++) {
      lines.push(`  ${nodeId(sorted[i])} --> ${nodeId(sorted[i + 1])}`);
    }
  }

  lines.push('```');
  lines.push('');

  // Legend
  lines.push('**Legend:**');
  lines.push('- Green = ALLOW');
  lines.push('- Red = DENY');
  lines.push('- Yellow = REVIEW (require_approval)');
  lines.push('- Purple = RATE LIMITED');
  lines.push('- Red border = Anomaly detected');

  return lines.join('\n');
}

// ─── Helpers ────────────────────────────────────────────────────────────────────

function getOutcomeIcon(outcome: DecisionOutcome): string {
  switch (outcome) {
    case 'allow': return '\u2713';
    case 'deny': return '\u2717';
    case 'require_approval': return '\u23F3';
    case 'rate_limited': return '\u26A0';
  }
}

function getOutcomeColor(outcome: DecisionOutcome): string {
  switch (outcome) {
    case 'allow': return C.green;
    case 'deny': return C.red;
    case 'require_approval': return C.yellow;
    case 'rate_limited': return C.magenta;
  }
}

function formatTimestamp(timestamp: string): string {
  const d = new Date(timestamp);
  return d.toLocaleTimeString('en-US', { hour12: false });
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const m = Math.floor(ms / 60_000);
  const s = Math.round((ms % 60_000) / 1000);
  return `${m}m ${s}s`;
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen - 3) + '...';
}
