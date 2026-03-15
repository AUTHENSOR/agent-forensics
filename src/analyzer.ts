/**
 * Analyzer — Identifies anomalies in receipt chains.
 *
 * Detects:
 * - Retry after denial (same action attempted multiple times after deny)
 * - Timing anomalies (unusual gaps or bursts)
 * - Escalation patterns (read -> write -> execute progression)
 * - Chain breaks (hash chain integrity failures)
 * - Rapid fire (many actions in short window)
 * - Privilege escalation (denied action followed by elevated attempts)
 */

import { Receipt, Anomaly, AnomalyType, ChainValidation } from './types.js';
import { sortReceipts } from './parser.js';

/** Configuration for anomaly detection thresholds. */
export interface AnalyzerOptions {
  /** Number of identical denied actions before flagging retry (default: 2) */
  retryThreshold?: number;
  /** Maximum gap in ms before flagging timing anomaly (default: 30000) */
  timingGapThresholdMs?: number;
  /** Minimum gap in ms — shorter gaps flagged as rapid fire (default: 100) */
  rapidFireThresholdMs?: number;
  /** Number of actions in rapid succession before flagging (default: 5) */
  rapidFireCount?: number;
}

const DEFAULT_OPTIONS: Required<AnalyzerOptions> = {
  retryThreshold: 2,
  timingGapThresholdMs: 30_000,
  rapidFireThresholdMs: 100,
  rapidFireCount: 5,
};

/** Operation privilege levels for escalation detection. */
const PRIVILEGE_LEVELS: Record<string, number> = {
  'read': 1,
  'list': 1,
  'get': 1,
  'query': 1,
  'search': 1,
  'write': 2,
  'create': 2,
  'update': 2,
  'put': 2,
  'send': 2,
  'delete': 3,
  'remove': 3,
  'execute': 4,
  'run': 4,
  'eval': 4,
  'admin': 5,
  'sudo': 5,
  'root': 5,
};

/**
 * Analyze a receipt chain for anomalies.
 */
export function analyze(
  receipts: Receipt[],
  chainValidation: ChainValidation,
  options?: AnalyzerOptions,
): Anomaly[] {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const sorted = sortReceipts(receipts);
  const anomalies: Anomaly[] = [];

  // Check chain integrity
  anomalies.push(...detectChainBreaks(chainValidation));

  // Behavioral anomalies
  anomalies.push(...detectRetryAfterDenial(sorted, opts));
  anomalies.push(...detectTimingAnomalies(sorted, opts));
  anomalies.push(...detectRapidFire(sorted, opts));
  anomalies.push(...detectEscalationPatterns(sorted));
  anomalies.push(...detectPrivilegeEscalation(sorted));

  // Sort anomalies by severity (critical first)
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };

  anomalies.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return anomalies;
}

/**
 * Detect chain integrity breaks.
 */
function detectChainBreaks(validation: ChainValidation): Anomaly[] {
  const anomalies: Anomaly[] = [];

  for (const link of validation.brokenLinks) {
    anomalies.push({
      type: 'chain_break',
      severity: 'critical',
      description: `Chain break at position ${link.position}: receipt ${link.receiptId} references hash ${link.actualPrevHash ?? 'null'} but expected ${link.expectedPrevHash ?? 'null'}. Possible tampering or data corruption.`,
      receiptIds: [link.receiptId],
      timestamp: new Date().toISOString(),
      details: {
        position: link.position,
        expectedPrevHash: link.expectedPrevHash,
        actualPrevHash: link.actualPrevHash,
      },
    });
  }

  return anomalies;
}

/**
 * Detect cases where a denied action was retried.
 */
function detectRetryAfterDenial(receipts: Receipt[], opts: Required<AnalyzerOptions>): Anomaly[] {
  const anomalies: Anomaly[] = [];

  // Group by action signature (type + resource + operation)
  const actionKey = (r: Receipt): string =>
    `${r.action.type}:${r.action.resource}:${r.action.operation}`;

  // Track denied actions and subsequent attempts
  const deniedActions = new Map<string, Receipt[]>();

  for (const receipt of receipts) {
    const key = actionKey(receipt);

    if (receipt.decision.outcome === 'deny') {
      if (!deniedActions.has(key)) {
        deniedActions.set(key, []);
      }
      deniedActions.get(key)!.push(receipt);
    }
  }

  // Find actions that were denied multiple times
  for (const [key, denials] of deniedActions) {
    if (denials.length >= opts.retryThreshold) {
      const [type, resource] = key.split(':');
      anomalies.push({
        type: 'retry_after_denial',
        severity: denials.length >= 3 ? 'high' : 'medium',
        description: `Retry after denial: ${type} ${resource} attempted ${denials.length}x (${formatTime(denials[0].timestamp)}). Possible: Agent retry loop on denied action.`,
        receiptIds: denials.map((d) => d.id),
        timestamp: denials[0].timestamp,
        details: {
          actionKey: key,
          attemptCount: denials.length,
          timestamps: denials.map((d) => d.timestamp),
        },
      });
    }
  }

  return anomalies;
}

/**
 * Detect unusual timing gaps between actions.
 */
function detectTimingAnomalies(receipts: Receipt[], opts: Required<AnalyzerOptions>): Anomaly[] {
  const anomalies: Anomaly[] = [];

  if (receipts.length < 2) return anomalies;

  // Calculate inter-action intervals
  const intervals: number[] = [];
  for (let i = 1; i < receipts.length; i++) {
    const gap = new Date(receipts[i].timestamp).getTime() - new Date(receipts[i - 1].timestamp).getTime();
    intervals.push(gap);
  }

  // Calculate mean and standard deviation
  const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
  const stdDev = Math.sqrt(variance);

  // Flag gaps that are more than 3 standard deviations from mean (or above threshold)
  for (let i = 0; i < intervals.length; i++) {
    const gap = intervals[i];

    if (gap > opts.timingGapThresholdMs && (stdDev === 0 || gap > mean + 3 * stdDev)) {
      const before = receipts[i];
      const after = receipts[i + 1];

      // Check if this is a review/approval gap (expected latency)
      const isApprovalGap =
        before.decision.outcome === 'require_approval' &&
        after.decision.outcome === 'allow' &&
        after.action.type === before.action.type &&
        after.action.resource === before.action.resource;

      anomalies.push({
        type: 'timing_anomaly',
        severity: isApprovalGap ? 'low' : 'medium',
        description: isApprovalGap
          ? `Timing anomaly: ${formatDuration(gap)} gap between ${before.action.type} REVIEW and APPROVAL. Expected: Human approval latency.`
          : `Timing anomaly: ${formatDuration(gap)} gap between actions at ${formatTime(before.timestamp)}. Average interval: ${formatDuration(mean)}.`,
        receiptIds: [before.id, after.id],
        timestamp: before.timestamp,
        details: {
          gapMs: gap,
          meanIntervalMs: Math.round(mean),
          stdDevMs: Math.round(stdDev),
          isApprovalGap,
        },
      });
    }
  }

  return anomalies;
}

/**
 * Detect rapid-fire action sequences.
 */
function detectRapidFire(receipts: Receipt[], opts: Required<AnalyzerOptions>): Anomaly[] {
  const anomalies: Anomaly[] = [];

  if (receipts.length < opts.rapidFireCount) return anomalies;

  let burstStart = 0;

  for (let i = 1; i < receipts.length; i++) {
    const gap = new Date(receipts[i].timestamp).getTime() - new Date(receipts[i - 1].timestamp).getTime();

    if (gap > opts.rapidFireThresholdMs) {
      // Check if burst window has enough actions
      const burstLength = i - burstStart;
      if (burstLength >= opts.rapidFireCount) {
        const burstReceipts = receipts.slice(burstStart, i);
        const burstDuration =
          new Date(burstReceipts[burstReceipts.length - 1].timestamp).getTime() -
          new Date(burstReceipts[0].timestamp).getTime();

        anomalies.push({
          type: 'rapid_fire',
          severity: burstLength >= 10 ? 'high' : 'medium',
          description: `Rapid fire: ${burstLength} actions in ${formatDuration(burstDuration)} starting at ${formatTime(burstReceipts[0].timestamp)}. Possible automated tool loop.`,
          receiptIds: burstReceipts.map((r) => r.id),
          timestamp: burstReceipts[0].timestamp,
          details: {
            actionCount: burstLength,
            durationMs: burstDuration,
            actionsPerSecond: burstDuration > 0 ? Math.round((burstLength / burstDuration) * 1000 * 10) / 10 : burstLength,
          },
        });
      }
      burstStart = i;
    }
  }

  // Check final window
  const finalBurstLength = receipts.length - burstStart;
  if (finalBurstLength >= opts.rapidFireCount) {
    const burstReceipts = receipts.slice(burstStart);
    const burstDuration =
      new Date(burstReceipts[burstReceipts.length - 1].timestamp).getTime() -
      new Date(burstReceipts[0].timestamp).getTime();

    anomalies.push({
      type: 'rapid_fire',
      severity: finalBurstLength >= 10 ? 'high' : 'medium',
      description: `Rapid fire: ${finalBurstLength} actions in ${formatDuration(burstDuration)} starting at ${formatTime(burstReceipts[0].timestamp)}.`,
      receiptIds: burstReceipts.map((r) => r.id),
      timestamp: burstReceipts[0].timestamp,
      details: {
        actionCount: finalBurstLength,
        durationMs: burstDuration,
      },
    });
  }

  return anomalies;
}

/**
 * Detect escalation patterns: read -> write(denied) -> write(denied) -> execute.
 */
function detectEscalationPatterns(receipts: Receipt[]): Anomaly[] {
  const anomalies: Anomaly[] = [];

  if (receipts.length < 3) return anomalies;

  // Track privilege level progression per agent
  const agentProgression = new Map<string, Array<{ level: number; receipt: Receipt }>>();

  for (const receipt of receipts) {
    const agentId = receipt.principal.id;
    if (!agentProgression.has(agentId)) {
      agentProgression.set(agentId, []);
    }

    const operation = receipt.action.operation.toLowerCase();
    const level = getPrivilegeLevel(operation);

    agentProgression.get(agentId)!.push({ level, receipt });
  }

  // Look for escalation sequences
  for (const [agentId, progression] of agentProgression) {
    if (progression.length < 3) continue;

    // Sliding window of 5 to find escalation
    for (let i = 0; i <= progression.length - 3; i++) {
      const window = progression.slice(i, Math.min(i + 5, progression.length));
      const levels = window.map((p) => p.level);

      // Check for strictly increasing privilege levels with at least 2 level jump
      const minLevel = Math.min(...levels);
      const maxLevel = Math.max(...levels);
      const hasDenials = window.some((p) => p.receipt.decision.outcome === 'deny');

      if (maxLevel - minLevel >= 2 && hasDenials) {
        // Check if levels are generally increasing
        let increasing = 0;
        for (let j = 1; j < levels.length; j++) {
          if (levels[j] > levels[j - 1]) increasing++;
        }

        if (increasing >= 2) {
          const ops = window.map(
            (p) =>
              `${p.receipt.action.operation}(${p.receipt.decision.outcome === 'deny' ? 'denied' : p.receipt.decision.outcome})`,
          );

          anomalies.push({
            type: 'escalation_pattern',
            severity: maxLevel >= 4 ? 'critical' : 'high',
            description: `Escalation pattern: ${ops.join(' -> ')}. Possible: Privilege escalation attempt by ${agentId}.`,
            receiptIds: window.map((p) => p.receipt.id),
            timestamp: window[0].receipt.timestamp,
            details: {
              agentId,
              operations: ops,
              privilegeLevels: levels,
              includesDenials: hasDenials,
            },
          });

          // Skip past this window to avoid duplicate detections
          i += window.length - 1;
        }
      }
    }
  }

  return anomalies;
}

/**
 * Detect privilege escalation: denied action followed by attempt at a higher-privilege resource.
 */
function detectPrivilegeEscalation(receipts: Receipt[]): Anomaly[] {
  const anomalies: Anomaly[] = [];

  // Sensitive resource patterns
  const sensitiveResources = [
    /\/etc\/(passwd|shadow|sudoers)/,
    /\/root\//,
    /\.ssh\//,
    /\.env/,
    /credentials/i,
    /secrets?/i,
    /token/i,
    /api[_-]?key/i,
  ];

  // Dangerous action patterns
  const dangerousActions = [
    /curl.*\|\s*sh/i,
    /bash.*-c/i,
    /eval\(/i,
    /exec\(/i,
    /rm\s+-rf/i,
    /chmod\s+777/i,
  ];

  for (const receipt of receipts) {
    const resource = receipt.action.resource;
    const params = JSON.stringify(receipt.action.parameters ?? {});

    const isSensitive = sensitiveResources.some((p) => p.test(resource));
    const isDangerous = dangerousActions.some((p) => p.test(resource) || p.test(params));

    if ((isSensitive || isDangerous) && receipt.decision.outcome === 'deny') {
      anomalies.push({
        type: 'privilege_escalation',
        severity: isDangerous ? 'critical' : 'high',
        description: `Blocked access to sensitive resource: ${receipt.action.type} ${resource}. ${receipt.decision.reason ?? 'Policy denied.'}`,
        receiptIds: [receipt.id],
        timestamp: receipt.timestamp,
        details: {
          resource,
          operation: receipt.action.operation,
          isSensitiveResource: isSensitive,
          isDangerousAction: isDangerous,
          reason: receipt.decision.reason,
        },
      });
    }
  }

  return anomalies;
}

/**
 * Get the privilege level for an operation.
 */
function getPrivilegeLevel(operation: string): number {
  const normalized = operation.toLowerCase();

  // Check exact matches
  if (PRIVILEGE_LEVELS[normalized] !== undefined) {
    return PRIVILEGE_LEVELS[normalized];
  }

  // Check partial matches
  for (const [key, level] of Object.entries(PRIVILEGE_LEVELS)) {
    if (normalized.includes(key)) return level;
  }

  return 1; // Default to lowest level
}

/**
 * Format a timestamp for display.
 */
function formatTime(timestamp: string): string {
  const d = new Date(timestamp);
  return d.toLocaleTimeString('en-US', { hour12: false });
}

/**
 * Format a duration in milliseconds to human-readable.
 */
function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3_600_000) {
    const m = Math.floor(ms / 60_000);
    const s = Math.round((ms % 60_000) / 1000);
    return `${m}m ${s}s`;
  }
  const h = Math.floor(ms / 3_600_000);
  const m = Math.round((ms % 3_600_000) / 60_000);
  return `${h}h ${m}m`;
}
