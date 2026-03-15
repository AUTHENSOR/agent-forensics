/**
 * Agent Forensics — Type definitions
 *
 * Compatible with Authensor receipt format.
 */

export interface ReceiptAction {
  type: string;
  resource: string;
  operation: string;
  parameters?: Record<string, unknown>;
}

export interface ReceiptPrincipal {
  type: string;
  id: string;
}

export type DecisionOutcome = 'allow' | 'deny' | 'require_approval' | 'rate_limited';

export interface ReceiptDecision {
  outcome: DecisionOutcome;
  reason?: string;
  approved_by?: string;
}

export interface ReceiptMatchedRule {
  id: string;
  name: string;
}

export interface Receipt {
  id: string;
  timestamp: string;
  receipt_hash: string;
  prev_receipt_hash: string | null;
  action: ReceiptAction;
  principal: ReceiptPrincipal;
  decision: ReceiptDecision;
  matched_rule?: ReceiptMatchedRule;
  evaluation_time_ms: number;
  parent_receipt_id?: string;
}

export interface ChainValidation {
  valid: boolean;
  totalReceipts: number;
  brokenLinks: BrokenLink[];
  orphanedReceipts: string[];
}

export interface BrokenLink {
  receiptId: string;
  expectedPrevHash: string | null;
  actualPrevHash: string | null;
  position: number;
}

export interface TreeNode {
  receipt: Receipt;
  children: TreeNode[];
  depth: number;
}

export type AnomalyType =
  | 'retry_after_denial'
  | 'timing_anomaly'
  | 'escalation_pattern'
  | 'chain_break'
  | 'rapid_fire'
  | 'action_outside_baseline'
  | 'privilege_escalation';

export interface Anomaly {
  type: AnomalyType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  receiptIds: string[];
  timestamp: string;
  details?: Record<string, unknown>;
}

export interface AnalysisReport {
  chain: Receipt[];
  integrity: ChainValidation;
  tree: TreeNode[];
  anomalies: Anomaly[];
  summary: ReportSummary;
}

export interface ReportSummary {
  totalReceipts: number;
  timeSpan: { start: string; end: string; durationMs: number };
  decisionCounts: Record<DecisionOutcome, number>;
  uniqueAgents: string[];
  uniqueActionTypes: string[];
  avgEvaluationTimeMs: number;
  maxChainDepth: number;
}

export type ReportFormat = 'terminal' | 'markdown' | 'json' | 'mermaid';
