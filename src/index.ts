/**
 * Agent Forensics — Black box recorder for AI agents.
 *
 * Reconstruct what happened. Find where it went wrong.
 *
 * @packageDocumentation
 */

export type {
  Receipt,
  ReceiptAction,
  ReceiptPrincipal,
  ReceiptDecision,
  ReceiptMatchedRule,
  DecisionOutcome,
  ChainValidation,
  BrokenLink,
  TreeNode,
  Anomaly,
  AnomalyType,
  AnalysisReport,
  ReportSummary,
  ReportFormat,
} from './types.js';

export {
  parseReceipts,
  sortReceipts,
  computeReceiptHash,
  validateChain,
  groupByChain,
} from './parser.js';

export {
  buildTree,
  getMaxDepth,
  flattenTree,
  summarize,
} from './tree-builder.js';

export {
  analyze,
} from './analyzer.js';
export type { AnalyzerOptions } from './analyzer.js';

export {
  generateReport,
} from './reporter.js';

import type { AnalysisReport, ReportFormat } from './types.js';
import type { AnalyzerOptions } from './analyzer.js';
import { parseReceipts, validateChain } from './parser.js';
import { buildTree, summarize } from './tree-builder.js';
import { analyze } from './analyzer.js';
import { generateReport } from './reporter.js';

/**
 * Full pipeline: parse, validate, build tree, analyze, report.
 */
export function forensicAnalysis(
  data: string,
  options?: {
    format?: ReportFormat;
    analyzerOptions?: AnalyzerOptions;
  },
): { report: AnalysisReport; formatted: string } {
  const receipts = parseReceipts(data);
  const integrity = validateChain(receipts);
  const roots = buildTree(receipts);
  const anomalies = analyze(receipts, integrity, options?.analyzerOptions);
  const summary = summarize(receipts, roots);

  const report: AnalysisReport = {
    chain: receipts,
    integrity,
    tree: roots,
    anomalies,
    summary,
  };

  const format = options?.format ?? 'terminal';
  const formatted = generateReport(report, format);

  return { report, formatted };
}
