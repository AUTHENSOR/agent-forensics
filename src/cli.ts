#!/usr/bin/env node

/**
 * Agent Forensics CLI
 *
 * Usage:
 *   agent-forensics analyze   --receipts <file>
 *   agent-forensics verify    --receipts <file>
 *   agent-forensics report    --receipts <file> --format <format>
 *   agent-forensics visualize --receipts <file>
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseReceipts, validateChain, sortReceipts } from './parser.js';
import { buildTree, summarize } from './tree-builder.js';
import { analyze, type AnalyzerOptions } from './analyzer.js';
import { generateReport } from './reporter.js';
import type { AnalysisReport, ReportFormat } from './types.js';

const VERSION = '0.1.0';

// ANSI helpers
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
};

function printUsage(): void {
  console.log(`
${C.bold}${C.cyan}Agent Forensics${C.reset} v${VERSION}
${C.dim}Black box recorder for AI agents${C.reset}

${C.bold}USAGE:${C.reset}
  agent-forensics <command> --receipts <file> [options]

${C.bold}COMMANDS:${C.reset}
  analyze     Analyze a receipt chain for anomalies
  verify      Validate hash chain integrity
  report      Generate an incident report
  visualize   Generate a Mermaid DAG diagram

${C.bold}OPTIONS:${C.reset}
  --receipts <file>    Path to receipt JSON file (required)
  --format <format>    Report format: terminal, markdown, json, mermaid
                       (default: terminal for analyze/report, mermaid for visualize)
  --version            Show version
  --help               Show this help message

${C.bold}EXAMPLES:${C.reset}
  ${C.dim}# Analyze a receipt chain${C.reset}
  npx agent-forensics analyze --receipts ./receipts.json

  ${C.dim}# Validate chain integrity${C.reset}
  npx agent-forensics verify --receipts ./receipts.json

  ${C.dim}# Generate markdown incident report${C.reset}
  npx agent-forensics report --receipts ./receipts.json --format markdown

  ${C.dim}# Visualize as Mermaid DAG${C.reset}
  npx agent-forensics visualize --receipts ./receipts.json
`);
}

function parseArgs(args: string[]): {
  command?: string;
  receiptsPath?: string;
  format?: ReportFormat;
  help: boolean;
  version: boolean;
} {
  const result: ReturnType<typeof parseArgs> = {
    help: false,
    version: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h') {
      result.help = true;
    } else if (arg === '--version' || arg === '-v') {
      result.version = true;
    } else if (arg === '--receipts' || arg === '-r') {
      result.receiptsPath = args[++i];
    } else if (arg === '--format' || arg === '-f') {
      const fmt = args[++i];
      if (!['terminal', 'markdown', 'json', 'mermaid'].includes(fmt)) {
        console.error(`${C.red}Error: Unknown format '${fmt}'. Use: terminal, markdown, json, mermaid${C.reset}`);
        process.exit(1);
      }
      result.format = fmt as ReportFormat;
    } else if (!arg.startsWith('-')) {
      result.command = arg;
    }
  }

  return result;
}

function loadReceipts(path: string): string {
  try {
    const absPath = resolve(path);
    return readFileSync(absPath, 'utf-8');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`${C.red}Error reading file: ${message}${C.reset}`);
    return process.exit(1) as never;
  }
}

function buildReport(data: string, analyzerOpts?: AnalyzerOptions): AnalysisReport {
  const receipts = parseReceipts(data);
  const sorted = sortReceipts(receipts);
  const integrity = validateChain(sorted);
  const tree = buildTree(sorted);
  const anomalies = analyze(sorted, integrity, analyzerOpts);
  const summary = summarize(sorted, tree);

  return { chain: sorted, integrity, tree, anomalies, summary };
}

// ─── Commands ───────────────────────────────────────────────────────────────────

function cmdAnalyze(receiptsPath: string, format?: ReportFormat): void {
  const data = loadReceipts(receiptsPath);
  const report = buildReport(data);
  const output = generateReport(report, format ?? 'terminal');
  console.log(output);

  // Exit with non-zero if anomalies found
  if (report.anomalies.length > 0) {
    process.exit(1);
  }
}

function cmdVerify(receiptsPath: string): void {
  const data = loadReceipts(receiptsPath);
  const receipts = parseReceipts(data);
  const sorted = sortReceipts(receipts);
  const validation = validateChain(sorted);

  console.log('');
  console.log(`${C.bold}${C.cyan}Agent Forensics \u2014 Chain Verification${C.reset}`);
  console.log(`${C.dim}\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501${C.reset}`);
  console.log('');
  console.log(`${C.bold}Receipts:${C.reset} ${validation.totalReceipts}`);

  if (validation.valid) {
    console.log(`${C.green}${C.bold}Status:${C.reset} ${C.green}\u2713 Chain integrity VALID${C.reset}`);
    console.log(`${C.green}All ${validation.totalReceipts} receipt hashes form a valid chain.${C.reset}`);
  } else {
    console.log(`${C.red}${C.bold}Status:${C.reset} ${C.red}\u2717 Chain integrity BROKEN${C.reset}`);
    console.log('');
    console.log(`${C.red}Broken links:${C.reset}`);

    for (const link of validation.brokenLinks) {
      console.log(`  ${C.red}\u2022 Receipt ${link.receiptId} at position ${link.position}${C.reset}`);
      console.log(`    Expected: ${link.expectedPrevHash}`);
      console.log(`    Actual:   ${link.actualPrevHash}`);
    }
  }

  if (validation.orphanedReceipts.length > 0) {
    console.log('');
    console.log(`${C.yellow}Orphaned receipts (new chain starts):${C.reset}`);
    for (const id of validation.orphanedReceipts) {
      console.log(`  ${C.yellow}\u2022 ${id}${C.reset}`);
    }
  }

  console.log('');

  if (!validation.valid) {
    process.exit(1);
  }
}

function cmdReport(receiptsPath: string, format?: ReportFormat): void {
  const data = loadReceipts(receiptsPath);
  const report = buildReport(data);
  const output = generateReport(report, format ?? 'markdown');
  console.log(output);
}

function cmdVisualize(receiptsPath: string): void {
  const data = loadReceipts(receiptsPath);
  const report = buildReport(data);
  const output = generateReport(report, 'mermaid');
  console.log(output);
}

// ─── Main ───────────────────────────────────────────────────────────────────────

function main(): void {
  const args = parseArgs(process.argv.slice(2));

  if (args.version) {
    console.log(`agent-forensics v${VERSION}`);
    return;
  }

  if (args.help || !args.command) {
    printUsage();
    return;
  }

  if (!args.receiptsPath) {
    console.error(`${C.red}Error: --receipts <file> is required${C.reset}`);
    process.exit(1);
    return;
  }

  const receiptsPath = args.receiptsPath;

  switch (args.command) {
    case 'analyze':
      cmdAnalyze(receiptsPath, args.format);
      break;
    case 'verify':
      cmdVerify(receiptsPath);
      break;
    case 'report':
      cmdReport(receiptsPath, args.format);
      break;
    case 'visualize':
      cmdVisualize(receiptsPath);
      break;
    default:
      console.error(`${C.red}Unknown command: ${args.command}${C.reset}`);
      printUsage();
      process.exit(1);
  }
}

main();
