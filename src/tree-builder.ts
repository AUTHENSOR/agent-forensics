/**
 * TreeBuilder -- Reconstructs the full decision DAG from receipts.
 *
 * Handles parent-child relationships and branching agent delegations.
 * The resulting tree can have multiple roots (parallel agent chains).
 */

import { Receipt, TreeNode, ReportSummary, DecisionOutcome } from './types.js';
import { sortReceipts } from './parser.js';

/**
 * Build a decision tree (DAG) from a list of receipts.
 *
 * Uses parent_receipt_id for delegation relationships.
 * Falls back to prev_receipt_hash for sequential chains.
 */
export function buildTree(receipts: Receipt[]): TreeNode[] {
  if (receipts.length === 0) return [];

  const sorted = sortReceipts(receipts);
  const nodeMap = new Map<string, TreeNode>();
  const roots: TreeNode[] = [];

  // Create nodes for all receipts
  for (const receipt of sorted) {
    nodeMap.set(receipt.id, {
      receipt,
      children: [],
      depth: 0,
    });
  }

  // Build parent-child relationships
  for (const receipt of sorted) {
    const node = nodeMap.get(receipt.id)!;

    if (receipt.parent_receipt_id) {
      const parent = nodeMap.get(receipt.parent_receipt_id);
      if (parent) {
        parent.children.push(node);
        node.depth = parent.depth + 1;
        continue;
      }
    }

    // No parent_receipt_id or parent not found -- check prev_receipt_hash
    if (receipt.prev_receipt_hash !== null) {
      // Find the receipt with matching receipt_hash
      const prevReceipt = sorted.find((r) => r.receipt_hash === receipt.prev_receipt_hash);
      if (prevReceipt) {
        const parent = nodeMap.get(prevReceipt.id);
        if (parent) {
          parent.children.push(node);
          node.depth = parent.depth + 1;
          continue;
        }
      }
    }

    // This is a root node
    roots.push(node);
  }

  // Recompute depths via BFS from roots
  for (const root of roots) {
    computeDepths(root, 0);
  }

  return roots;
}

/**
 * Recursively compute depths for all nodes.
 */
function computeDepths(node: TreeNode, depth: number): void {
  node.depth = depth;
  for (const child of node.children) {
    computeDepths(child, depth + 1);
  }
}

/**
 * Get the maximum depth of the tree.
 */
export function getMaxDepth(roots: TreeNode[]): number {
  let max = 0;

  function walk(node: TreeNode): void {
    if (node.depth > max) max = node.depth;
    for (const child of node.children) {
      walk(child);
    }
  }

  for (const root of roots) {
    walk(root);
  }

  return max;
}

/**
 * Flatten the tree into a chronologically ordered list of receipts.
 */
export function flattenTree(roots: TreeNode[]): Receipt[] {
  const receipts: Receipt[] = [];

  function walk(node: TreeNode): void {
    receipts.push(node.receipt);
    for (const child of node.children) {
      walk(child);
    }
  }

  for (const root of roots) {
    walk(root);
  }

  return sortReceipts(receipts);
}

/**
 * Generate a summary of the receipt chain.
 */
export function summarize(receipts: Receipt[], roots: TreeNode[]): ReportSummary {
  if (receipts.length === 0) {
    return {
      totalReceipts: 0,
      timeSpan: { start: '', end: '', durationMs: 0 },
      decisionCounts: { allow: 0, deny: 0, require_approval: 0, rate_limited: 0 },
      uniqueAgents: [],
      uniqueActionTypes: [],
      avgEvaluationTimeMs: 0,
      maxChainDepth: 0,
    };
  }

  const sorted = sortReceipts(receipts);
  const start = sorted[0].timestamp;
  const end = sorted[sorted.length - 1].timestamp;
  const durationMs = new Date(end).getTime() - new Date(start).getTime();

  const decisionCounts: Record<DecisionOutcome, number> = {
    allow: 0,
    deny: 0,
    require_approval: 0,
    rate_limited: 0,
  };

  const agents = new Set<string>();
  const actionTypes = new Set<string>();
  let totalEvalTime = 0;

  for (const r of receipts) {
    decisionCounts[r.decision.outcome]++;
    agents.add(r.principal.id);
    actionTypes.add(r.action.type);
    totalEvalTime += r.evaluation_time_ms;
  }

  return {
    totalReceipts: receipts.length,
    timeSpan: { start, end, durationMs },
    decisionCounts,
    uniqueAgents: [...agents],
    uniqueActionTypes: [...actionTypes],
    avgEvaluationTimeMs: Math.round((totalEvalTime / receipts.length) * 100) / 100,
    maxChainDepth: getMaxDepth(roots),
  };
}
