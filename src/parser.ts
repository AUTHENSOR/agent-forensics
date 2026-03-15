/**
 * Parser -- Reads Authensor receipt JSON and validates chain integrity.
 *
 * Handles both single receipt arrays and newline-delimited JSON.
 * Validates the hash chain to detect tampering.
 */

import { createHash } from 'node:crypto';
import { Receipt, ChainValidation, BrokenLink } from './types.js';

/**
 * Parse receipt data from a JSON string.
 * Supports both JSON array format and newline-delimited JSON (NDJSON).
 */
export function parseReceipts(data: string): Receipt[] {
  const trimmed = data.trim();

  // Try JSON array first
  if (trimmed.startsWith('[')) {
    const parsed = JSON.parse(trimmed) as unknown[];
    return parsed.map(validateReceiptShape);
  }

  // Try NDJSON (one receipt per line)
  const lines = trimmed.split('\n').filter((l) => l.trim().length > 0);
  return lines.map((line) => validateReceiptShape(JSON.parse(line)));
}

/**
 * Validate that an object has the expected receipt shape.
 */
function validateReceiptShape(obj: unknown): Receipt {
  if (typeof obj !== 'object' || obj === null) {
    throw new Error('Receipt must be a non-null object');
  }

  const r = obj as Record<string, unknown>;

  if (typeof r.id !== 'string') throw new Error(`Receipt missing 'id' field`);
  if (typeof r.timestamp !== 'string') throw new Error(`Receipt ${r.id}: missing 'timestamp'`);
  if (typeof r.receipt_hash !== 'string') throw new Error(`Receipt ${r.id}: missing 'receipt_hash'`);
  if (r.prev_receipt_hash !== null && typeof r.prev_receipt_hash !== 'string') {
    throw new Error(`Receipt ${r.id}: 'prev_receipt_hash' must be string or null`);
  }

  const action = r.action as Record<string, unknown> | undefined;
  if (!action || typeof action.type !== 'string' || typeof action.resource !== 'string' || typeof action.operation !== 'string') {
    throw new Error(`Receipt ${r.id}: invalid 'action' field`);
  }

  const principal = r.principal as Record<string, unknown> | undefined;
  if (!principal || typeof principal.type !== 'string' || typeof principal.id !== 'string') {
    throw new Error(`Receipt ${r.id}: invalid 'principal' field`);
  }

  const decision = r.decision as Record<string, unknown> | undefined;
  if (!decision || typeof decision.outcome !== 'string') {
    throw new Error(`Receipt ${r.id}: invalid 'decision' field`);
  }

  const validOutcomes = ['allow', 'deny', 'require_approval', 'rate_limited'];
  if (!validOutcomes.includes(decision.outcome as string)) {
    throw new Error(`Receipt ${r.id}: invalid outcome '${decision.outcome}'`);
  }

  if (typeof r.evaluation_time_ms !== 'number') {
    throw new Error(`Receipt ${r.id}: missing 'evaluation_time_ms'`);
  }

  return r as unknown as Receipt;
}

/**
 * Sort receipts by timestamp, preserving insertion order for equal timestamps.
 */
export function sortReceipts(receipts: Receipt[]): Receipt[] {
  return [...receipts].sort((a, b) => {
    const ta = new Date(a.timestamp).getTime();
    const tb = new Date(b.timestamp).getTime();
    return ta - tb;
  });
}

/**
 * Compute a receipt hash for verification.
 * Uses SHA-256 over canonical JSON of the receipt fields (excluding the hash itself).
 */
export function computeReceiptHash(receipt: Receipt): string {
  const payload = {
    id: receipt.id,
    timestamp: receipt.timestamp,
    prev_receipt_hash: receipt.prev_receipt_hash,
    action: receipt.action,
    principal: receipt.principal,
    decision: receipt.decision,
    matched_rule: receipt.matched_rule,
    evaluation_time_ms: receipt.evaluation_time_ms,
    parent_receipt_id: receipt.parent_receipt_id,
  };

  return createHash('sha256')
    .update(JSON.stringify(payload))
    .digest('hex');
}

/**
 * Validate the hash chain integrity of a receipt sequence.
 *
 * Checks:
 * 1. Each receipt's prev_receipt_hash points to the previous receipt's receipt_hash
 * 2. The first receipt has prev_receipt_hash === null
 * 3. No orphaned receipts (receipts referencing non-existent previous hashes)
 */
export function validateChain(receipts: Receipt[]): ChainValidation {
  if (receipts.length === 0) {
    return { valid: true, totalReceipts: 0, brokenLinks: [], orphanedReceipts: [] };
  }

  const sorted = sortReceipts(receipts);
  const hashSet = new Set(sorted.map((r) => r.receipt_hash));
  const brokenLinks: BrokenLink[] = [];
  const orphanedReceipts: string[] = [];

  for (let i = 0; i < sorted.length; i++) {
    const receipt = sorted[i];

    if (i === 0) {
      // First receipt should have null prev_receipt_hash
      if (receipt.prev_receipt_hash !== null) {
        // Check if the referenced hash exists in the chain
        if (!hashSet.has(receipt.prev_receipt_hash)) {
          orphanedReceipts.push(receipt.id);
        }
      }
      continue;
    }

    const prevReceipt = sorted[i - 1];

    // Check hash chain link
    if (receipt.prev_receipt_hash !== prevReceipt.receipt_hash) {
      // Could be a branch point (parent_receipt_id) or genuinely broken
      if (receipt.prev_receipt_hash !== null && !hashSet.has(receipt.prev_receipt_hash)) {
        brokenLinks.push({
          receiptId: receipt.id,
          expectedPrevHash: prevReceipt.receipt_hash,
          actualPrevHash: receipt.prev_receipt_hash,
          position: i,
        });
      } else if (receipt.prev_receipt_hash === null && i > 0) {
        // A null prev_receipt_hash mid-chain indicates a new chain start
        // This is valid for branching but worth noting
        orphanedReceipts.push(receipt.id);
      }
    }
  }

  return {
    valid: brokenLinks.length === 0,
    totalReceipts: receipts.length,
    brokenLinks,
    orphanedReceipts,
  };
}

/**
 * Group receipts by their chain (connected via prev_receipt_hash).
 * Returns an array of chains, each being an ordered array of receipts.
 */
export function groupByChain(receipts: Receipt[]): Receipt[][] {
  const sorted = sortReceipts(receipts);
  const hashToReceipt = new Map<string, Receipt>();
  const visited = new Set<string>();
  const chains: Receipt[][] = [];

  // Build hash lookup
  for (const r of sorted) {
    hashToReceipt.set(r.receipt_hash, r);
  }

  // Find chain roots (receipts with null prev_receipt_hash or missing prev)
  for (const r of sorted) {
    if (visited.has(r.id)) continue;

    if (r.prev_receipt_hash === null || !hashToReceipt.has(r.prev_receipt_hash)) {
      // This is a chain root
      const chain: Receipt[] = [];
      let current: Receipt | undefined = r;

      while (current && !visited.has(current.id)) {
        visited.add(current.id);
        chain.push(current);

        // Find the next receipt in the chain
        current = sorted.find(
          (s) => !visited.has(s.id) && s.prev_receipt_hash === current!.receipt_hash,
        );
      }

      if (chain.length > 0) {
        chains.push(chain);
      }
    }
  }

  // Collect any remaining unvisited receipts as individual chains
  for (const r of sorted) {
    if (!visited.has(r.id)) {
      visited.add(r.id);
      chains.push([r]);
    }
  }

  return chains;
}
