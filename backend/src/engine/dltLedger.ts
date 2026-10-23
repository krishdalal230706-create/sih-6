import crypto from 'crypto';
import { LedgerRecord } from '../types.js';
import { db } from '../models/db.js';
import { ledgerDb, computeBlockHash, computeSha256 } from '../db/ledgerDb.js';

export { computeBlockHash, computeSha256 };

export interface ChainVerificationResult {
  isVerified: boolean;
  brokenBlockNumber: number | null;
  errorType: 'NONE' | 'HASH_MISMATCH' | 'PREVIOUS_HASH_MISMATCH' | 'EMPTY_CHAIN';
  totalBlocksVerified: number;
  details: string;
  blockVerifications: Array<{
    blockNumber: number;
    isValid: boolean;
    hashMatches: boolean;
    linkageMatches: boolean;
  }>;
}

/**
 * Recomputes every block hash and checks SHA-256 hash-chain linkage sequentially.
 * Returns the exact first broken block if any tampering has occurred.
 */
export function verifyLedgerChain(): ChainVerificationResult {
  const blocks = ledgerDb.getAllBlocks();

  if (!blocks.length) {
    return {
      isVerified: false,
      brokenBlockNumber: null,
      errorType: 'EMPTY_CHAIN',
      totalBlocksVerified: 0,
      details: 'Ledger chain is empty.',
      blockVerifications: []
    };
  }

  const blockVerifications: ChainVerificationResult['blockVerifications'] = [];

  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i];
    const prevBlock = i > 0 ? blocks[i - 1] : null;

    // 1. Check previous hash linkage
    let linkageMatches = true;
    if (i === 0) {
      // Genesis block should have either 64 zeroes or valid parent
      if (!block.previousHash) {
        linkageMatches = false;
      }
    } else if (prevBlock && block.previousHash !== prevBlock.blockHash) {
      linkageMatches = false;
    }

    // 2. Recompute actual cryptographic SHA-256 hash
    const expectedHash = computeBlockHash(
      block.blockNumber,
      block.threatId,
      block.reporterOrg,
      block.patternHash,
      block.validators,
      block.timestamp,
      block.previousHash
    );

    const hashMatches = block.blockHash === expectedHash;
    const isValid = linkageMatches && hashMatches;

    blockVerifications.push({
      blockNumber: block.blockNumber,
      isValid,
      hashMatches,
      linkageMatches
    });

    if (!hashMatches) {
      return {
        isVerified: false,
        brokenBlockNumber: block.blockNumber,
        errorType: 'HASH_MISMATCH',
        totalBlocksVerified: i,
        details: `🚨 TAMPER DETECTED at Block #${block.blockNumber}: Recomputed SHA-256 hash (${expectedHash.slice(0, 12)}...) does not match stored block hash (${block.blockHash.slice(0, 12)}...). Data content has been altered!`,
        blockVerifications
      };
    }

    if (!linkageMatches) {
      return {
        isVerified: false,
        brokenBlockNumber: block.blockNumber,
        errorType: 'PREVIOUS_HASH_MISMATCH',
        totalBlocksVerified: i,
        details: `🚨 CHAIN LINKAGE SEVERED at Block #${block.blockNumber}: previousHash pointer (${block.previousHash.slice(0, 12)}...) does not match previous Block #${prevBlock?.blockNumber} hash (${prevBlock?.blockHash.slice(0, 12)}...).`,
        blockVerifications
      };
    }
  }

  return {
    isVerified: true,
    brokenBlockNumber: null,
    errorType: 'NONE',
    totalBlocksVerified: blocks.length,
    details: `✅ Blockchain integrity fully verified across all ${blocks.length} blocks. Cryptographic SHA-256 hashes and previousHash linkage intact.`,
    blockVerifications
  };
}

/**
 * Validates integrity for a specific block or whole chain context.
 */
export function verifyLedgerRecordIntegrity(blockNumber: number): {
  isVerified: boolean;
  hashVerified: boolean;
  reporterVerified: boolean;
  validationHistoryIntact: boolean;
  recordModified: boolean;
  brokenBlockNumber: number | null;
  details: string;
} {
  const blocks = ledgerDb.getAllBlocks();
  const index = blocks.findIndex((b) => b.blockNumber === blockNumber);

  if (index === -1) {
    return {
      isVerified: false,
      hashVerified: false,
      reporterVerified: false,
      validationHistoryIntact: false,
      recordModified: true,
      brokenBlockNumber: blockNumber,
      details: `Block #${blockNumber} not found on the DLT ledger.`
    };
  }

  const block = blocks[index];
  const expectedHash = computeBlockHash(
    block.blockNumber,
    block.threatId,
    block.reporterOrg,
    block.patternHash,
    block.validators,
    block.timestamp,
    block.previousHash
  );

  const hashVerified = block.blockHash === expectedHash;
  const prevBlock = index > 0 ? blocks[index - 1] : null;
  const linkageIntact = index === 0 ? Boolean(block.previousHash) : (prevBlock ? block.previousHash === prevBlock.blockHash : true);

  // Also check if any preceding block in chain was broken
  const chainResult = verifyLedgerChain();
  const precedingBroken = chainResult.brokenBlockNumber !== null && chainResult.brokenBlockNumber <= blockNumber;

  const isVerified = hashVerified && linkageIntact && !precedingBroken;

  return {
    isVerified,
    hashVerified,
    reporterVerified: Boolean(block.reporterOrg && block.validators.includes(block.reporterOrg)),
    validationHistoryIntact: linkageIntact && !precedingBroken,
    recordModified: !hashVerified,
    brokenBlockNumber: chainResult.brokenBlockNumber,
    details: isVerified
      ? `Block #${blockNumber} cryptographic hash verified against previous block hash (${block.previousHash.slice(0, 10)}...). Validator quorum of ${block.validators.length} signatures confirmed.`
      : !hashVerified
      ? `Block #${blockNumber} hash mismatch! Data has been modified without matching cryptographic signature.`
      : `Block #${blockNumber} chain linkage broken due to upstream alteration at Block #${chainResult.brokenBlockNumber}.`
  };
}

/**
 * Validator workflow status helper
 */
export function getValidatorStatus(validatorCount: number): 'REPORTED' | 'Verified by 1' | 'Verified by 3' | 'CONFIRMED' {
  if (validatorCount <= 1) return 'REPORTED';
  if (validatorCount === 2) return 'Verified by 1';
  if (validatorCount === 3) return 'Verified by 3';
  return 'CONFIRMED';
}

/**
 * Appends a new block to the real SHA-256 hash-chain and persists it to SQLite.
 */
export function addLedgerBlock(
  threatId: string,
  reporterOrg: string,
  patternHash: string,
  initialValidators?: string[],
  initialStatus?: string
): LedgerRecord {
  const blocks = ledgerDb.getAllBlocks();
  const previousBlock = blocks[blocks.length - 1];

  const newBlockNumber = previousBlock ? previousBlock.blockNumber + 1 : 10000;
  const previousHash = previousBlock
    ? previousBlock.blockHash
    : '0000000000000000000000000000000000000000000000000000000000000000';

  const validators = initialValidators || [reporterOrg, 'City Hospital', 'State University'];
  const status = initialStatus || (validators.length >= 3 ? 'CONFIRMED' : getValidatorStatus(validators.length));
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);

  const blockHash = computeBlockHash(
    newBlockNumber,
    threatId,
    reporterOrg,
    patternHash,
    validators,
    timestamp,
    previousHash
  );

  const newBlock: LedgerRecord = {
    blockNumber: newBlockNumber,
    threatId,
    reporterOrg,
    validators,
    status: status as any,
    timestamp,
    patternHash,
    previousHash,
    blockHash
  };

  ledgerDb.insertBlock(newBlock);
  db.ledgerRecords = ledgerDb.getAllBlocks();

  return newBlock;
}

/**
 * Progresses validator consensus workflow: Reported -> Verified by 1 -> Verified by 3 -> CONFIRMED
 */
export function advanceBlockValidation(blockNumber: number, validatorOrg: string): LedgerRecord | null {
  const blocks = ledgerDb.getAllBlocks();
  const block = blocks.find((b) => b.blockNumber === blockNumber);
  if (!block) return null;

  if (!block.validators.includes(validatorOrg)) {
    block.validators.push(validatorOrg);
  }

  // Update status based on validator count
  if (block.validators.length === 1) {
    block.status = 'REPORTED' as any;
  } else if (block.validators.length === 2) {
    block.status = 'Verified by 1' as any;
  } else if (block.validators.length === 3) {
    block.status = 'Verified by 3' as any;
  } else {
    block.status = 'CONFIRMED' as any;
  }

  // Recompute block hash with updated validators
  block.blockHash = computeBlockHash(
    block.blockNumber,
    block.threatId,
    block.reporterOrg,
    block.patternHash,
    block.validators,
    block.timestamp,
    block.previousHash
  );

  ledgerDb.updateBlock(block);
  db.ledgerRecords = ledgerDb.getAllBlocks();

  return block;
}

/**
 * Maliciously alters a stored record in SQLite to demonstrate real cryptographic tamper detection.
 */
export function tamperLedgerRecord(
  blockNumber: number = 10420,
  newThreatId: string = 'TH-TAMPERED-4019-EXPLOIT'
): {
  success: boolean;
  tamperedBlock: LedgerRecord | null;
  message: string;
} {
  const tampered = ledgerDb.tamperBlock(blockNumber, newThreatId);
  if (!tampered) {
    return {
      success: false,
      tamperedBlock: null,
      message: `Block #${blockNumber} could not be found for tampering.`
    };
  }

  db.ledgerRecords = ledgerDb.getAllBlocks();

  return {
    success: true,
    tamperedBlock: tampered,
    message: `Malicious alteration injected into Block #${blockNumber}. Threat ID mutated to "${newThreatId}" without valid SHA-256 recomputation.`
  };
}

/**
 * Restores pristine baseline ledger blocks and validates whole chain.
 */
export function restoreLedgerBaseline(): LedgerRecord[] {
  const baseline = ledgerDb.resetToBaseline();
  db.ledgerRecords = baseline;
  return baseline;
}
