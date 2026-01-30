// ============================================
// DETECTION ENGINE EXPORTS
// ============================================
// Complete detection system with false-positive prevention
//
// KEY RULE: DEX interaction alone ≠ compromise signal
// A wallet should NEVER be flagged as compromised solely for making
// a Uniswap transaction on any chain (Ethereum, Base, BNB, etc.)
//
// SECURITY FIX (2024-01): Added HARD OVERRIDE rule for drainer detection
// If ANY drainer signal is detected within 90 days, wallet MUST be classified
// as ACTIVE_COMPROMISE_DRAINER regardless of any other analysis.

// Core detection engine
export * from './detection-engine';

// CONTEXT CLASSIFIER (FALSE POSITIVE FIX 2024-01)
// PRE-FILTER that runs BEFORE drainer detection.
// Classifies wallet context to prevent false positives on:
// - DEX routers (1inch, Uniswap, CowSwap)
// - NFT marketplaces (OpenSea, Blur)
// - Privacy/rollup systems (Aztec, relayers)
// - Verified deployers, self-transfers, high-activity wallets
export * from './context-classifier';

// DRAINER ACTIVITY DETECTOR (REFACTORED 2024-01)
// Implements STRICT CRITERIA - ALL conditions must be met to flag as drainer:
// 1. Funds from MULTIPLE unrelated victims
// 2. Evidence of approval/signer compromise
// 3. Outflows to consolidation/laundering patterns
// 4. NO interaction with DEX/NFT/legitimate protocols
export * from './drainer-activity-detector';

// Malicious address database
export * from './malicious-database';

// Drainer address lists
export * from './drainer-addresses';

// Threat intelligence APIs
export * from './threat-intelligence';

// Safe contracts allowlist (prevents false positives)
export * from './safe-contracts';

// Contract classification (classify before flagging)
export * from './contract-classifier';

// Behavioral analysis (behavior-based detection)
export * from './behavior-analyzer';

// Transaction labeling (explicit LEGITIMATE vs SUSPICIOUS)
export * from './transaction-labeler';

// Conservative analyzer (maximum false-positive prevention)
export * from './conservative-analyzer';

// Infrastructure protection (DEX routers, bridges, marketplaces)
// CRITICAL: Provides chain-aware DEX allowlist for Base, Ethereum, BNB
export * from './infrastructure-protection';

// Solana-specific security detection (drainer/sweeper detection)
// THREE-STATE MODEL: SAFE, PREVIOUSLY_COMPROMISED, ACTIVELY_COMPROMISED
// DESIGN PHILOSOPHY: Prefer false negatives over false positives
export * from './solana-security';

// Base chain false-positive prevention
// Implements 6 rules for eliminating false positives:
// RULE 1: Whitelist core protocol interactions (Uniswap, ENS.base, bridges)
// RULE 2: Self-transfers are always safe
// RULE 3: Exchange wallet detection (CEX = reduce risk)
// RULE 4: Strict drainer/sweeper detection (ALL conditions required)
// RULE 5: "Previously Compromised" handling
// RULE 6: Risk scoring safeguards (Uniswap=0, ENS=0, Bridge≤1, Exchange=-)
export * from './base-chain-protection';

// ============================================
// BASE CHAIN SWEEPER BOT DETECTION (2026-01)
// ============================================
// Extends sweeper bot detection for Base chain specifics:
// - Sequencer-based ordering (no public mempool)
// - Same-block or near-zero-latency reactions
// - Gas price is NOT a reliable signal
// - Reaction-based detection instead of mempool signals
//
// HEURISTICS (≥2 must be true to flag):
// 1. Incoming → outgoing within ≤1 block
// 2. Never accumulates balance (ending balance ≈ 0)
// 3. Programmatic destination (fixed or rotating hot wallets)
// 4. Gas usage is flat and machine-consistent
// 5. Pattern repeats across many unrelated sender wallets
// 6. First action after funding is always drain
//
// FALSE-POSITIVE GUARDS:
// - Self-transfers, bridges, CEX deposits, legit contracts
// - Requires REPETITION + AUTOMATION (not single fast transfer)
export * from './base-sweeper-detector';

// ============================================
// THREE-STATE CLASSIFIER (2026-01 REDESIGN)
// ============================================
// Implements the redesigned compromise classification:
//
// 1. ACTIVELY_COMPROMISED (CRITICAL - RED)
//    - Confidence ≥ 80% required
//    - ONLY for wallets under ACTIVE attacker control
//    - Requires LIVE indicators (real-time sweep, ongoing drain)
//
// 2. HISTORICALLY_COMPROMISED (WARNING - ORANGE)
//    - Confidence 50-79%
//    - Past drainer interaction, attack has STOPPED
//    - No evidence of CURRENT attacker access
//    - Explicit message: "Previous compromise — no active control"
//
// 3. RISK_EXPOSURE (INFO - YELLOW)
//    - Confidence < 50%
//    - User error, voluntary interaction with suspicious addresses
//    - NOT called "compromised"
//
// CRITICAL RULES:
// - Historical signals NEVER trigger "ACTIVELY COMPROMISED"
// - First scan NEVER shows "ACTIVELY COMPROMISED" without live evidence
// - Confidence < 80% → DOWNGRADE to lower severity
export * from './three-state-classifier';
