// ============================================
// OFF-CHAIN THREAT INTELLIGENCE SIGNALS (OTTI)
// ============================================
// Main export file for the OTTI module.
//
// This module provides:
// - Off-chain threat signal types and interfaces
// - Service for querying and aggregating signals
// - Provider abstractions for modular intel sources
// - Scoring system (separate from on-chain risk)
//
// CORE PRINCIPLE:
// On-chain safety and off-chain risk are ALWAYS separated.
// Off-chain signals NEVER affect on-chain compromise status.

// Types
export * from './types';

// Service
export { OTTIService, getOTTIService, resetOTTIService } from './service';

// Providers
export * from './providers';

// ============================================
// QUICK START
// ============================================
// 
// import { getOTTIService, createMockProviders } from '@/lib/otti';
// 
// // Initialize service with mock providers (for development)
// const ottiService = getOTTIService();
// createMockProviders().forEach(p => ottiService.registerProvider(p));
// 
// // Assess an address
// const assessment = await ottiService.assessAddress('0x...', 'safe');
// 
// if (assessment.off_chain_risk_detected) {
//   console.log(assessment.summary.headline);
//   console.log(assessment.summary.explanation);
// }
