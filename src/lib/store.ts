// ============================================
// GLOBAL STATE STORE
// ============================================
// Uses Zustand for lightweight state management

import { create } from 'zustand';
import { Chain, WalletAnalysisResult, MonitoringAlert } from '@/types';

interface AnalysisState {
  // Current analysis
  currentAddress: string | null;
  currentChain: Chain | null;
  analysisResult: WalletAnalysisResult | null;
  isLoading: boolean;
  error: string | null;

  // History
  analysisHistory: WalletAnalysisResult[];

  // Monitoring
  monitoringAlerts: MonitoringAlert[];
  isMonitoringActive: boolean;

  // Actions
  setCurrentAnalysis: (address: string, chain: Chain) => void;
  setAnalysisResult: (result: WalletAnalysisResult) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  resetAnalysis: () => void;
  addToHistory: (result: WalletAnalysisResult) => void;
  clearHistory: () => void;
  addMonitoringAlert: (alert: MonitoringAlert) => void;
  clearMonitoringAlerts: () => void;
  setMonitoringActive: (active: boolean) => void;
}

export const useAnalysisStore = create<AnalysisState>((set, get) => ({
  // Initial state
  currentAddress: null,
  currentChain: null,
  analysisResult: null,
  isLoading: false,
  error: null,
  analysisHistory: [],
  monitoringAlerts: [],
  isMonitoringActive: false,

  // Actions
  setCurrentAnalysis: (address, chain) => {
    set({
      currentAddress: address,
      currentChain: chain,
      error: null,
    });
  },

  setAnalysisResult: (result) => {
    set({ analysisResult: result });
    // Auto-add to history
    get().addToHistory(result);
  },

  setLoading: (loading) => {
    set({ isLoading: loading });
  },

  setError: (error) => {
    set({ error, isLoading: false });
  },

  resetAnalysis: () => {
    set({
      currentAddress: null,
      currentChain: null,
      analysisResult: null,
      isLoading: false,
      error: null,
    });
  },

  addToHistory: (result) => {
    const history = get().analysisHistory;
    // Keep only last 10 analyses
    const newHistory = [result, ...history.slice(0, 9)];
    set({ analysisHistory: newHistory });
  },

  clearHistory: () => {
    set({ analysisHistory: [] });
  },

  addMonitoringAlert: (alert) => {
    const alerts = get().monitoringAlerts;
    set({ monitoringAlerts: [alert, ...alerts] });
  },

  clearMonitoringAlerts: () => {
    set({ monitoringAlerts: [] });
  },

  setMonitoringActive: (active) => {
    set({ isMonitoringActive: active });
  },
}));

// Settings store for user preferences
interface SettingsState {
  // Display preferences
  showAdvancedDetails: boolean;
  darkMode: boolean; // Always true for this app
  
  // Notification preferences
  enableAlerts: boolean;
  alertSound: boolean;

  // Actions
  toggleAdvancedDetails: () => void;
  setEnableAlerts: (enabled: boolean) => void;
  setAlertSound: (enabled: boolean) => void;
}

export const useSettingsStore = create<SettingsState>((set, get) => ({
  showAdvancedDetails: false,
  darkMode: true,
  enableAlerts: true,
  alertSound: false,

  toggleAdvancedDetails: () => {
    set({ showAdvancedDetails: !get().showAdvancedDetails });
  },

  setEnableAlerts: (enabled) => {
    set({ enableAlerts: enabled });
  },

  setAlertSound: (enabled) => {
    set({ alertSound: enabled });
  },
}));










