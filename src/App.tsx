/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { PyQtWindowFrame } from './components/PyQtWindowFrame';
import { RecoveryDomainView } from './components/RecoveryDomainView';
import { SanitizationDomainView } from './components/SanitizationDomainView';
import { AuditLogView } from './components/AuditLogView';
import { PythonSourceHub } from './components/PythonSourceHub';
import { AIChatbotDock } from './components/AIChatbotDock';
import { INITIAL_DEVICES, INITIAL_ARTIFACTS, INITIAL_AUDIT_LOGS } from './data/mockForensicData';
import { StorageDevice, RecoveredArtifact, AuditLogEntry, SanitizationResult, AIActionPlan } from './types/forensic';

export default function App() {
  const [devices, setDevices] = useState<StorageDevice[]>(INITIAL_DEVICES);
  const [selectedDevice, setSelectedDevice] = useState<StorageDevice>(INITIAL_DEVICES[0]);
  const [artifacts, setArtifacts] = useState<RecoveredArtifact[]>(INITIAL_ARTIFACTS);
  const [logs, setLogs] = useState<AuditLogEntry[]>(INITIAL_AUDIT_LOGS);

  const [activeDomain, setActiveDomain] = useState<'RECOVERY' | 'SANITIZATION' | 'AUDIT' | 'PYTHON_SOURCE' | 'AI_ASSISTANT'>('RECOVERY');
  const [isAIDockOpen, setIsAIDockOpen] = useState(false);
  const [quickPromptText, setQuickPromptText] = useState<string | undefined>(undefined);

  // Toggle hardware/logical write-blocker on selected storage media
  const toggleWriteBlocker = () => {
    setSelectedDevice((prev) => {
      const updated = { ...prev, writeBlockerActive: !prev.writeBlockerActive };
      setDevices((dList) => dList.map((d) => (d.id === prev.id ? updated : d)));
      return updated;
    });
  };

  const handleSelectDevice = (device: StorageDevice) => {
    setSelectedDevice(device);
  };

  // Called when forensic recovery pipeline completes
  const handleRecoveryComplete = (newArtifacts: RecoveredArtifact[], preHash: string, postHash: string) => {
    setArtifacts(newArtifacts);

    const newLog: AuditLogEntry = {
      id: `LOG-${Date.now().toString().slice(-4)}`,
      operationId: `REC-${Date.now().toString().slice(-6)}`,
      timestamp: new Date().toUTCString(),
      domain: 'RECOVERY',
      deviceModel: selectedDevice.model,
      devicePath: selectedDevice.path,
      pipelineOrStandard: 'Sleuth Kit (fls/tsk_recover) + Foremost File Carver',
      preSha256: preHash,
      postSha256: postHash,
      status: 'PASSED (Read-Only Preserved)',
      caseRef: 'CASE-2026-DFIR-001',
      operator: 'EXAMINER-409',
      artifactsCount: newArtifacts.length,
    };

    setLogs((prev) => [newLog, ...prev]);
  };

  // Called when NIST sanitization completes
  const handleSanitizationComplete = (result: SanitizationResult) => {
    const newLog: AuditLogEntry = {
      id: `LOG-${Date.now().toString().slice(-4)}`,
      operationId: result.operationId,
      timestamp: result.timestamp,
      domain: 'SANITIZATION',
      deviceModel: selectedDevice.model,
      devicePath: selectedDevice.path,
      pipelineOrStandard: result.standardApplied,
      preSha256: result.preWipeSha256,
      postSha256: result.postWipeSha256,
      status: result.verificationStatus,
      caseRef: 'DECOMMISSION-2026-NIST-042',
      operator: 'SEC-ADMIN-01',
    };

    setLogs((prev) => [newLog, ...prev]);
  };

  // Execute structured AI Action Plan
  const handleExecuteAIPlan = (plan: AIActionPlan) => {
    if (plan.domain === 'RECOVERY') {
      setActiveDomain('RECOVERY');
      // Ensure write-blocker is locked for safety
      if (!selectedDevice.writeBlockerActive) {
        toggleWriteBlocker();
      }
    } else if (plan.domain === 'SANITIZATION') {
      setActiveDomain('SANITIZATION');
      // For sanitization, write-blocker must be disengaged
      if (selectedDevice.writeBlockerActive) {
        toggleWriteBlocker();
      }
    }
  };

  const handleOpenQuickPlan = (prompt: string) => {
    setQuickPromptText(prompt);
    setActiveDomain('AI_ASSISTANT');
  };

  return (
    <PyQtWindowFrame
      activeDomain={activeDomain}
      setActiveDomain={setActiveDomain}
      devices={devices}
      selectedDevice={selectedDevice}
      onSelectDevice={handleSelectDevice}
      toggleWriteBlocker={toggleWriteBlocker}
      toggleAIDock={() => setIsAIDockOpen(!isAIDockOpen)}
      isAIDockOpen={isAIDockOpen}
      onOpenQuickPlan={handleOpenQuickPlan}
    >
      {/* Domain Content Views */}
      <div className="flex-1 flex overflow-hidden">
        {activeDomain === 'RECOVERY' && (
          <RecoveryDomainView
            devices={devices}
            selectedDevice={selectedDevice}
            onSelectDevice={handleSelectDevice}
            artifacts={artifacts}
            onRecoveryComplete={handleRecoveryComplete}
            onOpenQuickAIPlan={handleOpenQuickPlan}
          />
        )}

        {activeDomain === 'SANITIZATION' && (
          <SanitizationDomainView
            devices={devices}
            selectedDevice={selectedDevice}
            onSelectDevice={handleSelectDevice}
            onSanitizationComplete={handleSanitizationComplete}
            toggleWriteBlocker={toggleWriteBlocker}
            onOpenQuickAIPlan={handleOpenQuickPlan}
          />
        )}

        {activeDomain === 'AI_ASSISTANT' && (
          <AIChatbotDock
            isOpen={true}
            isFullPage={true}
            activeDomain="Smart AI Assistant & Web Search"
            selectedDevice={selectedDevice}
            onExecutePlan={handleExecuteAIPlan}
            quickPromptText={quickPromptText}
            clearQuickPrompt={() => setQuickPromptText(undefined)}
          />
        )}

        {activeDomain === 'AUDIT' && (
          <AuditLogView
            logs={logs}
            selectedDevice={selectedDevice}
            artifacts={artifacts}
          />
        )}

        {activeDomain === 'PYTHON_SOURCE' && <PythonSourceHub />}
      </div>

      {/* Dockable AI Copilot Panel (when not on full AI view and toggled open) */}
      {activeDomain !== 'AI_ASSISTANT' && (
        <AIChatbotDock
          isOpen={isAIDockOpen}
          onClose={() => setIsAIDockOpen(false)}
          activeDomain={
            activeDomain === 'RECOVERY'
              ? 'Digital Forensic Recovery Domain'
              : activeDomain === 'SANITIZATION'
              ? 'Secure Data Sanitization Domain (NIST 800-88)'
              : 'Operations & Audit'
          }
          selectedDevice={selectedDevice}
          onExecutePlan={handleExecuteAIPlan}
          quickPromptText={quickPromptText}
          clearQuickPrompt={() => setQuickPromptText(undefined)}
        />
      )}
    </PyQtWindowFrame>
  );
}
