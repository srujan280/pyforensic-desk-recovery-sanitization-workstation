import React, { useState } from 'react';
import {
  Trash2,
  AlertOctagon,
  HardDrive,
  Lock,
  Unlock,
  ShieldAlert,
  CheckCircle2,
  Download,
  Flame,
  Zap,
  Activity,
  FileCheck,
  ShieldCheck,
  Sparkles,
  Info,
  Shield,
} from 'lucide-react';
import { StorageDevice, SanitizationResult } from '../types/forensic';
import { generateSanitizationCertificatePDF } from '../utils/pdfCertificate';

interface SanitizationDomainViewProps {
  devices: StorageDevice[];
  selectedDevice: StorageDevice;
  onSelectDevice: (device: StorageDevice) => void;
  onSanitizationComplete: (result: SanitizationResult) => void;
  toggleWriteBlocker: () => void;
  onOpenQuickAIPlan: (prompt: string) => void;
}

export const SanitizationDomainView: React.FC<SanitizationDomainViewProps> = ({
  devices,
  selectedDevice,
  onSelectDevice,
  onSanitizationComplete,
  toggleWriteBlocker,
  onOpenQuickAIPlan,
}) => {
  const [selectedStandard, setSelectedStandard] = useState('NIST SP 800-88 Rev. 1 Purge (3-Pass Multi-Sector Overwrite)');
  const [wipeMft, setWipeMft] = useState(true);
  const [wipeSlack, setWipeSlack] = useState(true);

  // Safety Confirmation Modal state
  const [isConfirmModalOpen, setIsConfirmModalOpen] = useState(false);
  const [confirmPhraseInput, setConfirmPhraseInput] = useState('');
  const [ackPermanentLoss, setAckPermanentLoss] = useState(false);
  const [ackDecommissionAuth, setAckDecommissionAuth] = useState(false);

  // Overwriting Execution State
  const [isWiping, setIsWiping] = useState(false);
  const [wipeProgress, setWipeProgress] = useState(0);
  const [currentPass, setCurrentPass] = useState(1);
  const [totalPasses, setTotalPasses] = useState(3);
  const [entropy, setEntropy] = useState(7.8542);
  const [wipeStatusText, setWipeStatusText] = useState('Awaiting authorization.');
  const [activeWipeSector, setActiveWipeSector] = useState(0);
  const [throughputMbps, setThroughputMbps] = useState(485);

  const [sanitizationResult, setSanitizationResult] = useState<SanitizationResult | null>(null);

  const startWipePipeline = () => {
    setIsConfirmModalOpen(false);
    setIsWiping(true);
    setWipeProgress(0);
    setCurrentPass(1);
    const passes = selectedStandard.includes('Clear') ? 1 : 3;
    setTotalPasses(passes);

    const preHash = '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069';
    let pct = 0;

    const interval = setInterval(() => {
      pct += 4;
      setWipeProgress(pct);
      setActiveWipeSector((prev) => (prev + 5) % 120);

      // Multi-pass simulation
      if (pct < 33) {
        setCurrentPass(1);
        setWipeStatusText('Pass 1/3: Overwriting all addressable sectors with binary zeros (0x00)...');
        setEntropy(0.0);
        setThroughputMbps(512);
      } else if (pct < 66 && passes > 1) {
        setCurrentPass(2);
        setWipeStatusText('Pass 2/3: Overwriting sectors with binary ones (0xFF complement)...');
        setEntropy(0.0);
        setThroughputMbps(490);
      } else if (pct < 90 && passes > 1) {
        setCurrentPass(3);
        setWipeStatusText('Pass 3/3: Overwriting sectors with Cryptographic PRNG random stream...');
        setEntropy(7.9942);
        setThroughputMbps(470);
      } else if (pct >= 90 && pct < 100) {
        setWipeStatusText('NIST Verification Phase: Reading all sectors to ensure zero-entropy compliance...');
        setEntropy(0.0);
      } else if (pct >= 100) {
        clearInterval(interval);
        setIsWiping(false);
        setWipeProgress(100);
        setWipeStatusText('Sanitization complete! Verified 100% zero-entropy & NIST SP 800-88 compliant.');
        setEntropy(0.0);

        const postHash =
          passes > 1
            ? '0000000000000000000000000000000000000000000000000000000000000000'
            : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

        const result: SanitizationResult = {
          operationId: `SAN-${Date.now().toString().slice(-6)}`,
          targetDevice: `${selectedDevice.model} (${selectedDevice.path})`,
          standardApplied: selectedStandard,
          passesCompleted: passes,
          totalBytesWiped: selectedDevice.capacityBytes,
          preWipeSha256: preHash,
          postWipeSha256: postHash,
          verificationStatus: 'PASSED (NIST SP 800-88 Compliant - 0% Recoverable)',
          metadataWiped: wipeMft,
          unallocatedWiped: wipeSlack,
          executionTimeSeconds: 14.8,
          timestamp: new Date().toUTCString(),
          entropy: 0.0,
        };

        setSanitizationResult(result);
        onSanitizationComplete(result);
      }
    }, 120);
  };

  return (
    <div className="flex-1 flex flex-col h-full overflow-y-auto p-4 space-y-4 bg-slate-950">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Trash2 className="w-4 h-4 text-rose-400" />
              <span>Secure Data Sanitization &amp; Media Destruction (NIST SP 800-88)</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Irreversible cryptographic overwrite and metadata obliteration to ensure zero data recovery upon media disposal.
            </p>
          </div>

          <button
            onClick={() => onOpenQuickAIPlan('Explain NIST SP 800-88 Clear vs Purge requirements and which one I should use')}
            className="px-3 py-1.5 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5 text-sky-400" />
            <span>Consult AI Sanitization Advisor</span>
          </button>
        </div>

        {/* Device Selection Cards */}
        <div className="space-y-2">
          <div className="text-xs font-semibold text-slate-300">
            Step 1: Select Drive to Sanitize
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {devices.map((dev) => (
              <div
                key={dev.id}
                onClick={() => onSelectDevice(dev)}
                className={`p-3 rounded-xl border cursor-pointer transition-all ${
                  selectedDevice.id === dev.id
                    ? 'bg-rose-950/30 border-rose-500 text-white shadow-md shadow-rose-950/40'
                    : 'bg-slate-950/70 border-slate-800 hover:border-slate-700 text-slate-300'
                }`}
              >
                <div className="flex items-start justify-between">
                  <HardDrive className={`w-4 h-4 mt-0.5 ${selectedDevice.id === dev.id ? 'text-rose-400' : 'text-slate-400'}`} />
                  <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-slate-900 border border-slate-800 text-slate-300 font-mono">
                    {(dev.capacityBytes / 1024 ** 3).toFixed(0)} GB
                  </span>
                </div>
                <div className="font-semibold text-xs mt-2 truncate">{dev.model}</div>
                <div className="text-[11px] text-slate-400 font-mono mt-0.5">{dev.path}</div>
                <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-400">
                  <span>{dev.filesystem}</span>
                  <span className="text-rose-400 font-semibold">{dev.partitionTable}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Safety Interlock Check Card */}
      <div
        className={`p-4 rounded-2xl border transition-all ${
          selectedDevice.writeBlockerActive
            ? 'bg-amber-950/20 border-amber-500/60 text-amber-200'
            : 'bg-rose-950/30 border-rose-500 text-rose-200 shadow-md shadow-rose-950/30'
        }`}
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-start gap-3">
            <div className={`p-2 rounded-xl mt-0.5 ${selectedDevice.writeBlockerActive ? 'bg-amber-500/20' : 'bg-rose-500/20'}`}>
              {selectedDevice.writeBlockerActive ? (
                <Lock className="w-5 h-5 text-amber-400" />
              ) : (
                <Unlock className="w-5 h-5 text-rose-400 animate-pulse" />
              )}
            </div>
            <div>
              <div className="font-bold text-sm">
                {selectedDevice.writeBlockerActive
                  ? 'Hardware Write-Blocker is Currently Locked (Read-Only)'
                  : 'Write-Blocker Disengaged: Direct Sector Write Mode Active'}
              </div>
              <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                {selectedDevice.writeBlockerActive
                  ? 'Sanitization requires direct physical write access to overwrite disk sectors. To proceed, unlock the write-blocker below.'
                  : 'Safety lock is disabled. The forensic engine has direct sector authorization to wipe all logical and physical structures.'}
              </p>
            </div>
          </div>

          <button
            onClick={toggleWriteBlocker}
            className={`px-4 py-2 rounded-xl text-xs font-bold transition-all shadow-md ${
              selectedDevice.writeBlockerActive
                ? 'bg-amber-500 hover:bg-amber-400 text-slate-950'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700'
            }`}
          >
            {selectedDevice.writeBlockerActive ? 'Unlock Write-Blocker for Sanitization' : 'Re-Lock Write-Blocker'}
          </button>
        </div>
      </div>

      {/* Step 2: Choose Overwrite Standard */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm space-y-3">
        <div className="text-xs font-semibold text-white">Step 2: Choose Sanitization Method</div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {[
            {
              id: 'NIST SP 800-88 Rev. 1 Purge (3-Pass Multi-Sector Overwrite)',
              name: 'NIST SP 800-88 Purge',
              badge: 'Recommended for Decommission',
              badgeColor: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
              desc: '3-Pass Overwrite: 0x00 binary zeros, 0xFF binary ones, and Cryptographic PRNG stream with full read verification.',
              idealFor: 'Device disposal, donation, or high-security sanitization.',
            },
            {
              id: 'NIST SP 800-88 Rev. 1 Clear (Single-Pass Logical Overwrite)',
              name: 'NIST SP 800-88 Clear',
              badge: 'Fast Re-use',
              badgeColor: 'bg-sky-500/20 text-sky-300 border-sky-500/30',
              desc: 'Single-pass logical pseudo-random or zero overwrite across all addressable sectors with verification.',
              idealFor: 'Internal redeployment within the same organization.',
            },
            {
              id: 'DoD 5220.22-M (3-Pass Military Sanitization)',
              name: 'DoD 5220.22-M',
              badge: 'Military Standard',
              badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
              desc: '3-pass overwrite with a fixed character, complement, and random stream with verification read.',
              idealFor: 'Contractual legacy defense compliance specifications.',
            },
          ].map((std) => (
            <div
              key={std.id}
              onClick={() => setSelectedStandard(std.id)}
              className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                selectedStandard === std.id
                  ? 'bg-rose-600/10 border-rose-500 text-white shadow-md shadow-rose-950/30'
                  : 'bg-slate-950/70 border-slate-800 hover:border-slate-700 text-slate-300'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-xs">{std.name}</span>
                <span className={`text-[10px] px-2 py-0.5 rounded-full border font-semibold ${std.badgeColor}`}>
                  {std.badge}
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed mb-2">{std.desc}</p>
              <div className="text-[11px] text-slate-500 pt-2 border-t border-slate-800/80">
                <strong>Ideal for:</strong> {std.idealFor}
              </div>
            </div>
          ))}
        </div>

        {/* Toggles & Big Action Button */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800 text-xs">
          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2 cursor-pointer text-slate-200">
              <input
                type="checkbox"
                checked={wipeMft}
                onChange={(e) => setWipeMft(e.target.checked)}
                className="rounded border-slate-700 text-rose-500 focus:ring-0"
              />
              <span>Obliterate MFT records, GPT/MBR partition tables &amp; directory structures</span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer text-slate-200">
              <input
                type="checkbox"
                checked={wipeSlack}
                onChange={(e) => setWipeSlack(e.target.checked)}
                className="rounded border-slate-700 text-rose-500 focus:ring-0"
              />
              <span>Wipe unallocated slack space</span>
            </label>
          </div>

          <button
            onClick={() => {
              if (selectedDevice.writeBlockerActive) {
                alert('Write-Blocker is ACTIVE! Please unlock the write-blocker above before sanitization.');
                return;
              }
              setIsConfirmModalOpen(true);
            }}
            disabled={isWiping}
            className={`px-5 py-2.5 rounded-xl text-xs font-bold flex items-center gap-2 shadow-lg transition-all ${
              selectedDevice.writeBlockerActive
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                : isWiping
                ? 'bg-rose-900 text-slate-300 cursor-not-allowed'
                : 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-600/30'
            }`}
          >
            <Flame className="w-4 h-4" />
            <span>{isWiping ? 'Wiping Media Sectors...' : 'Execute NIST Secure Destruction'}</span>
          </button>
        </div>
      </div>

      {/* Progress & Live Telemetry Monitor */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm space-y-3">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-white font-bold flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${isWiping ? 'bg-rose-500 animate-pulse' : 'bg-slate-600'}`} />
            {wipeStatusText}
          </span>
          <span className="text-rose-400 font-bold">{wipeProgress}%</span>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-slate-950 rounded-full h-3 overflow-hidden border border-slate-800">
          <div
            className="bg-gradient-to-r from-amber-500 to-rose-600 h-full transition-all duration-150"
            style={{ width: `${wipeProgress}%` }}
          />
        </div>

        {/* Telemetry Row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
          <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800">
            <div className="text-[10px] text-slate-400">Current Overwrite Pass:</div>
            <div className="text-white font-bold mt-0.5">
              Pass {currentPass} of {totalPasses}
            </div>
          </div>

          <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800">
            <div className="text-[10px] text-slate-400">Shannon Sector Entropy:</div>
            <div className={`font-bold mt-0.5 ${entropy === 0 ? 'text-emerald-400' : 'text-amber-400'}`}>
              {entropy.toFixed(4)} bits/byte
            </div>
          </div>

          <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800">
            <div className="text-[10px] text-slate-400">Write Throughput:</div>
            <div className="text-sky-300 font-bold mt-0.5">{throughputMbps} MB/s</div>
          </div>

          <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800">
            <div className="text-[10px] text-slate-400">Verification Status:</div>
            <div className="text-emerald-400 font-bold mt-0.5 truncate">
              {wipeProgress === 100 ? '100% UNIFORMITY CONFIRMED' : isWiping ? 'ACTIVE WIPE' : 'IDLE'}
            </div>
          </div>
        </div>
      </div>

      {/* Certificate Banner when Finished */}
      {sanitizationResult && (
        <div className="bg-slate-900 border border-rose-500/50 rounded-2xl p-4 shadow-xl shadow-rose-950/30 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center">
              <CheckCircle2 className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <div className="font-bold text-sm text-white">
                NIST SP 800-88 Rev. 1 Sanitization Verified &amp; Certified
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5">
                Certificate ID: {sanitizationResult.operationId} • Pre-Wipe: {sanitizationResult.preWipeSha256.substring(0, 16)}... • Post-Wipe: {sanitizationResult.postWipeSha256.substring(0, 16)}...
              </div>
            </div>
          </div>

          <button
            onClick={() => generateSanitizationCertificatePDF(sanitizationResult, selectedDevice)}
            className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-bold flex items-center gap-2 shadow-lg shadow-rose-600/30 transition-all"
          >
            <Download className="w-4 h-4" />
            <span>Download Official Destruction Certificate (PDF)</span>
          </button>
        </div>
      )}

      {/* Safety Confirmation Modal */}
      {isConfirmModalOpen && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-rose-500 rounded-2xl max-w-lg w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center gap-2.5 text-rose-400 font-bold text-base border-b border-slate-800 pb-3">
              <AlertOctagon className="w-5 h-5 text-rose-500" />
              <span>Confirm Irreversible Media Destruction</span>
            </div>

            <div className="bg-rose-950/40 border border-rose-800/80 rounded-xl p-3 text-xs text-rose-200 space-y-2">
              <p className="font-semibold">
                You are about to permanently obliterate all data on:
              </p>
              <div className="font-mono bg-slate-950 p-2.5 rounded-lg text-slate-200 text-[11px] leading-relaxed">
                Device: <strong>{selectedDevice.model}</strong> ({selectedDevice.path})<br />
                Serial Number: {selectedDevice.serialNumber}<br />
                Capacity: {(selectedDevice.capacityBytes / 1024 ** 3).toFixed(1)} GB<br />
                Standard: {selectedStandard}
              </div>
              <p className="text-rose-300 text-[11px]">
                Once started, all file systems, partition maps, and sector contents are permanently wiped.
                No data can ever be recovered by any forensic software or laboratory.
              </p>
            </div>

            <div className="space-y-2 text-xs text-slate-300">
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={ackPermanentLoss}
                  onChange={(e) => setAckPermanentLoss(e.target.checked)}
                  className="rounded border-slate-700 text-rose-600 focus:ring-0 mt-0.5"
                />
                <span>I confirm that all data on this drive can be permanently obliterated.</span>
              </label>

              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={ackDecommissionAuth}
                  onChange={(e) => setAckDecommissionAuth(e.target.checked)}
                  className="rounded border-slate-700 text-rose-600 focus:ring-0 mt-0.5"
                />
                <span>I have operational authorization to decommission or sanitize this media.</span>
              </label>

              <div className="pt-2">
                <div className="text-[11px] text-slate-400 mb-1">
                  Type <span className="font-mono font-bold text-rose-400">PURGE-VERIFIED-DATA</span> to unlock:
                </div>
                <input
                  type="text"
                  placeholder="PURGE-VERIFIED-DATA"
                  value={confirmPhraseInput}
                  onChange={(e) => setConfirmPhraseInput(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-700 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-rose-500"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2.5 border-t border-slate-800 pt-3">
              <button
                onClick={() => {
                  setIsConfirmModalOpen(false);
                  setConfirmPhraseInput('');
                  setAckPermanentLoss(false);
                  setAckDecommissionAuth(false);
                }}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold"
              >
                Cancel
              </button>

              <button
                onClick={startWipePipeline}
                disabled={
                  confirmPhraseInput !== 'PURGE-VERIFIED-DATA' ||
                  !ackPermanentLoss ||
                  !ackDecommissionAuth
                }
                className={`px-5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 ${
                  confirmPhraseInput === 'PURGE-VERIFIED-DATA' &&
                  ackPermanentLoss &&
                  ackDecommissionAuth
                    ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-600/40'
                    : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                }`}
              >
                <Flame className="w-4 h-4" />
                <span>Confirm &amp; Obliterate Media</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
