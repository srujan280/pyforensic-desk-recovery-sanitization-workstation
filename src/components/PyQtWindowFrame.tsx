import React from 'react';
import {
  Shield,
  HardDrive,
  Lock,
  Unlock,
  FileCheck2,
  Trash2,
  Search,
  Sparkles,
  FileCode2,
  Globe,
  ChevronDown,
  ExternalLink,
} from 'lucide-react';
import { StorageDevice } from '../types/forensic';

interface PyQtWindowFrameProps {
  children: React.ReactNode;
  activeDomain: 'RECOVERY' | 'SANITIZATION' | 'AUDIT' | 'PYTHON_SOURCE' | 'AI_ASSISTANT';
  setActiveDomain: (domain: 'RECOVERY' | 'SANITIZATION' | 'AUDIT' | 'PYTHON_SOURCE' | 'AI_ASSISTANT') => void;
  devices: StorageDevice[];
  selectedDevice: StorageDevice;
  onSelectDevice: (device: StorageDevice) => void;
  toggleWriteBlocker: () => void;
  toggleAIDock: () => void;
  isAIDockOpen: boolean;
  onOpenQuickPlan: (prompt: string) => void;
}

export const PyQtWindowFrame: React.FC<PyQtWindowFrameProps> = ({
  children,
  activeDomain,
  setActiveDomain,
  devices,
  selectedDevice,
  onSelectDevice,
  toggleWriteBlocker,
  toggleAIDock,
  isAIDockOpen,
  onOpenQuickPlan,
}) => {
  const [isDeviceMenuOpen, setIsDeviceMenuOpen] = React.useState(false);

  return (
    <div className="flex flex-col h-screen w-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* Clean, Modern Top Header */}
      <header className="bg-slate-900 border-b border-slate-800 px-4 py-2.5 flex items-center justify-between gap-4 z-30 shrink-0">
        {/* Brand & Identity */}
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-sky-600 to-indigo-600 flex items-center justify-center shadow-md shadow-sky-500/20 text-white font-bold">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold text-base text-white tracking-tight">PyForensic Desk</h1>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-sky-500/10 border border-sky-400/30 text-sky-400 font-semibold uppercase tracking-wider">
                PyQt6 &amp; NIST 800-88
              </span>
            </div>
            <p className="text-xs text-slate-400">Forensic Recovery &amp; Secure Media Sanitization Suite</p>
          </div>
        </div>

        {/* Center: Clean Navigation Tabs */}
        <nav className="flex items-center bg-slate-950/80 p-1 rounded-xl border border-slate-800 shadow-inner">
          <button
            onClick={() => setActiveDomain('RECOVERY')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeDomain === 'RECOVERY'
                ? 'bg-sky-600 text-white shadow-sm shadow-sky-600/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Search className="w-3.5 h-3.5" />
            <span>File Recovery</span>
          </button>

          <button
            onClick={() => setActiveDomain('SANITIZATION')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeDomain === 'SANITIZATION'
                ? 'bg-rose-600 text-white shadow-sm shadow-rose-600/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Secure Sanitization</span>
          </button>

          <button
            onClick={() => setActiveDomain('AI_ASSISTANT')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeDomain === 'AI_ASSISTANT'
                ? 'bg-indigo-600 text-white shadow-sm shadow-indigo-600/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-sky-400" />
            <span>Smart AI</span>
            <span className="flex items-center gap-1 text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.2 rounded-full border border-emerald-500/30">
              <Globe className="w-2.5 h-2.5" /> Web
            </span>
          </button>

          <button
            onClick={() => setActiveDomain('AUDIT')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeDomain === 'AUDIT'
                ? 'bg-slate-800 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <FileCheck2 className="w-3.5 h-3.5" />
            <span>Certificates &amp; Logs</span>
          </button>

          <button
            onClick={() => setActiveDomain('PYTHON_SOURCE')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeDomain === 'PYTHON_SOURCE'
                ? 'bg-emerald-700 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <FileCode2 className="w-3.5 h-3.5" />
            <span>Python Desktop</span>
          </button>
        </nav>

        {/* Right: Storage Media Selector & Write-Blocker Switch */}
        <div className="flex items-center gap-3">
          {/* Storage Media Selector Button */}
          <div className="relative">
            <button
              onClick={() => setIsDeviceMenuOpen(!isDeviceMenuOpen)}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700/80 border border-slate-700 text-xs font-medium transition-colors text-left"
            >
              <HardDrive className="w-3.5 h-3.5 text-sky-400 shrink-0" />
              <div className="leading-tight">
                <div className="text-white font-semibold truncate max-w-[150px]">{selectedDevice.model}</div>
                <div className="text-[10px] text-slate-400">
                  {selectedDevice.path} • {(selectedDevice.capacityBytes / 1024 ** 3).toFixed(1)} GB
                </div>
              </div>
              <ChevronDown className="w-3.5 h-3.5 text-slate-400 ml-1" />
            </button>

            {/* Dropdown Menu */}
            {isDeviceMenuOpen && (
              <div className="absolute right-0 top-full mt-1.5 w-72 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl p-1.5 z-50 space-y-1">
                <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-2 py-1">
                  Select Target Storage Media
                </div>
                {devices.map((d) => (
                  <button
                    key={d.id}
                    onClick={() => {
                      onSelectDevice(d);
                      setIsDeviceMenuOpen(false);
                    }}
                    className={`w-full text-left p-2 rounded-lg text-xs flex items-center justify-between transition-colors ${
                      d.id === selectedDevice.id
                        ? 'bg-sky-600/20 border border-sky-500/50 text-sky-200'
                        : 'hover:bg-slate-800 text-slate-300'
                    }`}
                  >
                    <div>
                      <div className="font-semibold">{d.model}</div>
                      <div className="text-[10px] text-slate-400 font-mono">
                        {d.path} • {(d.capacityBytes / 1024 ** 3).toFixed(1)} GB • {d.filesystem}
                      </div>
                    </div>
                    {d.id === selectedDevice.id && (
                      <span className="w-2 h-2 rounded-full bg-sky-400" />
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Simple, Large Write-Blocker Safety Switch */}
          <button
            onClick={toggleWriteBlocker}
            title="Click to toggle physical/logical write-blocker"
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-bold transition-all shadow-sm ${
              selectedDevice.writeBlockerActive
                ? 'bg-emerald-950/80 border-emerald-500 text-emerald-300 hover:bg-emerald-900/80 shadow-emerald-950/40'
                : 'bg-rose-950/80 border-rose-500 text-rose-300 hover:bg-rose-900/80 shadow-rose-950/40 animate-pulse'
            }`}
          >
            {selectedDevice.writeBlockerActive ? (
              <>
                <Lock className="w-3.5 h-3.5 text-emerald-400" />
                <span>Write-Blocker: SAFE (Read-Only)</span>
              </>
            ) : (
              <>
                <Unlock className="w-3.5 h-3.5 text-rose-400" />
                <span>Write-Blocker: OFF (Writable)</span>
              </>
            )}
          </button>

          {/* AI Side-Dock Toggle (when not on full AI view) */}
          {activeDomain !== 'AI_ASSISTANT' && (
            <button
              onClick={toggleAIDock}
              className={`p-2 rounded-lg border transition-colors flex items-center justify-center ${
                isAIDockOpen
                  ? 'bg-sky-600 text-white border-sky-500 shadow-md shadow-sky-600/30'
                  : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
              }`}
              title="Toggle AI Copilot Side Panel"
            >
              <Sparkles className="w-4 h-4" />
            </button>
          )}
        </div>
      </header>

      {/* Main Workstation View Area */}
      <div className="flex-1 flex overflow-hidden relative">{children}</div>

      {/* Clean Status Bar */}
      <footer className="h-7 bg-slate-900 border-t border-slate-800 px-4 flex items-center justify-between text-xs text-slate-400 font-mono shrink-0">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            Target: <strong className="text-white font-sans">{selectedDevice.model}</strong>
          </span>
          <span className="text-slate-500">|</span>
          <span>Path: {selectedDevice.path}</span>
          <span className="text-slate-500">|</span>
          <span>Health: {selectedDevice.healthPercent}%</span>
        </div>

        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1 text-sky-400">
            <Globe className="w-3 h-3" /> Live Internet Search Grounding: Active
          </span>
          <span className="text-slate-500">|</span>
          <span>The Sleuth Kit 4.12 • NIST SP 800-88 Rev. 1</span>
        </div>
      </footer>
    </div>
  );
};
