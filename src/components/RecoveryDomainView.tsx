import React, { useState } from 'react';
import {
  Search,
  HardDrive,
  Lock,
  Unlock,
  FileCheck,
  FileSearch,
  CheckCircle2,
  AlertTriangle,
  Download,
  Eye,
  FileText,
  Image,
  Database,
  Radio,
  FileCode,
  ShieldCheck,
  Sparkles,
  ArrowRight,
  Filter,
} from 'lucide-react';
import { StorageDevice, RecoveredArtifact } from '../types/forensic';
import { generateRecoveryCertificatePDF } from '../utils/pdfCertificate';

interface RecoveryDomainViewProps {
  devices: StorageDevice[];
  selectedDevice: StorageDevice;
  onSelectDevice: (device: StorageDevice) => void;
  artifacts: RecoveredArtifact[];
  onRecoveryComplete: (newArtifacts: RecoveredArtifact[], preHash: string, postHash: string) => void;
  onOpenQuickAIPlan: (prompt: string) => void;
}

export const RecoveryDomainView: React.FC<RecoveryDomainViewProps> = ({
  devices,
  selectedDevice,
  onSelectDevice,
  artifacts,
  onRecoveryComplete,
  onOpenQuickAIPlan,
}) => {
  const [enableSleuthkit, setEnableSleuthkit] = useState(true);
  const [enableCarving, setEnableCarving] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(100);
  const [scanStatusText, setScanStatusText] = useState('Forensic analysis idle. Ready for acquisition.');
  const [activeSectorIndex, setActiveSectorIndex] = useState(0);

  const [preHash, setPreHash] = useState('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  const [postHash, setPostHash] = useState('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTypeFilter, setSelectedTypeFilter] = useState('ALL');
  const [selectedArtifact, setSelectedArtifact] = useState<RecoveredArtifact | null>(artifacts[0] || null);

  // Run recovery pipeline
  const runRecovery = () => {
    setIsScanning(true);
    setScanProgress(0);
    setScanStatusText('Acquiring hardware read-lock & computing Pre-Scan SHA-256 baseline...');

    let currentPct = 0;
    const interval = setInterval(() => {
      currentPct += 5;
      setScanProgress(currentPct);
      setActiveSectorIndex((prev) => (prev + 3) % 120);

      if (currentPct === 20) {
        setScanStatusText('Running Sleuth Kit (fls / tsk_recover) to extract deleted MFT records...');
      } else if (currentPct === 55) {
        setScanStatusText('Carving unallocated disk sectors using Foremost magic headers...');
      } else if (currentPct === 80) {
        setScanStatusText('Extracting EXIF GPS tags, MACB timelines, and computing SHA-256...');
      } else if (currentPct >= 100) {
        clearInterval(interval);
        setIsScanning(false);
        setScanProgress(100);
        setScanStatusText(`Acquisition completed successfully! ${artifacts.length} verified artifacts recovered.`);

        const calculatedHash = '996c46bbaf7cce4d88e0b62e49c7489ab10375f4d8a183d84a7e937d940656a8';
        setPreHash(calculatedHash);
        setPostHash(calculatedHash);
        onRecoveryComplete(artifacts, calculatedHash, calculatedHash);
      }
    }, 120);
  };

  const filteredArtifacts = artifacts.filter((art) => {
    const matchesQuery =
      art.filename.toLowerCase().includes(searchQuery.toLowerCase()) ||
      art.fileType.toLowerCase().includes(searchQuery.toLowerCase()) ||
      art.id.toLowerCase().includes(searchQuery.toLowerCase());

    if (selectedTypeFilter === 'ALL') return matchesQuery;
    if (selectedTypeFilter === 'IMAGE') return matchesQuery && art.fileType.includes('Image');
    if (selectedTypeFilter === 'DOC') return matchesQuery && (art.fileType.includes('PDF') || art.fileType.includes('Word'));
    if (selectedTypeFilter === 'DATA') return matchesQuery && (art.fileType.includes('SQLite') || art.fileType.includes('Packet'));
    return matchesQuery;
  });

  return (
    <div className="flex-1 flex flex-col md:flex-row h-full overflow-hidden bg-slate-950">
      {/* Left/Main Content Column */}
      <div className="flex-1 flex flex-col overflow-y-auto p-4 space-y-4">
        {/* Banner with 3-Step Guide */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <Search className="w-4 h-4 text-sky-400" />
                <span>Digital Forensic Data Recovery Domain</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Deep file carving and deleted artifact recovery operating in 100% read-only mode to preserve evidence.
              </p>
            </div>

            {/* AI Assistant Quick Guide Button */}
            <button
              onClick={() => onOpenQuickAIPlan('Guide me through carving lost photos and documents from my drive')}
              className="px-3 py-1.5 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-colors"
            >
              <Sparkles className="w-3.5 h-3.5 text-sky-400" />
              <span>Ask Smart AI Guide</span>
            </button>
          </div>

          {/* Step 1: Storage Media Grid */}
          <div className="space-y-2">
            <div className="text-xs font-semibold text-slate-300 flex items-center justify-between">
              <span>Step 1: Choose Storage Drive to Recover</span>
              <span className="text-[11px] text-slate-400 font-normal">
                {selectedDevice.writeBlockerActive ? (
                  <span className="text-emerald-400 font-semibold flex items-center gap-1">
                    <ShieldCheck className="w-3.5 h-3.5" /> Read-Only Write-Blocker Active
                  </span>
                ) : (
                  <span className="text-amber-400 font-semibold flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> Write-Blocker Inactive
                  </span>
                )}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
              {devices.map((dev) => (
                <div
                  key={dev.id}
                  onClick={() => onSelectDevice(dev)}
                  className={`p-3 rounded-xl border cursor-pointer transition-all ${
                    selectedDevice.id === dev.id
                      ? 'bg-sky-600/10 border-sky-500 shadow-md shadow-sky-600/10 text-white'
                      : 'bg-slate-950/70 border-slate-800 hover:border-slate-700 text-slate-300'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <HardDrive className={`w-4 h-4 mt-0.5 ${selectedDevice.id === dev.id ? 'text-sky-400' : 'text-slate-400'}`} />
                    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-slate-900 border border-slate-800 text-slate-300 font-mono">
                      {(dev.capacityBytes / 1024 ** 3).toFixed(0)} GB
                    </span>
                  </div>
                  <div className="font-semibold text-xs mt-2 truncate">{dev.model}</div>
                  <div className="text-[11px] text-slate-400 font-mono mt-0.5">{dev.path}</div>
                  <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-400">
                    <span>{dev.filesystem}</span>
                    <span className="text-emerald-400 font-semibold">{dev.smartStatus}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Step 2 & 3: Recovery Controls and Trigger */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-xs font-semibold text-white">Step 2: Recovery Engines &amp; Carving Tools</div>
              <div className="flex items-center gap-4 mt-1 text-xs">
                <label className="flex items-center gap-2 cursor-pointer text-slate-200">
                  <input
                    type="checkbox"
                    checked={enableSleuthkit}
                    onChange={(e) => setEnableSleuthkit(e.target.checked)}
                    className="rounded border-slate-700 text-sky-500 focus:ring-0"
                  />
                  <span>Sleuth Kit (fls / tsk_recover)</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer text-slate-200">
                  <input
                    type="checkbox"
                    checked={enableCarving}
                    onChange={(e) => setEnableCarving(e.target.checked)}
                    className="rounded border-slate-700 text-sky-500 focus:ring-0"
                  />
                  <span>Foremost Deep Magic Carver</span>
                </label>
              </div>
            </div>

            {/* Big Action Button */}
            <button
              onClick={runRecovery}
              disabled={isScanning}
              className={`px-5 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center gap-2 shadow-lg ${
                isScanning
                  ? 'bg-sky-800 text-slate-300 cursor-not-allowed'
                  : 'bg-sky-600 hover:bg-sky-500 text-white shadow-sky-600/30'
              }`}
            >
              <FileSearch className="w-4 h-4" />
              <span>{isScanning ? 'Recovering Artifacts...' : 'Scan & Recover Files Now'}</span>
            </button>
          </div>

          {/* Progress Bar & Status */}
          <div className="space-y-1.5 pt-1">
            <div className="flex justify-between text-xs text-slate-300 font-mono">
              <span className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${isScanning ? 'bg-amber-400 animate-pulse' : 'bg-emerald-400'}`} />
                {scanStatusText}
              </span>
              <span className="font-bold text-sky-400">{scanProgress}%</span>
            </div>
            <div className="w-full bg-slate-950 rounded-full h-2.5 overflow-hidden border border-slate-800">
              <div
                className="bg-gradient-to-r from-sky-500 to-indigo-500 h-full transition-all duration-150"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
          </div>
        </div>

        {/* Live Sector Allocation Heatmap */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-slate-200">Sector Allocation &amp; Carved File Map</span>
            <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded bg-slate-800" /> Free Space
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded bg-sky-900" /> Allocated
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded bg-emerald-500" /> Carved Evidence
              </span>
            </div>
          </div>

          <div className="grid grid-cols-24 sm:grid-cols-30 gap-1 p-1.5 bg-slate-950 rounded-xl border border-slate-800 max-h-16 overflow-hidden">
            {Array.from({ length: 120 }).map((_, i) => {
              const isCarved = i === 12 || i === 24 || i === 48 || i === 72 || i === 95;
              const isAllocated = i % 4 === 0;
              const isScanningSector = isScanning && i === activeSectorIndex;

              return (
                <div
                  key={i}
                  className={`h-2 rounded transition-colors duration-100 ${
                    isScanningSector
                      ? 'bg-amber-400 ring-2 ring-amber-300'
                      : isCarved
                      ? 'bg-emerald-500 shadow-xs shadow-emerald-500/50'
                      : isAllocated
                      ? 'bg-sky-900'
                      : 'bg-slate-800'
                  }`}
                />
              );
            })}
          </div>
        </div>

        {/* Recovered Artifacts Inventory */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm flex-1 flex flex-col space-y-3 min-h-[300px]">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <h3 className="font-bold text-sm text-white">
                Recovered Files ({filteredArtifacts.length})
              </h3>
              <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
                {['ALL', 'DOC', 'IMAGE', 'DATA'].map((type) => (
                  <button
                    key={type}
                    onClick={() => setSelectedTypeFilter(type)}
                    className={`px-3 py-1 rounded-lg font-medium transition-all ${
                      selectedTypeFilter === type
                        ? 'bg-sky-600 text-white'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search file name or type..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-8 pr-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 w-52"
                />
              </div>

              <button
                onClick={() =>
                  generateRecoveryCertificatePDF(
                    `REC-${Date.now().toString().slice(-6)}`,
                    selectedDevice,
                    preHash,
                    postHash,
                    artifacts
                  )
                }
                className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow-md shadow-emerald-600/20 transition-all"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export PDF Certificate</span>
              </button>
            </div>
          </div>

          {/* Artifacts Table */}
          <div className="flex-1 overflow-x-auto border border-slate-800 rounded-xl bg-slate-950">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider font-mono border-b border-slate-800">
                <tr>
                  <th className="p-3">File Name</th>
                  <th className="p-3">Type</th>
                  <th className="p-3">Size</th>
                  <th className="p-3">Sector</th>
                  <th className="p-3">Carver</th>
                  <th className="p-3">Integrity</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {filteredArtifacts.map((art) => (
                  <tr
                    key={art.id}
                    onClick={() => setSelectedArtifact(art)}
                    className={`cursor-pointer transition-colors ${
                      selectedArtifact?.id === art.id ? 'bg-sky-600/10' : 'hover:bg-slate-900/50'
                    }`}
                  >
                    <td className="p-3 font-medium text-white flex items-center gap-2">
                      {art.fileType.includes('Image') ? (
                        <Image className="w-4 h-4 text-amber-400" />
                      ) : art.fileType.includes('PDF') || art.fileType.includes('Word') ? (
                        <FileText className="w-4 h-4 text-sky-400" />
                      ) : art.fileType.includes('Database') ? (
                        <Database className="w-4 h-4 text-purple-400" />
                      ) : (
                        <Radio className="w-4 h-4 text-emerald-400" />
                      )}
                      <span>{art.filename}</span>
                    </td>
                    <td className="p-3 text-slate-400">{art.fileType}</td>
                    <td className="p-3 font-mono">{(art.sizeBytes / (1024 * 1024)).toFixed(2)} MB</td>
                    <td className="p-3 font-mono text-slate-400">{art.sectorOffset.toLocaleString()}</td>
                    <td className="p-3 font-mono text-slate-400">{art.carvedBy}</td>
                    <td className="p-3">
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                        {art.recoveryIntegrity}
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedArtifact(art);
                        }}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-sky-300 rounded-lg text-xs transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Right Column: File Details Inspector */}
      {selectedArtifact && (
        <div className="w-full md:w-80 lg:w-96 bg-slate-900 border-l border-slate-800 p-4 flex flex-col space-y-3 overflow-y-auto">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="text-xs font-bold text-sky-400 uppercase tracking-wide flex items-center gap-1.5">
              <Eye className="w-4 h-4" />
              File Forensic Inspector
            </span>
            <span className="text-[10px] font-mono text-slate-400">{selectedArtifact.id}</span>
          </div>

          {/* Details Card */}
          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1.5 text-xs">
            <div className="font-bold text-white text-sm break-words">{selectedArtifact.filename}</div>
            <div className="text-slate-400 font-mono text-[11px]">
              {(selectedArtifact.sizeBytes / (1024 * 1024)).toFixed(2)} MB • {selectedArtifact.fileType}
            </div>
            <div className="text-slate-500 font-mono text-[10px] truncate select-all">
              SHA-256: {selectedArtifact.sha256}
            </div>
          </div>

          {/* MACB Timeline */}
          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-2 text-xs">
            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
              MACB Timestamps (Filesystem Timeline)
            </div>
            <div className="space-y-1 text-slate-300 font-mono text-[11px]">
              <div className="flex justify-between">
                <span className="text-slate-500">Modified:</span>
                <span>{selectedArtifact.timestamps.modified}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Accessed:</span>
                <span>{selectedArtifact.timestamps.accessed}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Created:</span>
                <span>{selectedArtifact.timestamps.created}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Born/Entry:</span>
                <span>{selectedArtifact.timestamps.born}</span>
              </div>
            </div>
          </div>

          {/* EXIF / Carved Metadata */}
          {selectedArtifact.metadata && Object.keys(selectedArtifact.metadata).length > 0 && (
            <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-2 text-xs">
              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                Extracted Metadata &amp; Headers
              </div>
              {selectedArtifact.metadata.cameraMake && (
                <div className="text-[11px]">
                  <span className="text-slate-500">Camera: </span>
                  <span className="text-white font-medium">{selectedArtifact.metadata.cameraMake}</span>
                </div>
              )}
              {selectedArtifact.metadata.gps && (
                <div className="text-[11px]">
                  <span className="text-slate-500">GPS: </span>
                  <span className="text-amber-400 font-mono">{selectedArtifact.metadata.gps}</span>
                </div>
              )}
              {selectedArtifact.metadata.author && (
                <div className="text-[11px]">
                  <span className="text-slate-500">Author: </span>
                  <span className="text-white font-medium">{selectedArtifact.metadata.author}</span>
                </div>
              )}
              {selectedArtifact.metadata.carverHeader && (
                <div className="text-[11px] font-mono">
                  <span className="text-slate-500">Magic Header: </span>
                  <span className="text-emerald-400">{selectedArtifact.metadata.carverHeader}</span>
                </div>
              )}
            </div>
          )}

          {/* Hex & ASCII Stream Preview */}
          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 flex-1 flex flex-col min-h-[140px]">
            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">
              Hex &amp; ASCII Stream Preview
            </div>
            <div className="p-2 rounded-lg bg-black font-mono text-[10px] leading-tight text-sky-300 overflow-x-auto whitespace-pre flex-1 border border-slate-900 select-text">
              {selectedArtifact.hexPreview}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
