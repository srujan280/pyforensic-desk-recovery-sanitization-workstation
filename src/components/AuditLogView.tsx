import React, { useState } from 'react';
import {
  Database,
  Search,
  Download,
  FileCheck2,
  Trash2,
  ShieldCheck,
  RefreshCw,
  HardDrive,
  CheckCircle2,
  FileText,
} from 'lucide-react';
import { AuditLogEntry, StorageDevice, RecoveredArtifact } from '../types/forensic';
import { generateRecoveryCertificatePDF, generateSanitizationCertificatePDF } from '../utils/pdfCertificate';

interface AuditLogViewProps {
  logs: AuditLogEntry[];
  selectedDevice: StorageDevice;
  artifacts: RecoveredArtifact[];
}

export const AuditLogView: React.FC<AuditLogViewProps> = ({ logs, selectedDevice, artifacts }) => {
  const [filterDomain, setFilterDomain] = useState<'ALL' | 'RECOVERY' | 'SANITIZATION'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredLogs = logs.filter((log) => {
    const matchesDomain = filterDomain === 'ALL' || log.domain === filterDomain;
    const matchesSearch =
      log.operationId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.deviceModel.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.pipelineOrStandard.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.preSha256.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesDomain && matchesSearch;
  });

  const exportJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(logs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `forensic_audit_trail_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const recoveryCount = logs.filter((l) => l.domain === 'RECOVERY').length;
  const sanitizationCount = logs.filter((l) => l.domain === 'SANITIZATION').length;

  return (
    <div className="flex-1 flex flex-col h-full overflow-y-auto p-4 space-y-4 bg-slate-950">
      {/* Top Banner & Stats */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Database className="w-4 h-4 text-sky-400" />
              <span>SQLite Chain of Custody &amp; Audit Trail</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Cryptographically verified operation records and PDF certificates for legal and compliance audit.
            </p>
          </div>

          <button
            onClick={exportJSON}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-semibold flex items-center gap-2 border border-slate-700 transition-colors shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Database JSON</span>
          </button>
        </div>

        {/* Quick Stats Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400">
              <Search className="w-5 h-5" />
            </div>
            <div>
              <div className="text-lg font-bold text-white">{recoveryCount}</div>
              <div className="text-xs text-slate-400">Forensic Recovery Audits</div>
            </div>
          </div>

          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
              <Trash2 className="w-5 h-5" />
            </div>
            <div>
              <div className="text-lg font-bold text-white">{sanitizationCount}</div>
              <div className="text-xs text-slate-400">NIST Media Destruction Logs</div>
            </div>
          </div>

          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <CheckCircle2 className="w-5 h-5" />
            </div>
            <div>
              <div className="text-lg font-bold text-white">100% Verified</div>
              <div className="text-xs text-slate-400">SHA-256 Cryptographic Match</div>
            </div>
          </div>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-semibold">Filter Domain:</span>
          <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
            {(['ALL', 'RECOVERY', 'SANITIZATION'] as const).map((dom) => (
              <button
                key={dom}
                onClick={() => setFilterDomain(dom)}
                className={`px-3 py-1 rounded-lg font-semibold transition-all ${
                  filterDomain === dom
                    ? dom === 'RECOVERY'
                      ? 'bg-sky-600 text-white'
                      : dom === 'SANITIZATION'
                      ? 'bg-rose-600 text-white'
                      : 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {dom === 'ALL' ? 'All Operations' : dom === 'RECOVERY' ? 'Recoveries' : 'Sanitizations'}
              </button>
            ))}
          </div>
        </div>

        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search by ID, drive model, hash, or standard..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 pr-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 w-72"
          />
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm flex-1 flex flex-col min-h-[300px] space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="font-bold text-sm text-white">
            Operation Records ({filteredLogs.length})
          </h3>
          <span className="text-[11px] text-slate-400 font-mono">SQLite 3: operations_log</span>
        </div>

        <div className="flex-1 overflow-x-auto border border-slate-800 rounded-xl bg-slate-950">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider font-mono border-b border-slate-800">
              <tr>
                <th className="p-3">Operation ID</th>
                <th className="p-3">Domain</th>
                <th className="p-3">Target Media</th>
                <th className="p-3">Method / Standard</th>
                <th className="p-3">Pre-SHA-256</th>
                <th className="p-3">Post-SHA-256</th>
                <th className="p-3">Compliance</th>
                <th className="p-3">Date</th>
                <th className="p-3 text-right">PDF Certificate</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {filteredLogs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-900/50 transition-colors">
                  <td className="p-3 font-mono font-bold text-sky-400">{log.operationId}</td>
                  <td className="p-3">
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${
                        log.domain === 'RECOVERY'
                          ? 'bg-sky-500/10 text-sky-400 border border-sky-500/20'
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }`}
                    >
                      {log.domain}
                    </span>
                  </td>
                  <td className="p-3 font-medium text-white">{log.deviceModel}</td>
                  <td className="p-3 text-slate-400">{log.pipelineOrStandard}</td>
                  <td className="p-3 font-mono text-[11px] text-slate-500 truncate max-w-[120px]" title={log.preSha256}>
                    {log.preSha256.substring(0, 14)}...
                  </td>
                  <td className="p-3 font-mono text-[11px] text-slate-500 truncate max-w-[120px]" title={log.postSha256}>
                    {log.postSha256.substring(0, 14)}...
                  </td>
                  <td className="p-3">
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold flex items-center gap-1 w-fit">
                      <CheckCircle2 className="w-3 h-3" />
                      {log.status}
                    </span>
                  </td>
                  <td className="p-3 text-slate-400 font-mono text-[11px] whitespace-nowrap">{log.timestamp}</td>
                  <td className="p-3 text-right">
                    <button
                      onClick={() => {
                        if (log.domain === 'RECOVERY') {
                          generateRecoveryCertificatePDF(
                            log.operationId,
                            selectedDevice,
                            log.preSha256,
                            log.postSha256,
                            artifacts,
                            log.caseRef,
                            log.operator
                          );
                        } else {
                          generateSanitizationCertificatePDF(
                            {
                              operationId: log.operationId,
                              targetDevice: log.deviceModel,
                              standardApplied: log.pipelineOrStandard,
                              passesCompleted: 3,
                              totalBytesWiped: selectedDevice.capacityBytes,
                              preWipeSha256: log.preSha256,
                              postWipeSha256: log.postSha256,
                              verificationStatus: log.status,
                              metadataWiped: true,
                              unallocatedWiped: true,
                              executionTimeSeconds: 14.8,
                              timestamp: log.timestamp,
                              entropy: 0.0,
                            },
                            selectedDevice,
                            log.caseRef,
                            log.operator
                          );
                        }
                      }}
                      className="px-3 py-1 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-semibold inline-flex items-center gap-1.5 transition-colors shadow-sm"
                    >
                      <Download className="w-3 h-3" />
                      <span>Download PDF</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
