import React, { useState, useEffect } from 'react';
import {
  FileCode2,
  Copy,
  Check,
  Download,
  Play,
  Terminal,
  FileText,
  PackageCheck,
  Cpu,
  RefreshCw,
  FolderCode,
} from 'lucide-react';
import { PythonSourceFile } from '../types/forensic';

export const PythonSourceHub: React.FC = () => {
  const [files, setFiles] = useState<PythonSourceFile[]>([]);
  const [activeFileName, setActiveFileName] = useState('ui_assistant.py');
  const [copied, setCopied] = useState(false);
  const [isRunningTest, setIsRunningTest] = useState(false);
  const [testOutput, setTestOutput] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/python-sources')
      .then((res) => res.json())
      .then((data) => {
        if (data.files) {
          setFiles(data.files);
        }
      })
      .catch((err) => console.error('Failed to load python files:', err));
  }, []);

  const activeFile = files.find((f) => f.filename === activeFileName) || files[0];

  const handleCopy = () => {
    if (activeFile) {
      navigator.clipboard.writeText(activeFile.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = () => {
    if (activeFile) {
      const blob = new Blob([activeFile.content], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = activeFile.filename;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  const runTestbench = async (script: string) => {
    setIsRunningTest(true);
    setTestOutput(`[SYSTEM] Initializing Python 3 subshell runner for python_app/${script === 'audit' ? 'audit_certificate.py' : 'forensic_engine.py'}...\n`);

    try {
      const res = await fetch('/api/run-python-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script }),
      });
      const data = await res.json();
      setTestOutput(
        `$ python3 python_app/${data.script}\n\n` +
        `[STDOUT]:\n${data.stdout || '(no output)'}\n` +
        (data.stderr ? `[STDERR]:\n${data.stderr}\n` : '') +
        `\n[PROCESS COMPLETED WITH EXIT CODE: ${data.exitCode}]`
      );
    } catch (e: any) {
      setTestOutput(`[ERROR] Execution failed: ${e.message}`);
    } finally {
      setIsRunningTest(false);
    }
  };

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden p-4 space-y-4 bg-slate-950">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-sm flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-bold text-emerald-400">
            <FolderCode className="w-5 h-5" />
            <span>Python Desktop Architecture Hub (PyQt6 &amp; Forensic Engines)</span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Production-grade Python modules: <code className="text-sky-300 font-mono">ui_assistant.py</code> (PyQt GUI &amp; AI Chatbot), <code className="text-sky-300 font-mono">forensic_engine.py</code> (TSK Carving &amp; NIST Sanitization), and <code className="text-sky-300 font-mono">audit_certificate.py</code> (SQLite &amp; ReportLab).
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => runTestbench('engine')}
            disabled={isRunningTest}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 text-white rounded-xl text-xs font-bold flex items-center gap-2 transition-all shadow-md shadow-emerald-600/20"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{isRunningTest ? 'Executing Python...' : 'Run Forensic Engine Test'}</span>
          </button>

          <button
            onClick={() => runTestbench('audit')}
            disabled={isRunningTest}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all"
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Test SQLite &amp; ReportLab</span>
          </button>
        </div>
      </div>

      {/* Main Code View Area */}
      <div className="flex-1 flex flex-col md:flex-row gap-4 min-h-0">
        {/* Left Navigation: Files list */}
        <div className="w-full md:w-64 bg-slate-900 border border-slate-800 rounded-2xl p-3 flex flex-col space-y-2">
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider px-2 py-1">
            Python Modules
          </div>
          <div className="space-y-1">
            {files.map((file) => (
              <button
                key={file.filename}
                onClick={() => setActiveFileName(file.filename)}
                className={`w-full text-left px-3 py-2.5 rounded-xl text-xs font-mono flex items-center justify-between transition-all ${
                  activeFileName === file.filename
                    ? 'bg-sky-600/20 border border-sky-500 text-sky-200 font-bold shadow-xs'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                }`}
              >
                <div className="flex items-center gap-2 truncate">
                  <FileCode2 className="w-4 h-4 text-sky-400 shrink-0" />
                  <span className="truncate">{file.filename}</span>
                </div>
                <span className="text-[10px] text-slate-500">{(file.sizeBytes / 1024).toFixed(1)}k</span>
              </button>
            ))}
          </div>

          {/* Local Desktop Instructions */}
          <div className="mt-auto p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5 text-xs text-slate-400">
            <div className="text-white font-bold flex items-center gap-1.5">
              <PackageCheck className="w-4 h-4 text-emerald-400" />
              <span>Run on Local Desktop:</span>
            </div>
            <pre className="font-mono text-[10px] bg-slate-900 p-2 rounded-lg text-sky-300 leading-relaxed overflow-x-auto">
              cd python_app{'\n'}pip install -r requirements.txt{'\n'}python run.py
            </pre>
          </div>
        </div>

        {/* Right Code Display & Live Test Output */}
        <div className="flex-1 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl min-h-0 overflow-hidden shadow-sm">
          {/* Header */}
          <div className="h-11 bg-slate-950 border-b border-slate-800 px-4 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 font-mono text-white font-semibold">
              <FileCode2 className="w-4 h-4 text-sky-400" />
              <span>python_app/{activeFile?.filename}</span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCopy}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs flex items-center gap-1.5 transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied!' : 'Copy Code'}</span>
              </button>

              <button
                onClick={handleDownload}
                className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm shadow-sky-600/20"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download File</span>
              </button>
            </div>
          </div>

          {/* Code Body */}
          <div className="flex-1 p-4 overflow-y-auto font-mono text-xs text-slate-300 bg-slate-950/70 whitespace-pre leading-relaxed select-text">
            {activeFile?.content || '# Loading Python module...'}
          </div>

          {/* Terminal Testbench Output Console */}
          {testOutput && (
            <div className="h-48 border-t border-slate-800 bg-black flex flex-col">
              <div className="h-8 bg-slate-900 border-b border-slate-800 px-3 flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5 text-emerald-400 font-semibold">
                  <Terminal className="w-3.5 h-3.5" />
                  Python 3 Testbench Execution Output
                </span>
                <button
                  onClick={() => setTestOutput(null)}
                  className="hover:text-white text-slate-400"
                >
                  Close Console
                </button>
              </div>
              <div className="flex-1 p-3 font-mono text-xs text-emerald-300 overflow-y-auto whitespace-pre leading-relaxed select-text">
                {testOutput}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
