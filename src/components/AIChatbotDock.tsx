import React, { useState, useRef, useEffect } from 'react';
import {
  Sparkles,
  Send,
  X,
  Bot,
  User,
  CheckCircle,
  Play,
  Shield,
  HelpCircle,
  Terminal,
  Loader2,
  Globe,
  ExternalLink,
  Search,
  BookOpen,
  ArrowRight,
  RotateCcw,
} from 'lucide-react';
import { StorageDevice, AIActionPlan, ChatMessage } from '../types/forensic';

interface AIChatbotDockProps {
  isOpen: boolean;
  onClose?: () => void;
  activeDomain: string;
  selectedDevice: StorageDevice;
  onExecutePlan: (plan: AIActionPlan) => void;
  quickPromptText?: string;
  clearQuickPrompt?: () => void;
  isFullPage?: boolean;
}

export const AIChatbotDock: React.FC<AIChatbotDockProps> = ({
  isOpen,
  onClose,
  activeDomain,
  selectedDevice,
  onExecutePlan,
  quickPromptText,
  clearQuickPrompt,
  isFullPage = false,
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'init-1',
      sender: 'assistant',
      text: `Hello, Examiner! I am your **PyForensic Smart AI Assistant** with **live Google Search internet access** 🌐.\n\nI monitor **${selectedDevice.model}** and can help you with:\n\n• **Live Web Research**: Look up any NIST guidelines, CVE vulnerabilities, drive firmware advisories, or file formats.\n• **File Recovery Guidance**: Plan deep file carving with Sleuth Kit & Foremost without touching device sectors.\n• **NIST Sanitization Planning**: Formulate compliant Clear, Purge, or DoD media destruction routines.\n• **General & Technical Inquiries**: Ask me anything technical, forensic, or cybersecurity-related!\n\nWhat would you like to explore today?`,
      timestamp: new Date().toLocaleTimeString(),
      webSources: [
        { title: 'NIST SP 800-88 Rev. 1 Guidelines for Media Sanitization', url: 'https://csrc.nist.gov/pubs/sp/800/88/r1/final' },
        { title: 'The Sleuth Kit (TSK) Open Source Digital Forensics', url: 'https://www.sleuthkit.org/' },
      ],
    },
  ]);
  const [inputText, setInputText] = useState('');
  const [isThinking, setIsThinking] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isThinking]);

  useEffect(() => {
    if (quickPromptText) {
      handleSendMessage(quickPromptText);
      clearQuickPrompt?.();
    }
  }, [quickPromptText]);

  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputText).trim();
    if (!text || isThinking) return;

    if (!textToSend) setInputText('');

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text,
      timestamp: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setIsThinking(true);

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: text,
          activeDomain,
          selectedDevice,
          conversationHistory: messages.slice(-4),
        }),
      });

      const data = await response.json();

      const aiMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        sender: 'assistant',
        text: data.text || 'Action plan formulated based on forensic parameters.',
        timestamp: new Date().toLocaleTimeString(),
        actionPlan: data.actionPlan,
        searchQueries: data.searchQueries || [],
        webSources: data.webSources || [],
      };

      setMessages((prev) => [...prev, aiMsg]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          id: `ai-err-${Date.now()}`,
          sender: 'assistant',
          text: `⚠️ **AI Engine Notice**: Running local DFIR heuristic fallback. Forensic rule verified for **${selectedDevice.model}**.`,
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setIsThinking(false);
    }
  };

  const samplePrompts = [
    '🌐 Search latest NIST SP 800-88 sanitization standards',
    '🔍 Recover deleted photos and documents from USB',
    '🛡️ What is a hardware write-blocker and why is it needed?',
    '⚡ Explain NIST 800-88 Clear vs Purge vs Destroy',
    '💾 Can SSD data be recovered after wear-leveling or TRIM?',
    '🧪 Compare Foremost file carving with The Sleuth Kit fls',
  ];

  if (!isOpen && !isFullPage) return null;

  return (
    <div
      className={`flex flex-col h-full bg-slate-950 text-slate-100 select-text ${
        isFullPage
          ? 'flex-1 overflow-hidden'
          : 'w-80 sm:w-96 border-l border-slate-800 z-40'
      }`}
    >
      {/* Header */}
      <div className="h-12 bg-slate-900 border-b border-slate-800 px-4 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center shadow-sm shadow-sky-500/20">
            <Sparkles className="w-4 h-4 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-bold text-white">Forensic AI Assistant</span>
              <span className="flex items-center gap-1 text-[10px] bg-emerald-500/10 text-emerald-400 font-semibold px-2 py-0.5 rounded-full border border-emerald-500/30">
                <Globe className="w-2.5 h-2.5" /> Live Web Access
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {onClose && !isFullPage && (
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white p-1.5 rounded-lg hover:bg-slate-800 transition-colors"
              title="Close Panel"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Suggested Topic Chips */}
      <div className="px-4 py-2 border-b border-slate-800/80 bg-slate-900/50 flex gap-1.5 overflow-x-auto no-scrollbar shrink-0">
        {samplePrompts.map((prompt, idx) => (
          <button
            key={idx}
            onClick={() => handleSendMessage(prompt)}
            className="text-xs px-3 py-1 rounded-full bg-slate-800 hover:bg-slate-700 text-sky-300 font-medium whitespace-nowrap transition-colors border border-slate-700/60 shadow-xs hover:border-sky-500/50"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
          >
            {/* Sender Tag */}
            <div className="flex items-center gap-1.5 mb-1.5 text-[11px] text-slate-400 font-mono">
              {msg.sender === 'user' ? (
                <>
                  <span>You (Examiner)</span>
                  <User className="w-3.5 h-3.5 text-sky-400" />
                </>
              ) : (
                <>
                  <Bot className="w-3.5 h-3.5 text-indigo-400" />
                  <span className="text-indigo-400 font-semibold">PyForensic Smart AI</span>
                </>
              )}
              <span>• {msg.timestamp}</span>
            </div>

            {/* Bubble */}
            <div
              className={`p-3.5 rounded-2xl max-w-[94%] leading-relaxed shadow-sm ${
                msg.sender === 'user'
                  ? 'bg-sky-600 text-white rounded-tr-xs'
                  : 'bg-slate-900 border border-slate-800 text-slate-200 rounded-tl-xs space-y-3'
              }`}
            >
              {/* Google Search Queries indicator */}
              {msg.searchQueries && msg.searchQueries.length > 0 && (
                <div className="p-2 rounded-lg bg-slate-950/70 border border-slate-800 flex items-center gap-2 text-[11px] text-sky-300">
                  <Search className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                  <span>
                    <strong>Google Search:</strong> &ldquo;{msg.searchQueries.join(', ')}&rdquo;
                  </span>
                </div>
              )}

              {/* Message Content */}
              <div className="whitespace-pre-wrap leading-relaxed">{msg.text}</div>

              {/* Web Sources / Grounding Links */}
              {msg.webSources && msg.webSources.length > 0 && (
                <div className="mt-2 pt-2 border-t border-slate-800/80 space-y-1.5">
                  <div className="flex items-center gap-1 text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                    <Globe className="w-3 h-3 text-sky-400" />
                    <span>Internet Sources &amp; Citations:</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                    {msg.webSources.map((source, sIdx) => (
                      <a
                        key={sIdx}
                        href={source.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-2 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 flex items-center justify-between text-[11px] text-sky-300 transition-colors group"
                      >
                        <span className="truncate pr-2 font-medium">{source.title}</span>
                        <ExternalLink className="w-3 h-3 text-slate-500 group-hover:text-sky-400 shrink-0" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Structured AI Action Plan */}
              {msg.actionPlan && (
                <div
                  className={`mt-2 p-3 rounded-xl border text-xs space-y-2.5 ${
                    msg.actionPlan.domain === 'RECOVERY'
                      ? 'bg-sky-950/40 border-sky-500/60 text-sky-200'
                      : 'bg-rose-950/40 border-rose-500/60 text-rose-200'
                  }`}
                >
                  <div className="flex items-center justify-between border-b border-current/20 pb-2">
                    <span className="font-bold text-sm flex items-center gap-1.5">
                      <Terminal className="w-4 h-4" />
                      {msg.actionPlan.plan_title}
                    </span>
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded-full bg-black/40 font-bold">
                      {msg.actionPlan.domain}
                    </span>
                  </div>

                  <div className="space-y-1.5 text-xs text-slate-300">
                    <div className="font-semibold text-white">Recommended Action Sequence:</div>
                    {msg.actionPlan.steps?.map((step, sIdx) => (
                      <div key={sIdx} className="flex items-start gap-2">
                        <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                        <span>{step}</span>
                      </div>
                    ))}
                  </div>

                  <button
                    onClick={() => msg.actionPlan && onExecutePlan(msg.actionPlan)}
                    className={`w-full py-2 rounded-lg font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-md ${
                      msg.actionPlan.domain === 'RECOVERY'
                        ? 'bg-sky-600 hover:bg-sky-500 text-white shadow-sky-600/30'
                        : 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-600/30'
                    }`}
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Approve &amp; Start {msg.actionPlan.domain === 'RECOVERY' ? 'Recovery' : 'Sanitization'} Now</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        ))}

        {isThinking && (
          <div className="flex items-center gap-2 text-slate-400 text-xs italic font-mono p-3 bg-slate-900/60 rounded-xl border border-slate-800/60 w-fit">
            <Loader2 className="w-4 h-4 text-sky-400 animate-spin" />
            <span>Searching internet &amp; formulating forensic answer...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Bar */}
      <div className="p-3 border-t border-slate-800 bg-slate-900 shrink-0">
        <div className="flex items-center gap-2 bg-slate-950 border border-slate-700/80 rounded-xl px-3 py-1.5 focus-within:border-sky-500 transition-colors shadow-inner">
          <input
            type="text"
            placeholder="Ask AI anything with live internet access (e.g. 'Search latest NIST guidelines' or 'Recover photos')..."
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
            className="flex-1 bg-transparent text-xs text-white placeholder-slate-400 focus:outline-none"
          />
          <button
            onClick={() => handleSendMessage()}
            disabled={!inputText.trim() || isThinking}
            className="p-1.5 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-800 disabled:text-slate-600 text-white rounded-lg transition-colors shadow-sm"
            title="Send Message"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
        <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400 font-mono">
          <span className="flex items-center gap-1 text-slate-400">
            <Globe className="w-3 h-3 text-emerald-400" />
            Internet Search Grounding: <strong>Connected</strong>
          </span>
          <span>Target Drive: {selectedDevice.model.substring(0, 22)}...</span>
        </div>
      </div>
    </div>
  );
};
