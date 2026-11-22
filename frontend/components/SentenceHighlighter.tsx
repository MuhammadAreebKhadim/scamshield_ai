import React, { useState } from "react";
import { AlertCircle, AlertTriangle, Info } from "lucide-react";
import { HighlightedSentence } from "@/lib/api";

interface SentenceHighlighterProps {
  content: string;
  flaggedSentences: HighlightedSentence[];
}

export default function SentenceHighlighter({ content, flaggedSentences }: SentenceHighlighterProps) {
  const [selectedHighlight, setSelectedHighlight] = useState<HighlightedSentence | null>(null);

  if (!flaggedSentences || flaggedSentences.length === 0) {
    return (
      <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/40 text-sm leading-relaxed text-slate-700 dark:text-slate-300 font-mono whitespace-pre-wrap">
        {content}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Annotated text view */}
      <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 leading-loose text-sm font-sans text-slate-800 dark:text-slate-200 shadow-inner">
        {renderHighlightedContent(content, flaggedSentences, (h) => setSelectedHighlight(h))}
      </div>

      {/* Flagged sentences detail cards */}
      <div className="space-y-2">
        <h4 className="text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold flex items-center gap-1.5">
          <AlertCircle className="w-4 h-4 text-rose-500" />
          <span>Flagged Deceptive Elements ({flaggedSentences.length})</span>
        </h4>

        <div className="grid grid-cols-1 gap-2.5">
          {flaggedSentences.map((h, i) => {
            const isHigh = h.severity === "CRITICAL" || h.severity === "HIGH";
            return (
              <div
                key={i}
                onClick={() => setSelectedHighlight(h)}
                className={`p-3 rounded-lg border text-xs cursor-pointer transition-all ${
                  isHigh
                    ? "bg-rose-500/10 border-rose-500/30 text-rose-900 dark:text-rose-200 hover:bg-rose-500/20"
                    : "bg-amber-500/10 border-amber-500/30 text-amber-900 dark:text-amber-200 hover:bg-amber-500/20"
                }`}
              >
                <div className="flex items-center justify-between font-mono font-bold text-[11px] mb-1">
                  <span className="flex items-center gap-1">
                    {isHigh ? (
                      <AlertCircle className="w-3.5 h-3.5 text-rose-500" />
                    ) : (
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                    )}
                    <span>Evidence #{i + 1}</span>
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] uppercase ${isHigh ? "bg-rose-500 text-white" : "bg-amber-500 text-slate-900 font-bold"}`}>
                    {h.severity}
                  </span>
                </div>
                <p className="font-semibold text-slate-900 dark:text-white my-1 italic">
                  "{h.text}"
                </p>
                <p className="text-slate-600 dark:text-slate-400 text-[11px] mt-1">
                  Reason: {h.reason}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function renderHighlightedContent(
  fullText: string,
  flagged: HighlightedSentence[],
  onSelect: (h: HighlightedSentence) => void
) {
  // Sort flagged phrases by appearance order
  let remaining = fullText;
  const elements = [];
  let keyIndex = 0;

  for (const item of flagged) {
    const textSnippet = item.text.trim();
    if (!textSnippet) continue;

    const matchPos = remaining.indexOf(textSnippet);
    if (matchPos !== -1) {
      // Add unflagged text before
      if (matchPos > 0) {
        elements.push(
          <span key={`text-${keyIndex++}`}>{remaining.substring(0, matchPos)}</span>
        );
      }

      // Add highlighted span
      const isCritical = item.severity === "CRITICAL" || item.severity === "HIGH";
      elements.push(
        <mark
          key={`mark-${keyIndex++}`}
          onClick={() => onSelect(item)}
          title={`[${item.severity}] ${item.reason}`}
          className={`cursor-pointer px-1 py-0.5 mx-0.5 rounded transition-all underline decoration-2 ${
            isCritical
              ? "bg-rose-500/25 text-rose-950 dark:text-rose-100 decoration-rose-500 font-medium"
              : "bg-amber-500/25 text-amber-950 dark:text-amber-100 decoration-amber-500 font-medium"
          }`}
        >
          {textSnippet}
        </mark>
      );

      remaining = remaining.substring(matchPos + textSnippet.length);
    }
  }

  if (remaining) {
    elements.push(<span key={`text-end`}>{remaining}</span>);
  }

  return elements.length > 0 ? elements : fullText;
}
