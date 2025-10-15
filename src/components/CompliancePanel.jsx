import React from "react";

export default function CompliancePanel({ hits, onJump }) {
  return (
    <div className="border rounded p-2 max-h-[70vh] overflow-auto">
      <div className="font-semibold mb-2">검출 {hits.length}건</div>
      {hits.map((h, i) => (
        <div key={i} className="border-b py-2">
          <div className="text-sm">[{h.severity}] {h.topic} · {h.rule_id}</div>
          <div className="text-xs bg-gray-50 p-1 rounded mt-1">“…{h.excerpt}…”</div>
          <div className="flex gap-2 mt-2">
            <button className="text-blue-600 underline" onClick={() => onJump?.(h)}>위치 이동</button>
          </div>
        </div>
      ))}
    </div>
  );
}