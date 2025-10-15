export function reportToMarkdown({ hits, pack, docTitle = "문서" }) {
  const sum = { block: 0, warn: 0, info: 0 };
  hits.forEach((h) => sum[h.severity]++);
  let md = `# 광고·심의 점검 리포트 (KR)\n- 문서명: ${docTitle}\n- 규칙팩: ${pack.pack} ${pack.version}\n\n## 요약\n- BLOCK: ${sum.block} | WARN: ${sum.warn} | INFO: ${sum.info}\n\n## 상세\n`;
  hits.forEach((h) => {
    const rule = pack.rules.find((r) => r.id === h.rule_id);
    md += `### [${h.severity}] ${h.topic} — ${h.rule_id}\n- 근거: ${rule?.rationale || "-"}\n- 문제 구문: \`${h.excerpt}\`\n\n`;
  });
  return md;
}