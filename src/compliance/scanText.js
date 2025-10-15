export function scanText(text, rules) {
  const norm = text.normalize("NFC");
  const lower = norm.toLowerCase();
  const hits = [];
  for (const r of rules) {
    // keyword
    for (const kw of r._keywords || []) {
      let idx = lower.indexOf(kw);
      while (idx !== -1) {
        const end = idx + kw.length;
        const ctx = norm.slice(Math.max(0, idx - 30), Math.min(norm.length, end + 30));
        if (!(r._excepts || []).some((ex) => ex.test(ctx))) {
          hits.push({ rule_id: r.id, topic: r.topic, severity: r.severity, start: idx, end, excerpt: norm.slice(idx, end) });
        }
        idx = lower.indexOf(kw, idx + 1);
      }
    }
    // regex
    for (const re of r._regexes || []) {
      let m;
      while ((m = re.exec(norm)) !== null) {
        const idx = m.index,
          end = idx + m[0].length;
        const ctx = norm.slice(Math.max(0, idx - 30), Math.min(norm.length, end + 30));
        if (!(r._excepts || []).some((ex) => ex.test(ctx))) {
          hits.push({ rule_id: r.id, topic: r.topic, severity: r.severity, start: idx, end, excerpt: m[0] });
        }
      }
    }
  }
  return hits.sort((a, b) => a.start - b.start);
}