export function buildRangesFromOffsets(containerEl, offsets) {
  const walker = document.createTreeWalker(containerEl, NodeFilter.SHOW_TEXT, null);
  const nodes = [];
  let n;
  while ((n = walker.nextNode())) nodes.push(n);

  // 각 텍스트 노드의 누적 길이 테이블
  const acc = [];
  let sum = 0;
  for (const node of nodes) {
    acc.push({ node, start: sum, end: sum + node.textContent.length });
    sum += node.textContent.length;
  }

  function toDOMOffset(globalOffset) {
    const row = acc.find((r) => r.start <= globalOffset && globalOffset <= r.end);
    if (!row) return null;
    return { node: row.node, offset: globalOffset - row.start };
  }

  return offsets.map((o) => {
    const s = toDOMOffset(o.start);
    const e = toDOMOffset(o.end);
    if (!s || !e) return null;
    const r = document.createRange();
    r.setStart(s.node, s.offset);
    r.setEnd(e.node, e.offset);
    return r;
  }).filter(Boolean);
}