// public/workers/readerWorker.js
// 최소 뼈대: 메인에서 보낸 payload를 받아 간단 계산을 하고 되돌려줍니다.

self.onmessage = (e) => {
  const { id, kind, payload } = e.data || {};
  try {
    if (kind === "metrics") {
      const text = String(payload?.text || "");
      // 예시 계산(가벼운 것): 길이/단어/문장 수
      const length = text.length;
      const words = (text.match(/[a-zA-Z0-9가-힣]+/g) || []).length;
      const sentences = (text.split(/(?<=[.!?])\s+|[\n]+/g) || []).filter(Boolean).length;

      // 더 무거운 계산은 여기에 추가(키워드 빈도, n-gram, 규칙기반 린트 등)
      self.postMessage({ id, ok: true, data: { length, words, sentences } });
      return;
    }

    // 알 수 없는 작업
    self.postMessage({ id, ok: false, error: "unknown_kind" });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err && err.message || err) });
  }
};
