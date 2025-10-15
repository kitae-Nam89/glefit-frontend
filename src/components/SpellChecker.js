import { useEffect, useState } from 'react';

function SpellChecker() {
  const [text, setText] = useState('');
  const [results, setResults] = useState([]);
  const [timer, setTimer] = useState(null);

  // 실시간 감지
  const handleInput = (e) => {
    const newText = e.target.value;
    setText(newText);

    if (timer) clearTimeout(timer);
    const newTimer = setTimeout(() => {
      checkSpelling(newText);
    }, 800); // 0.8초간 멈추면 검사
    setTimer(newTimer);
  };

  const checkSpelling = async (inputText) => {
    if (!inputText.trim()) {
      setResults([]);
      return;
    }

    try {
      const res = await fetch('http://localhost:5000/spellcheck', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: inputText })
      });
      const data = await res.json();
      setResults(data.suggestions || []);
    } catch (err) {
      console.error('오류:', err);
    }
  };

  return (
    <div style={{ padding: '20px' }}>
      <h2>✍️ 글핏 실시간 맞춤법 검사기</h2>
      <textarea
        value={text}
        onChange={handleInput}
        rows="10"
        style={{ width: '100%', fontSize: '16px' }}
        placeholder="글을 입력하면 자동으로 검사됩니다."
      />
      <ul>
        {results.map((item, idx) => (
          <li key={idx} style={{ color: 'red' }}>
            {item.original} → {item.suggestion}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default SpellChecker;
