import os, json
from sentence_transformers import SentenceTransformer
import faiss

# 추출된 문서들이 있는 폴더 경로
DOCS_PATH = "data_docs"

# 모델 로드
model = SentenceTransformer("jhgan/ko-sbert-nli")

# 원고 목록 불러오기
corpus = []
for fname in os.listdir(DOCS_PATH):
    if fname.endswith(".txt") or fname.endswith(".docx"):
        try:
            fullpath = os.path.join(DOCS_PATH, fname)
            if fname.endswith(".txt"):
                with open(fullpath, encoding="utf-8") as f:
                    corpus.append(f.read().strip())
            else:
                # docx 처리
                import docx
                doc = docx.Document(fullpath)
                text = "\n".join([p.text for p in doc.paragraphs if p.text.strip()])
                corpus.append(text)
        except Exception as e:
            print(f"❌ {fname} 오류: {e}")

# 문장 임베딩
print(f"총 {len(corpus)}건 문서 임베딩 중...")
embeddings = model.encode(corpus, convert_to_tensor=False)

# FAISS 인덱스 구축
index = faiss.IndexFlatL2(len(embeddings[0]))
index.add(embeddings)

# 저장
with open("corpus.json", "w", encoding="utf-8") as f:
    json.dump(corpus, f, ensure_ascii=False, indent=2)
faiss.write_index(index, "plagiarism_index.faiss")

print("✅ corpus.json 및 plagiarism_index.faiss 생성 완료")
