"""RAG retrieval over the local MITRE ATT&CK knowledge base.

Uses Chroma when available. If Chroma (or its embedding model) can't be loaded,
it falls back to TF-IDF similarity so the pipeline still works.
"""
import json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


def _doc(t):
    return f"{t['name']} ({t['id']}, {t['tactic']}). {t['description']} {t['keywords']}"


class Retriever:
    def __init__(self, kb_path="data/attack_kb.json"):
        self.kb = json.load(open(kb_path, encoding="utf-8"))
        self.docs = [_doc(t) for t in self.kb]
        self.backend = "tfidf"
        self._col = None
        try:
            import chromadb
            client = chromadb.Client()
            col = client.get_or_create_collection("attack_kb")
            col.add(ids=[t["id"] for t in self.kb], documents=self.docs)
            col.query(query_texts=["test"], n_results=1)  # forces the embedding model to load
            self._col = col
            self.backend = "chroma"
        except Exception as e:  # missing package, offline model download, etc.
            print(f"[retrieval] Chroma unavailable ({type(e).__name__}); using TF-IDF fallback.")
            self._vec = TfidfVectorizer(stop_words="english").fit(self.docs)
            self._mat = self._vec.transform(self.docs)

    def search(self, query, k=3):
        by_id = {t["id"]: t for t in self.kb}
        if self._col is not None:
            res = self._col.query(query_texts=[query], n_results=k)
            return [by_id[i] for i in res["ids"][0]]
        sims = cosine_similarity(self._vec.transform([query]), self._mat)[0]
        order = sims.argsort()[::-1][:k]
        return [self.kb[i] for i in order]
