import hashlib
import math
import re

_TOKEN_RE = re.compile(r"[a-z0-9]{2,}")

_STOPWORDS = frozenset(
    {
        "all",
        "and",
        "any",
        "are",
        "but",
        "can",
        "for",
        "from",
        "have",
        "into",
        "not",
        "per",
        "that",
        "the",
        "this",
        "use",
        "using",
        "via",
        "was",
        "were",
        "when",
        "will",
        "with",
        "your",
    }
)


def tokenize(text: str) -> list[str]:
    """Extract normalized alphanumeric tokens while filtering common stopwords."""
    raw = _TOKEN_RE.findall(text.lower())
    return [tok for tok in raw if tok not in _STOPWORDS]


def compute_deterministic_embedding(text: str, dimensions: int = 384) -> list[float]:
    """Compute an L2-normalized signed feature-hash vector with zero external dependencies."""
    if dimensions <= 0:
        raise ValueError("dimensions must be positive")

    tokens = tokenize(text)
    if not tokens:
        return [0.0] * dimensions

    features = list(tokens)
    for idx in range(len(tokens) - 1):
        features.append(f"{tokens[idx]}_{tokens[idx + 1]}")

    vec = [0.0] * dimensions
    for feat in features:
        digest = hashlib.sha256(feat.encode("utf-8")).digest()
        bucket = int.from_bytes(digest[:4], "big") % dimensions
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        vec[bucket] += sign

    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0.0:
        return [0.0] * dimensions
    return [round(v / norm, 6) for v in vec]


def cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    """Compute cosine similarity between two equal-length vectors."""
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0
    dot = sum(a * b for a, b in zip(vec_a, vec_b, strict=True))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def keyword_overlap_score(
    query: str,
    document: str,
    tags: list[str] | None = None,
) -> float:
    """Compute fractional query token recall against document text and tags."""
    q_tokens = set(tokenize(query))
    if not q_tokens:
        return 0.0
    doc_text = document
    if tags:
        doc_text = f"{document} {' '.join(tags)}"
    d_tokens = set(tokenize(doc_text))
    if not d_tokens:
        return 0.0
    overlap = len(q_tokens & d_tokens)
    return overlap / len(q_tokens)


def hybrid_score(
    *,
    query: str,
    query_vec: list[float],
    document: str,
    doc_vec: list[float],
    tags: list[str] | None = None,
    doc_service: str | None = None,
    target_service: str | None = None,
) -> float:
    """Blend deterministic cosine similarity, keyword overlap, and service match."""
    cos = max(0.0, cosine_similarity(query_vec, doc_vec))
    kw = keyword_overlap_score(query, document, tags=tags)
    score = 0.55 * cos + 0.45 * kw
    if (
        target_service
        and doc_service
        and target_service.strip().lower() == doc_service.strip().lower()
    ):
        score += 0.25
    return round(min(1.0, score), 4)
