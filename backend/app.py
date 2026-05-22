from __future__ import annotations

import json
import math
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from flask import Flask, jsonify, request, send_from_directory
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = ROOT / "frontend"
DATA_DIR = ROOT / "data"
AUDIT_PATH = DATA_DIR / "audit_log.jsonl"


@dataclass
class Document:
    doc_id: str
    title: str
    category: str
    sensitivity: str
    content: str


DOCUMENTS = [
    Document(
        "D001",
        "企业级RAG隐私风险概述",
        "威胁建模",
        "中",
        "企业级RAG系统中，用户Query、Embedding向量、检索访问模式、Prompt上下文和生成结果都可能暴露业务逻辑、决策意图和敏感知识。隐私保护RAG需要覆盖入口防护、密态检索、安全生成和审计闭环。",
    ),
    Document(
        "D002",
        "L0-L4分级保护框架",
        "分级保护",
        "高",
        "L0用于Plain RAG基线评估，L1用于查询规范化、上下文最小化和日志脱敏，L2采用DistanceDP查询扰动，L3采用CKKS FHE密态检索，L4在L3基础上增加TEE密钥保护。",
    ),
    Document(
        "D003",
        "加密HNSW密态检索路线",
        "密态检索",
        "高",
        "加密HNSW以图索引为核心，通过K-means粗路由缩小候选子图，使用CKKS SIMD批量编码进行密态距离计算，并利用Chebyshev多项式近似完成密态邻居选择。",
    ),
    Document(
        "D004",
        "DistanceDP查询扰动",
        "差分隐私",
        "中",
        "DistanceDP通过对查询Embedding添加校准噪声，为查询向量提供概率性隐私保护。该路线适合中敏查询，可在不大幅改变现有向量数据库工程形态的前提下增强隐私保护。",
    ),
    Document(
        "D005",
        "多索引自适应策略",
        "索引适配",
        "中",
        "PrivRAG支持HNSW、IVF-PQ和Flat三种索引形态。HNSW适合高召回图检索，IVF-PQ适合大规模高吞吐场景，Flat适合小规模高安全密态内积验证。",
    ),
    Document(
        "D006",
        "TEE可选增强定位",
        "可信执行环境",
        "高",
        "本方案不依赖TEE作为核心检索路线。TEE仅在L4中作为可选增强，用于保护CKKS密钥管理和策略决策环境，核心检索逻辑仍由FHE或DP等密码学机制承担。",
    ),
    Document(
        "D007",
        "安全生成与审计闭环",
        "安全生成",
        "中",
        "安全生成阶段需要对Top-K候选片段进行最小必要上下文重组，对Prompt和输出进行敏感片段过滤，并记录策略路线、风险等级、检索片段和脱敏结果，形成可审计闭环。",
    ),
]


SENSITIVE_PATTERNS = {
    "PII": [
        r"1[3-9]\d{9}",
        r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+",
        r"\d{15}|\d{17}[\dXx]",
        r"身份证|手机号|邮箱|住址|姓名",
    ],
    "商业机密": [
        r"客户名单|合同|报价|利润|成本|供应商|招标|商业机密|内部资料|预算",
    ],
    "技术敏感": [
        r"密钥|私钥|漏洞|后门|攻击|绕过|权限|源代码|核心算法|模型权重|Embedding|向量库",
    ],
    "高安全": [
        r"TEE|FHE|同态|CKKS|密态|HNSW|隐私|加密|差分隐私|DistanceDP",
    ],
}

LEVELS = {
    "L0": {
        "name": "L0 基线评估",
        "index": "Plain HNSW",
        "protection": "无隐私保护，仅用于实验对照",
        "color": "#6B7280",
    },
    "L1": {
        "name": "L1 轻量保护",
        "index": "HNSW",
        "protection": "查询规范化、上下文最小化、日志脱敏",
        "color": "#2E7D32",
    },
    "L2": {
        "name": "L2 标准保护",
        "index": "HNSW / IVF-PQ + DP",
        "protection": "DistanceDP查询扰动、隐私预算管理",
        "color": "#F59E0B",
    },
    "L3": {
        "name": "L3 密态检索",
        "index": "加密HNSW / IVF-PQ",
        "protection": "CKKS FHE密态距离计算、Chebyshev近似邻居选择",
        "color": "#DC2626",
    },
    "L4": {
        "name": "L4 可选增强",
        "index": "L3索引形态保持不变",
        "protection": "L3 + 可选TEE密钥保护，TEE不承担核心检索逻辑",
        "color": "#7C3AED",
    },
}


def tokenize(text: str) -> str:
    chinese_chars = re.findall(r"[\u4e00-\u9fff]", text)
    words = re.findall(r"[A-Za-z0-9_+-]+", text.lower())
    return " ".join(chinese_chars + words)


VECTORIZER = TfidfVectorizer(tokenizer=lambda x: x.split(), lowercase=False)
DOC_MATRIX = VECTORIZER.fit_transform([tokenize(doc.title + " " + doc.content) for doc in DOCUMENTS])


def find_sensitive_items(query: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for category, patterns in SENSITIVE_PATTERNS.items():
        for pattern in patterns:
            for match in re.finditer(pattern, query, flags=re.IGNORECASE):
                value = match.group(0)
                hits.append({"category": category, "value": mask_value(value)})
    return hits


def mask_value(value: str) -> str:
    if len(value) <= 4:
        return value
    if "@" in value:
        name, domain = value.split("@", 1)
        return f"{name[:2]}***@{domain}"
    return f"{value[:2]}***{value[-2:]}"


def sensitivity_score(query: str, hits: list[dict[str, str]]) -> float:
    score = 0.12
    score += 0.16 * len({item["category"] for item in hits})
    score += 0.05 * min(len(hits), 4)
    if len(query) > 80:
        score += 0.08
    if re.search(r"密钥|私钥|漏洞|客户名单|合同|源代码|模型权重|核心算法", query, re.I):
        score += 0.22
    if re.search(r"TEE|FHE|CKKS|密态|加密HNSW|DistanceDP", query, re.I):
        score += 0.14
    return min(score, 0.96)


def choose_route(query: str, score: float, hits: list[dict[str, str]]) -> dict[str, Any]:
    if re.search(r"基线|plain|无保护|对照", query, re.I):
        level = "L0"
        reason = "这类查询更像实验对照，因此选择Plain RAG基线，用来比较隐私保护带来的收益和开销。"
    elif re.search(r"TEE|密钥保护|最高安全|强合规", query, re.I):
        level = "L4"
        reason = "查询涉及密钥保护或高安全诉求，因此在L3密态检索基础上增加TEE可选增强；TEE只护密钥，不承担核心检索。"
    elif score >= 0.62:
        level = "L3"
        reason = "查询包含高敏技术或业务信息，需要让检索过程尽量在密态下完成，因此选择FHE密态检索路线。"
    elif score >= 0.36:
        level = "L2"
        reason = "查询存在中等敏感风险，但不必直接使用最高开销路线，因此采用DistanceDP扰动增强查询向量隐私。"
    else:
        level = "L1"
        reason = "查询敏感度较低，先采用轻量入口防护和上下文最小化，避免所有查询都走重型加密路线。"

    if level in {"L3", "L4"}:
        index = "Encrypted HNSW"
    elif re.search(r"大规模|吞吐|批量|高性能", query, re.I):
        index = "IVF-PQ"
    elif re.search(r"高安全|小规模|全量", query, re.I):
        index = "Flat"
    else:
        index = LEVELS[level]["index"]

    return {
        "level": level,
        "name": LEVELS[level]["name"],
        "index": index,
        "protection": LEVELS[level]["protection"],
        "reason": reason,
        "color": LEVELS[level]["color"],
        "is_tee_required": level == "L4",
        "is_crypto_core": level in {"L2", "L3", "L4"},
    }


def apply_query_protection(query: str, route: dict[str, Any]) -> dict[str, Any]:
    protected = query.strip()
    operations: list[str] = ["查询规范化"]
    if route["level"] in {"L1", "L2", "L3", "L4"}:
        protected = re.sub(r"1[3-9]\d{9}", "[手机号]", protected)
        protected = re.sub(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", "[邮箱]", protected)
        operations.append("敏感实体脱敏")
    if route["level"] in {"L2", "L3", "L4"}:
        operations.append("DistanceDP查询扰动")
    if route["level"] in {"L3", "L4"}:
        operations.append("CKKS密态距离计算")
        operations.append("加密HNSW候选检索")
    if route["level"] == "L4":
        operations.append("TEE密钥保护")
    return {"protected_query": protected, "operations": operations}


def retrieve(query: str, route: dict[str, Any], top_k: int = 3) -> list[dict[str, Any]]:
    query_vector = VECTORIZER.transform([tokenize(query)])
    scores = cosine_similarity(query_vector, DOC_MATRIX).ravel()

    if route["level"] == "L2":
        rng = np.random.default_rng(42)
        scores = scores + rng.normal(0, 0.015, size=scores.shape)
    if route["index"] == "IVF-PQ":
        scores = scores * np.array([0.96, 0.94, 0.93, 0.95, 1.02, 0.92, 0.94])
    if route["index"] == "Flat":
        top_k = min(top_k, 2)

    order = np.argsort(scores)[::-1][:top_k]
    results = []
    for rank, idx in enumerate(order, 1):
        doc = DOCUMENTS[int(idx)]
        results.append(
            {
                "rank": rank,
                "doc_id": doc.doc_id,
                "title": doc.title,
                "category": doc.category,
                "sensitivity": doc.sensitivity,
                "score": round(float(max(scores[idx], 0)), 4),
                "snippet": doc.content[:118] + ("..." if len(doc.content) > 118 else ""),
            }
        )
    return results


def build_answer(query: str, route: dict[str, Any], docs: list[dict[str, Any]]) -> str:
    if not docs:
        return "未检索到足够相关的知识片段。"
    titles = "、".join(doc["title"] for doc in docs[:2])
    return (
        f"系统判断该查询适合采用{route['name']}，当前索引路线为{route['index']}。"
        f"根据检索到的《{titles}》等片段，PrivRAG会先判断查询风险，再选择合适的保护等级："
        f"低风险走轻量保护，中风险走DP扰动，高风险走FHE密态检索，密钥保护要求更高时才启用TEE增强。"
        f"最终只将最小必要上下文送入生成阶段，并记录可审计日志。"
    )


def estimate_metrics(route: dict[str, Any], docs: list[dict[str, Any]]) -> dict[str, Any]:
    level = route["level"]
    latency = {"L0": 42, "L1": 58, "L2": 86, "L3": 168, "L4": 182}[level]
    security = {"L0": 8, "L1": 35, "L2": 58, "L3": 84, "L4": 90}[level]
    recall = round(0.72 + 0.04 * len(docs) - (0.03 if level == "L2" else 0), 2)
    return {
        "latency_ms_demo": latency,
        "security_score_demo": security,
        "retrieval_quality_demo": min(recall, 0.92),
        "communication_overhead": "低" if level in {"L0", "L1"} else ("中" if level == "L2" else "较高"),
        "note": "演示指标用于展示路线差异，正式实验需接入真实基准测试。",
    }


def append_audit(record: dict[str, Any]) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    with AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_audit(limit: int = 20) -> list[dict[str, Any]]:
    if not AUDIT_PATH.exists():
        return []
    lines = AUDIT_PATH.read_text(encoding="utf-8").splitlines()[-limit:]
    return [json.loads(line) for line in lines if line.strip()]


app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")


@app.get("/")
def index() -> Any:
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/api/health")
def health() -> Any:
    return jsonify({"status": "ok", "service": "PrivRAG Demo", "documents": len(DOCUMENTS)})


@app.get("/api/config")
def config() -> Any:
    return jsonify(
        {
            "levels": LEVELS,
            "pipeline": [
                "隐私入口",
                "敏感度评估",
                "L0-L4策略路由",
                "多索引检索",
                "安全生成",
                "审计留痕",
            ],
            "indexes": ["HNSW", "IVF-PQ", "Flat", "Encrypted HNSW"],
        }
    )


@app.post("/api/query")
def query() -> Any:
    payload = request.get_json(silent=True) or {}
    raw_query = str(payload.get("query", "")).strip()
    if not raw_query:
        return jsonify({"error": "query is required"}), 400

    started = time.perf_counter()
    hits = find_sensitive_items(raw_query)
    score = sensitivity_score(raw_query, hits)
    route = choose_route(raw_query, score, hits)
    protection = apply_query_protection(raw_query, route)
    docs = retrieve(protection["protected_query"], route)
    answer = build_answer(raw_query, route, docs)
    metrics = estimate_metrics(route, docs)
    elapsed_ms = math.ceil((time.perf_counter() - started) * 1000)

    response = {
        "query": raw_query,
        "risk": {
            "score": round(score, 2),
            "level": "高" if score >= 0.62 else ("中" if score >= 0.36 else "低"),
            "sensitive_items": hits,
        },
        "route": route,
        "protection": protection,
        "retrieval": docs,
        "answer": answer,
        "metrics": metrics | {"actual_elapsed_ms": elapsed_ms},
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    append_audit(
        {
            "timestamp": response["timestamp"],
            "query": raw_query[:80],
            "risk_score": response["risk"]["score"],
            "risk_level": response["risk"]["level"],
            "route": route["level"],
            "index": route["index"],
            "operations": protection["operations"],
        }
    )
    return jsonify(response)


@app.get("/api/audit")
def audit() -> Any:
    return jsonify({"items": read_audit()})


@app.get("/api/documents")
def documents() -> Any:
    return jsonify(
        {
            "items": [
                {
                    "doc_id": doc.doc_id,
                    "title": doc.title,
                    "category": doc.category,
                    "sensitivity": doc.sensitivity,
                    "preview": doc.content[:80] + "...",
                }
                for doc in DOCUMENTS
            ]
        }
    )


if __name__ == "__main__":
    host = os.environ.get("PRIVRAG_HOST", "0.0.0.0")
    port = int(os.environ.get("PRIVRAG_PORT", "5000"))
    debug = os.environ.get("PRIVRAG_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
