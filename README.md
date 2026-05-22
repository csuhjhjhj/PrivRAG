# PrivRAG

PrivRAG is a lightweight privacy-preserving Retrieval-Augmented Generation (RAG) prototype. It implements a Flask backend and a Vue-based web UI for experimenting with privacy-aware query routing, risk assessment, retrieval strategy selection, and audit logging.

The current implementation focuses on the system workflow and extensible interfaces. It uses a small built-in knowledge base and TF-IDF retrieval to keep the project easy to run, while reserving clear integration points for production embedding models, vector databases, differential privacy modules, and homomorphic-encryption backends.

## Features

- Query risk analysis for PII, business-sensitive terms, technical-sensitive terms, and high-security keywords
- L0-L4 protection-level routing:
  - L0: Plain RAG baseline
  - L1: lightweight input protection and context minimization
  - L2: DistanceDP-style query perturbation
  - L3: FHE-oriented encrypted retrieval path
  - L4: optional TEE-based key-protection enhancement
- Retrieval strategy selection across HNSW, IVF-PQ, Flat, and Encrypted HNSW routes
- Scenario-based query testing for normal knowledge queries, PII-bearing queries, technical-sensitive queries, key-protection cases, and baseline evaluation
- Top-K document retrieval over a built-in knowledge base
- Safe-generation explanation with minimal-context handling
- Audit log recording for risk level, selected route, index type, and protection operations

## Architecture

```text
frontend/          Vue single-page UI served as static files
backend/app.py     Flask application and API routes
data/              Runtime audit log directory
requirements.txt   Python dependencies
run_server.sh      Simple Linux startup script
privrag.service    Example systemd unit
```

Runtime flow:

```text
Query
  -> sensitive entity detection
  -> risk scoring
  -> L0-L4 route selection
  -> index strategy selection
  -> protected retrieval
  -> safe answer construction
  -> audit logging
```

## API

### `GET /api/health`

Returns service health and document count.

### `GET /api/config`

Returns protection-level metadata, pipeline steps, and available index routes.

### `POST /api/query`

Runs the PrivRAG query pipeline.

Request:

```json
{
  "query": "客户张三反馈账号无法登录，手机号是13812345678，请帮我查相关售后处理记录。"
}
```

Response includes:

- risk score and sensitive entities
- selected L0-L4 route
- selected index strategy
- protection operations
- retrieved snippets
- generated answer
- demo metrics

### `GET /api/audit`

Returns recent audit records.

### `GET /api/documents`

Returns metadata for the built-in knowledge base.

## Local Run

```bash
cd privrag_demo
pip install -r requirements.txt
python backend/app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Deployment

The service can be started directly:

```bash
PRIVRAG_HOST=0.0.0.0 PRIVRAG_PORT=5000 PRIVRAG_DEBUG=0 python backend/app.py
```

Or with the included helper:

```bash
chmod +x run_server.sh
./run_server.sh
```

Optional environment variables:

```bash
PRIVRAG_HOST=0.0.0.0
PRIVRAG_PORT=5000
PRIVRAG_DEBUG=0
```

For long-running deployment, `privrag.service` can be adapted as a systemd unit. In production, consider using a WSGI server such as Gunicorn or uWSGI behind Nginx.

If the runtime environment cannot access the Vue CDN, download the Vue runtime to `frontend/assets/vue.global.prod.js` and update `frontend/index.html` to reference the local file.

## Extension Points

The current prototype keeps heavy cryptographic and vector-database components modular. Suggested next steps:

- Replace TF-IDF retrieval with embedding-based retrieval
- Connect FAISS or Milvus for HNSW, IVF-PQ, and Flat indexes
- Add a real DistanceDP perturbation module
- Add a TenSEAL or Microsoft SEAL based small-scale encrypted inner-product demo
- Add document upload and index rebuild APIs
- Add persistent storage for audit logs and retrieval experiments

## Notes

This project is a research prototype. L1/L2 routing, sensitive-entity detection, route selection, and audit logging are implemented as executable logic. FHE, Encrypted HNSW, and TEE paths are represented as route-level interfaces and workflow modules, ready for progressive replacement with concrete cryptographic implementations.
