# PrivRAG Demo

隐私保护RAG原型展示系统。后端使用 Flask，前端使用 Vue CDN，由 Flask 直接托管静态页面，适合先部署到服务器做课题展示。

## 功能

- 查询敏感度识别：PII、商业机密、技术敏感、高安全关键词
- L0-L4动态路由：基线、轻量保护、DistanceDP、FHE密态检索、TEE可选增强
- 多索引路线展示：HNSW、IVF-PQ、Flat、Encrypted HNSW
- 可选测试场景：普通知识查询、个人信息查询、核心技术查询、密钥保护场景、基线对照实验
- 分级保护页面：解释为什么需要L0-L4，并提供各等级路线对比
- 创新架构页面：展示从查询输入到安全生成、审计留痕的完整链路
- Top-K知识片段检索：使用 TF-IDF 模拟向量检索流程
- 安全生成说明：展示最小必要上下文和保护路线
- 审计日志：记录风险等级、保护路线、索引类型和操作链

## 本地运行

```bash
cd privrag_demo
python backend/app.py
```

访问：

```text
http://127.0.0.1:5000
```

## 服务器部署

直接将 `privrag_demo` 上传到服务器，安装依赖后运行：

```bash
pip install -r requirements.txt
python backend/app.py
```

生产环境可用 `gunicorn` 或 `waitress` 托管 Flask。

也可以直接使用仓库内的 `run_server.sh` 或 `privrag.service` 作为服务器启动模板。

可选环境变量：

```bash
PRIVRAG_HOST=0.0.0.0
PRIVRAG_PORT=5000
PRIVRAG_DEBUG=0
```

如果服务器不能访问外网 CDN，可将 Vue 运行时下载到 `frontend/assets/vue.global.prod.js`，再把 `frontend/index.html` 中的 Vue 引用改成本地路径。

## 说明

当前版本是展示型原型：L1/L2策略、敏感识别、路由和审计为真实逻辑；FHE、加密HNSW和TEE部分以接口化和流程展示为主。后续可以逐步接入真实 embedding、FAISS HNSW、TenSEAL/SEAL 小规模密态计算和文档上传模块。
