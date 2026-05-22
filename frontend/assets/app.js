const { createApp } = Vue;

createApp({
  data() {
    return {
      tab: "overview",
      loading: false,
      queryText: "请分析客户名单和合同报价是否适合走加密HNSW检索，是否需要TEE保护密钥？",
      result: null,
      auditItems: [],
      levels: {},
      selectedLevel: "L3",
      pipeline: ["隐私入口", "敏感度评估", "L0-L4路由", "多索引检索", "安全生成", "审计留痕"],
      scenarioIndex: 0,
      scenarios: [
        {
          name: "普通知识查询",
          expect: "预计 L1",
          query: "我想查一下公司知识库里关于报销流程和差旅标准的最新说明，帮我整理成简短答复。",
          desc: "低敏办公查询，展示入口防护、上下文最小化和日志脱敏。",
        },
        {
          name: "含个人信息查询",
          expect: "预计 L2",
          query: "客户张三反馈账号无法登录，手机号是13812345678，邮箱zhangsan@example.com，请帮我查相关售后处理记录。",
          desc: "含PII的业务查询，展示敏感实体识别、脱敏和DistanceDP查询扰动。",
        },
        {
          name: "核心技术方案查询",
          expect: "预计 L3",
          query: "帮我检索内部技术文档，看看核心算法里的向量库检索和模型权重管理方案有没有提到加密或访问控制。",
          desc: "高敏技术查询，展示FHE密态检索和加密HNSW路线。",
        },
        {
          name: "密钥保护场景",
          expect: "预计 L4",
          query: "法务要核对重点客户名单、合同报价和密钥托管记录，安全团队要求在TEE隔离环境里保护密钥，请只返回必要摘要并保留审计证据。",
          desc: "高安全业务查询，展示L3密态检索基础上的TEE可选增强。",
        },
        {
          name: "基线对照实验",
          expect: "预计 L0",
          query: "今天做Plain RAG基线测试，先用公开样例文档跑一遍普通检索，记录HNSW和Flat的返回差异。",
          desc: "实验对照查询，展示L0基线评估不是生产保护路线。",
        },
      ],
      archNodes: [
        { kicker: "01", title: "隐私入口层", desc: "先做查询规范化、敏感实体识别和上下文最小化，减少原始输入暴露。" },
        { kicker: "02", title: "策略决策引擎", desc: "根据敏感度、延迟需求和安全要求，决定走哪一级保护和哪类索引。" },
        { kicker: "03", title: "L0-L4分级保护", desc: "把FHE、DP、TEE等路线变成可执行等级，避免所有查询一刀切。" },
        { kicker: "04", title: "多索引检索层", desc: "以HNSW为核心，同时适配IVF-PQ和Flat，兼顾性能、精度和安全。" },
        { kicker: "05", title: "密码学保护层", desc: "用DistanceDP保护中敏查询，用CKKS FHE支撑高敏密态检索。" },
        { kicker: "06", title: "安全生成与审计", desc: "只送入最小必要上下文，并记录风险、路线、索引和保护操作。" },
      ],
      innovationCards: [
        {
          title: "不是所有查询都重加密",
          tag: "L0-L4动态分级",
          desc: "先判断查询风险，再选择轻量保护、DP扰动、FHE密态检索或TEE可选增强，避免一刀切。",
        },
        {
          title: "核心路线不依赖TEE",
          tag: "纯密码学主线",
          desc: "L2/L3以DistanceDP和CKKS FHE为核心，TEE只作为L4密钥保护增强，不绑死硬件。",
        },
        {
          title: "不是只做Flat暴力检索",
          tag: "加密HNSW核心索引",
          desc: "突出HNSW图索引在密态场景下的适配，并兼容IVF-PQ和Flat，体现工程可落地性。",
        },
        {
          title: "安全性可以解释和审计",
          tag: "可论证安全闭环",
          desc: "每次查询都记录风险、路线、索引和保护操作，让方案不是黑盒，而是可追溯、可评估。",
        },
      ],
    };
  },
  computed: {
    pageTitle() {
      return {
        overview: "创新点总览",
        query: "查询演示控制台",
        levels: "L0-L4分级保护体系",
        architecture: "系统创新架构",
        audit: "安全审计日志",
      }[this.tab];
    },
    resultHighlights() {
      if (!this.result) return [];
      const items = [
        `识别到${this.result.risk.level}风险查询，自动选择${this.result.route.level}路线`,
        `当前检索索引：${this.result.route.index}`,
        this.result.route.is_tee_required
          ? "TEE只作为密钥保护增强，核心检索仍按L3密态路线理解"
          : "当前路线不依赖TEE硬件",
      ];
      if (this.result.route.level === "L2") {
        items.push("体现DistanceDP查询扰动，适合中敏查询");
      }
      if (["L3", "L4"].includes(this.result.route.level)) {
        items.push("体现FHE密态检索和加密HNSW核心创新");
      }
      return items;
    },
  },
  async mounted() {
    await this.loadConfig();
  },
  methods: {
    async loadConfig() {
      const res = await fetch("/api/config");
      const data = await res.json();
      this.levels = data.levels;
      this.pipeline = data.pipeline;
    },
    fillExample() {
      this.scenarioIndex = (this.scenarioIndex + 1) % this.scenarios.length;
      this.queryText = this.scenarios[this.scenarioIndex].query;
    },
    selectScenario(index) {
      this.scenarioIndex = index;
      this.queryText = this.scenarios[index].query;
    },
    goDemo() {
      this.tab = "query";
      window.setTimeout(() => this.submitQuery(), 60);
    },
    async submitQuery() {
      if (!this.queryText.trim()) return;
      this.loading = true;
      try {
        const res = await fetch("/api/query", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: this.queryText }),
        });
        this.result = await res.json();
        await this.loadAudit();
      } finally {
        this.loading = false;
      }
    },
    async loadAudit() {
      const res = await fetch("/api/audit");
      const data = await res.json();
      this.auditItems = data.items.reverse();
    },
    async openAudit() {
      this.tab = "audit";
      await this.loadAudit();
    },
  },
}).mount("#app");
