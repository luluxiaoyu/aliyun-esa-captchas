/**
 * ESA Edge Routine - 混合模式 (业务 + 调试)
 * 1. 业务接口: /api/captcha (目前使用硬编码密钥)
 * 2. 侦探接口: /env (用于寻找失踪的环境变量)
 */

// ★★★ 你的硬编码密钥 (业务接口兜底使用) ★★★
const HARDCODED_SECRET = "secret"; 

// 统一响应格式
function responseJSON(code, msg, data = null, status = 200) {
  return new Response(JSON.stringify({ code, msg, data }), {
    status: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "*"
    },
  });
}

// 错误码映射
const ERROR_MAP = {
  "T001": "验证通过",
  "F003": "CaptchaVerifyParam解析错误",
  "F005": "场景ID不存在",
  "F017": "VerifyToken被修改",
  "F018": "验签数据重复使用",
  "F019": "验证超时",
  "F020": "票据不匹配",
  "F021": "SceneId不一致"
};

export default {
  // ★ 使用 ...args 接收所有参数，防止参数错位导致的丢失
  async fetch(request, ...args) {
    const url = new URL(request.url);

    // 0. CORS 预检
    if (request.method === "OPTIONS") {
      return new Response(null, {
          headers: {
              "Access-Control-Allow-Origin": "*",
              "Access-Control-Allow-Methods": "GET, OPTIONS",
              "Access-Control-Allow-Headers": "*"
          }
      });
    }

    // ==========================================
    // 🕵️‍♂️ 侦探接口: /env
    // 访问此接口查看 SERVER_SECRET 到底在哪
    // ==========================================
    if (url.pathname === "/env") {
      
      const report = {
        title: "ESA 环境变量大搜查",
        timestamp: new Date().toISOString(),
        args_received: args.length, // 看看收到了几个参数
        findings: []
      };

      // 1. 检查所有传入参数 (Args)
      args.forEach((arg, index) => {
        const info = {
          index: index,
          type: typeof arg,
          is_object: arg && typeof arg === 'object',
          keys: [],
          has_waitUntil: false,
          found_secret: false,
          secret_value: null
        };

        if (info.is_object) {
          try {
            // 看看这个对象里有哪些 Key
            info.keys = Object.keys(arg); 
            // 检查是否有 waitUntil (如果有，说明它是 ctx 上下文对象)
            info.has_waitUntil = typeof arg.waitUntil === 'function';
            // 检查是否有 SERVER_SECRET
            if (arg.SERVER_SECRET) {
              info.found_secret = true;
              info.secret_value = arg.SERVER_SECRET;
            }
          } catch(e) { info.error = e.message }
        }
        report.findings.push({ source: `Argument[${index}]`, ...info });
      });

      // 2. 检查全局变量 (Global Scope)
      let globalSecret = null;
      try {
        if (typeof SERVER_SECRET !== 'undefined') {
          globalSecret = SERVER_SECRET;
        }
      } catch(e) {}

      report.findings.push({
        source: "Global Scope",
        found_secret: !!globalSecret,
        secret_value: globalSecret,
        note: "如果这里找到了，说明是 ServiceWorker 模式注入"
      });

      // 3. 检查 globalThis
      report.findings.push({
        source: "globalThis",
        found_secret: !!globalThis.SERVER_SECRET,
        secret_value: globalThis.SERVER_SECRET
      });

      return new Response(JSON.stringify(report, null, 2), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }


    // ==========================================
    // 💼 业务接口: /api/captcha
    // ==========================================
    if (url.pathname === "/api/captcha" && request.method === "GET") {
      
      // --- 内部鉴权 ---
      const inputSecret = url.searchParams.get("secret");
      
      // 目前直接使用硬编码常量 (等 /env 查出结果后，我们可以改成动态获取)
      if (inputSecret !== HARDCODED_SECRET) {
        return responseJSON(403, "接口鉴权失败: Secret 错误或丢失", {
             tip: "请检查 URL 参数 ?secret=..."
        });
      }

      // --- 验证码结果检查 ---
      const verifyCode = request.headers.get("x-captcha-verify-code");

      if (!verifyCode) {
        return responseJSON(500, "配置错误: 未检测到 ESA 验证结果 (Missing Header)", {
             tip: "请检查 ESA 控制台 WAF 规则"
        });
      }

      // --- 结果映射 ---
      if (verifyCode === "T001") {
        return responseJSON(0, "验证通过", {
          req_id: crypto.randomUUID(),
          verify_code: "T001"
        });
      } else {
        const cnMsg = ERROR_MAP[verifyCode] || `未知错误码: ${verifyCode}`;
        return responseJSON(400, cnMsg, {
          verify_code: verifyCode
        });
      }
    }

    return new Response("ESA Captcha Service: 404 Not Found", { status: 404 });
  }
};
