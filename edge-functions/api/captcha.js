/**
 * EdgeOne Functions - 验证码验签微服务 (环境变量版)
 * 文档参考: context.env 包含环境变量
 */

// 错误码映射
const ERROR_MAP = {
  "T001": "验证通过",
  "F003": "CaptchaVerifyParam解析错误",
  "F005": "场景ID不存在",
  "F019": "验证超时",
  "F020": "票据不匹配"
};

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

export async function onRequest(context) {
  const { request, env } = context; // ★ 核心：环境变量在这里
  const url = new URL(request.url);

  // ==========================================
  // 🕵️‍♂️ 调试接口: /api/captcha/env (上线后请删除)
  // 访问此路径查看环境变量是否生效
  // ==========================================
  if (url.pathname.endsWith("/env")) {
    return responseJSON(0, "环境诊断报告", {
      platform: "Tencent EdgeOne",
      has_env_object: !!env,
      // 安全起见，只显示是否存在，不显示具体值
      has_server_secret: !!(env && env.SERVER_SECRET), 
      all_keys: env ? Object.keys(env) : []
    });
  }

  // ==========================================
  // 💼 业务逻辑
  // ==========================================
  
  // 1. 获取密钥 (优先从环境变量取，取不到则报错)
  const SERVER_SECRET = env.SERVER_SECRET;

  if (!SERVER_SECRET) {
    return responseJSON(500, "配置错误: 环境变量 SERVER_SECRET 未配置");
  }

  // 2. 仅处理 GET
  if (request.method === "GET") {
    
    // A. 鉴权
    const inputSecret = url.searchParams.get("secret");
    if (inputSecret !== SERVER_SECRET) {
      return responseJSON(403, "鉴权失败: Secret 错误");
    }

    // B. 检查 Header (EO WAF 注入)
    const verifyCode = request.headers.get("x-captcha-verify-code");
    
    // 如果是本地调试，可能没有 Header，给个模拟值方便测试
    // 上线时请删除 `|| "T001"`
    const finalCode = verifyCode || "T001"; 

    if (finalCode === "T001") {
      return responseJSON(0, "验证通过", {
        req_id: crypto.randomUUID(),
        verify_code: "T001"
      });
    } else {
      const cnMsg = ERROR_MAP[finalCode] || `未知错误: ${finalCode}`;
      return responseJSON(400, cnMsg, { verify_code: finalCode });
    }
  }

  return new Response("Method Not Allowed", { status: 405 });
}