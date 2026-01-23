/**
 * EdgeOne Functions - 验证码验签微服务 (生产安全版)
 * * 安全机制:
 * 1. Query 参数鉴权: ?secret=xxx (匹配 SERVER_SECRET)
 * 2. Header 来源鉴权: x-esa-secret (匹配 ESA_SECRET)
 * 3. WAF 结果校验: x-captcha-verify-code (WAF 注入结果)
 */

// 错误码映射
const ERROR_MAP = {
  "T001": "验证通过",
  "F003": "CaptchaVerifyParam解析错误",
  "F005": "场景ID不存在",
  "F019": "验证超时",
  "F020": "票据不匹配"
};

// 辅助函数：统一 JSON 响应
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
  const { request, env } = context;
  const url = new URL(request.url);

  // ==========================================
  // 1. 环境配置检查
  // ==========================================
  const SERVER_SECRET = env.SERVER_SECRET;
  const ESA_SECRET = env.ESA_SECRET; 

  if (!SERVER_SECRET || !ESA_SECRET) {
    return responseJSON(500, "服务配置错误: 环境变量丢失 (SERVER_SECRET 或 ESA_SECRET)");
  }

  // ==========================================
  // 2. 仅处理 GET 请求
  // ==========================================
  if (request.method === "GET") {
    
    // --- A. Query 参数鉴权 ---
    const inputSecret = url.searchParams.get("secret");
    if (inputSecret !== SERVER_SECRET) {
      return responseJSON(403, "鉴权失败: URL Secret 错误");
    }

    // --- B. Header 来源鉴权 ---
    // 用于确保请求包含特定的 Header 密钥 (防止绕过)
    const headerSecret = request.headers.get("x-esa-secret");
    if (headerSecret !== ESA_SECRET) {
      return responseJSON(403, "鉴权失败: 非法来源 (Header Secret 错误或丢失)");
    }

    // --- C. 检查 WAF 验证结果 ---
    // 必须存在 x-captcha-verify-code 头，否则视为未经过 WAF 验证
    const verifyCode = request.headers.get("x-captcha-verify-code");

    if (!verifyCode) {
      return responseJSON(500, "安全警告: 未检测到 WAF 验证结果", {
           tip: "请求未经过验证码规则或规则配置错误"
      });
    }

    // --- D. 业务结果返回 ---
    if (verifyCode === "T001") {
      return responseJSON(0, "验证通过", {
        verify_code: "T001"
      });
    } else {
      // 返回具体的错误原因
      const cnMsg = ERROR_MAP[verifyCode] || `未知错误: ${verifyCode}`;
      return responseJSON(400, cnMsg, { verify_code: verifyCode });
    }
  }

  // 其他 Method
  return new Response("Method Not Allowed", { status: 405 });
}
