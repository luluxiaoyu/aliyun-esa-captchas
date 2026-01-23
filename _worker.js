/**
 * ESA Edge Routine - 验证码验签微服务
 */

const SERVER_SECRET = "secret"; 

// 错误码映射
const ERROR_MAP = {
  "T001": "验证通过",
  "F003": "参数解析错误",
  "F005": "场景ID不存在",
  "F017": "Token被修改",
  "F018": "重复使用",
  "F019": "验证超时",
  "F020": "票据不匹配",
  "F021": "SceneId不一致"
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

export default {
  // 忽略后面的参数，因为我们已经知道 env 没传进来
  async fetch(request) {
    const url = new URL(request.url);

    // 1. CORS 预检
    if (request.method === "OPTIONS") {
      return new Response(null, {
          headers: {
              "Access-Control-Allow-Origin": "*",
              "Access-Control-Allow-Methods": "GET, OPTIONS",
              "Access-Control-Allow-Headers": "*"
          }
      });
    }

    // 2. 核心业务接口
    if (url.pathname === "/api/captcha" && request.method === "GET") {
      
      // --- A. 鉴权 ---
      const inputSecret = url.searchParams.get("secret");
      
      if (inputSecret !== SERVER_SECRET) {
        // 返回 403 并提示正确的用法
        return responseJSON(403, "鉴权失败: Secret 错误或丢失", {
             tip: "请确保请求 URL 包含 ?secret=secret"
        });
      }

      // --- B. 检查 Header ---
      const verifyCode = request.headers.get("x-captcha-verify-code");

      if (!verifyCode) {
        return responseJSON(500, "配置错误: ESA WAF 未注入 Header", {
             tip: "请检查 ESA 控制台 WAF 规则配置"
        });
      }

      // --- C. 返回结果 ---
      if (verifyCode === "T001") {
        return responseJSON(0, "验证通过", {
          req_id: crypto.randomUUID(),
          verify_code: "T001"
        });
      } else {
        const cnMsg = ERROR_MAP[verifyCode] || `未知错误: ${verifyCode}`;
        return responseJSON(400, cnMsg, {
          verify_code: verifyCode
        });
      }
    }

    // 404
    return new Response("ESA Captcha Service: 404 Not Found", { status: 404 });
  }
};
