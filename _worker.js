// 统一响应格式
function responseJSON(code, msg, data = null, status = 200) {
  return new Response(JSON.stringify({ code, msg, data }), {
    status: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*", // 允许跨域调试
      "Access-Control-Allow-Headers": "*"
    },
  });
}

// 错误码映射表
const ERROR_MAP = {
  "T001": "验证通过",
  "F003": "CaptchaVerifyParam解析错误",
  "F005": "场景ID（SceneId）不存在",
  "F017": "VerifyToken内容被修改",
  "F018": "验签数据重复使用",
  "F019": "验签超出时间限制（有效期90秒）或未发起验证就验签",
  "F020": "验签票据与场景ID或用户不匹配",
  "F021": "验证的SceneId和验签的SceneId不一致"
};

function getSafeSecret(env) {
  try {
    if (typeof SERVER_SECRET !== 'undefined') {
      return SERVER_SECRET;
    }
  } catch (e) {}
  if (env && env.SERVER_SECRET) {
    return env.SERVER_SECRET;
  }
  return "default_secret";
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS 预检
    if (request.method === "OPTIONS") {
      return new Response(null, {
          headers: {
              "Access-Control-Allow-Origin": "*",
              "Access-Control-Allow-Methods": "GET, OPTIONS",
              "Access-Control-Allow-Headers": "*"
          }
      });
    }

    // 路由匹配
    if (url.pathname === "/api/captcha" && request.method === "GET") {
      
      // --- 内部鉴权 (检查 Secret) ---
      const inputSecret = url.searchParams.get("secret");
      
      // 使用兼容函数获取密钥
      const CONFIG_SECRET = getSafeSecret(env);

      if (inputSecret !== CONFIG_SECRET) {
        return responseJSON(403, "接口鉴权失败: Secret 错误或丢失", {
           tip: "请检查后端请求是否携带了正确的 secret 参数，或 ESA 环境变量 SERVER_SECRET 是否配置正确"
        });
      }

      // --- 验证码结果检查 ---
      const verifyCode = request.headers.get("x-captcha-verify-code");

      if (!verifyCode) {
        return responseJSON(500, "配置错误: 未检测到 ESA 验证结果 (Missing Header)", {
             tip: "请检查 ESA 控制台 WAF 规则：URI是否正确? 方法是否为GET? 是否启用了Header注入?"
        });
      }

      // --- 结果映射 ---
      if (verifyCode === "T001") {
        return responseJSON(0, ERROR_MAP["T001"], {
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

    // 404 处理
    return new Response("ESA Captcha Service: 404 Not Found", { status: 404 });
  }
};
