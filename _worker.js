/**
 * ESA Edge Routine - 验证码验签微服务 (Service Worker 模式)
 * 接口: GET /api/captcha
 * 鉴权: Query 参数 ?secret=xxx
 * 环境变量: 直接作为全局变量使用 (SERVER_SECRET)
 */

// 监听 fetch 事件
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

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
  "F005": "场景ID（SceneId）不存在",
  "F017": "VerifyToken内容被修改",
  "F018": "验签数据重复使用",
  "F019": "验签超出时间限制（有效期90秒）或未发起验证就验签",
  "F020": "验签票据与场景ID或用户不匹配",
  "F021": "验证的SceneId和验签的SceneId不一致"
};

// 安全获取密钥的函数
function getSecret() {
  if (typeof SERVER_SECRET !== 'undefined') {
    return SERVER_SECRET;
  }
  return "default_secret"; // 兜底防止报错
}

async function handleRequest(request) {
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

  // 2. 路由匹配
  if (url.pathname === "/api/captcha" && request.method === "GET") {
    
    // --- A. 内部鉴权 ---
    const inputSecret = url.searchParams.get("secret");
    const configSecret = getSecret(); // 获取全局变量

    if (inputSecret !== configSecret) {
      return responseJSON(403, "接口鉴权失败: Secret 错误或丢失", {
         tip: "请检查 ESA 环境变量 SERVER_SECRET 是否配置"
      });
    }

    // --- B. 验证码结果检查 (从 Header 获取) ---
    const verifyCode = request.headers.get("x-captcha-verify-code");

    if (!verifyCode) {
      return responseJSON(500, "配置错误: 未检测到 ESA 验证结果 (Missing Header)", {
           tip: "请检查 ESA 控制台规则：URI是否正确? 方法是否为GET? 参数模式是否为Query?"
      });
    }

    // --- C. 结果映射 ---
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
