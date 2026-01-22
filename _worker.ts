/**
 * ESA Edge Routine - 验证码验签微服务 (TypeScript 版)
 * 接口: GET /api/captcha
 * 鉴权: Query 参数 ?secret=xxx
 */

// 1. 定义环境变量的结构 (这样你就知道 env 里有什么了)
interface Env {
  SERVER_SECRET?: string; // 从控制台注入的变量
  // TICKET_EXPIRE?: string; // 如果有其他变量也可以加在这里
}

// ★★★ 硬编码备用密钥 (如果环境变量配置失败，回退使用这个) ★★★
const HARDCODED_SECRET = "secret";

// 错误码映射表
const ERROR_MAP: Record<string, string> = {
  "T001": "验证通过",
  "F003": "CaptchaVerifyParam解析错误",
  "F005": "场景ID（SceneId）不存在",
  "F017": "VerifyToken内容被修改",
  "F018": "验签数据重复使用",
  "F019": "验签超出时间限制（有效期90秒）或未发起验证就验签",
  "F020": "验签票据与场景ID或用户不匹配",
  "F021": "验证的SceneId和验签的SceneId不一致"
};

// 辅助函数：统一响应格式
function responseJSON(code: number, msg: string, data: any = null, status: number = 200): Response {
  return new Response(JSON.stringify({ code, msg, data }), {
    status: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*", // 允许跨域调试
      "Access-Control-Allow-Headers": "*"
    },
  });
}

// 2. 这里的 export default 必须符合 ESA 的 ESM 标准
export default {
  // 注意参数类型：request 是 Request，env 是我们要用的 Env 接口
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
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
      
      // --- A. 内部鉴权 ---
      const inputSecret = url.searchParams.get("secret");
      
      // ★ 智能获取密钥：优先用环境变量，没有则用硬编码常量
      // 在 TS 里，env.SERVER_SECRET 会有自动补全，非常爽
      const activeSecret = env.SERVER_SECRET || HARDCODED_SECRET;

      if (inputSecret !== activeSecret) {
        return responseJSON(403, "接口鉴权失败: Secret 错误或丢失", {
           tip: "请检查后端请求的 secret 参数是否正确"
        });
      }

      // --- B. 验证码结果检查 ---
      // 获取 ESA WAF 注入的验证结果 Header
      const verifyCode = request.headers.get("x-captcha-verify-code");

      if (!verifyCode) {
        return responseJSON(500, "配置错误: 未检测到 ESA 验证结果 (Missing Header)", {
             tip: "请检查 ESA 控制台 WAF 规则：URI是否正确? 方法是否为GET? 是否启用了Header注入?"
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
};
