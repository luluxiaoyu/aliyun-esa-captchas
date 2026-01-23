/**
 * ESA Edge Routine - 验证码验签
 */

// ★★★★★ 配置区域 ★★★★★
const SERVER_SECRET = "your_password_here";  // 接口密钥
const ESA_DOMAIN = "test.example.com";       // 域名
// ★★★★★★★★★★★★★★★★★★★★

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

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // 通用 CORS 头
    const responseHeaders = {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "*"
    };

    // CORS 预检
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: responseHeaders });
    }

    // ============================================================
    // 接口 1: /api/captcha (对外入口)
    // 功能: 发起回环请求，获取 ESA WAF 的验证结果
    // ============================================================
    if (pathname === "/api/captcha") {
      const inputSecret = url.searchParams.get("secret");
      const verifyParam = url.searchParams.get("captcha_verify_param");

      // 1. 基础鉴权
      if (inputSecret !== SERVER_SECRET) {
        return new Response(JSON.stringify({ code: 403, msg: "鉴权失败: 密钥错误" }), { status: 403, headers: responseHeaders });
      }

      // 2. 参数检查
      if (!verifyParam) {
        return new Response(JSON.stringify({ code: 400, msg: "参数丢失: 缺少 captcha_verify_param" }), { status: 400, headers: responseHeaders });
      }

      try {
        // 3. 构造回环请求 (请求本机 /api/verify 触发 WAF)
        const targetUrl = `https://${ESA_DOMAIN}/api/verify?secret=${inputSecret}&captcha_verify_param=${encodeURIComponent(verifyParam)}`;
        
        const verifyResponse = await fetch(targetUrl, {
          method: 'GET',
          headers: {
            'User-Agent': 'ESA-Internal-Loopback'
          }
        });

        // 4. 获取 WAF 注入的结果头
        const verifyCode = verifyResponse.headers.get("x-captcha-verify-code");
        const msg = ERROR_MAP[verifyCode] || `未知错误或WAF未生效: ${verifyCode}`;

        if (verifyCode === "T001") {
          return new Response(JSON.stringify({
            code: 0,
            msg: msg,
            data: {
              req_id: crypto.randomUUID(),
              verify_code: "T001"
            }
          }), { status: 200, headers: responseHeaders });
        } else {
          return new Response(JSON.stringify({
            code: 400,
            msg: msg,
            data: { verify_code: verifyCode }
          }), { status: 200, headers: responseHeaders });
        }

      } catch (e) {
        return new Response(JSON.stringify({ code: 500, msg: "内部回环请求失败", data: e.message }), { status: 500, headers: responseHeaders });
      }
    }

    // ============================================================
    // 接口 2: /api/verify (内部验证口)
    // 功能: 仅用于被 ESA WAF 拦截。如果能走到这里，说明验证已通过。
    // ============================================================
    if (pathname === "/api/verify") {
      const inputSecret = url.searchParams.get("secret");

      // 仅校验 Secret，不再校验其他 Header
      if (inputSecret !== SERVER_SECRET) {
        return new Response(JSON.stringify({ code: 403, msg: "Forbidden" }), { status: 403, headers: responseHeaders });
      }

      return new Response(JSON.stringify({ code: 0, msg: "ESA Check Passed" }), { status: 200, headers: responseHeaders });
    }

    return new Response(JSON.stringify({ code: 404, msg: "Not Found" }), { status: 404, headers: responseHeaders });
  }
};
