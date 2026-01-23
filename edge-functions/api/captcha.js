/**
 * EdgeOne Functions - 调试专用版
 * 功能: 遇到错误时，强制输出所有 Request Headers
 */

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

  // 1. 收集所有请求头 (核心调试逻辑)
  const allHeaders = {};
  // 使用 forEach 遍历 Headers 对象
  request.headers.forEach((value, key) => {
    allHeaders[key] = value;
  });

  // 2. 基础鉴权 (Secret)
  const SERVER_SECRET = env.SERVER_SECRET;
  const ESA_SECRET = env.ESA_SECRET;

  if (!SERVER_SECRET) return responseJSON(500, "ENV SERVER_SECRET 未配置");
  
  // A. Query Secret 检查
  if (url.searchParams.get("secret") !== SERVER_SECRET) {
    return responseJSON(403, "Query Secret 错误");
  }

  // B. Header Secret 检查 (如果有配置 ESA_SECRET，则检查)
  // 调试期间，如果你担心是这个拦截了，可以暂时注释掉下面这几行
  if (ESA_SECRET) {
     const headerSecret = request.headers.get("x-esa-secret");
     if (headerSecret !== ESA_SECRET) {
        return responseJSON(403, "Header Secret (x-esa-secret) 错误或丢失", {
            received_headers: allHeaders // 鉴权失败也把头打印出来看看
        });
     }
  }

  // 3. 检查 WAF 验证结果
  const verifyCode = request.headers.get("x-captcha-verify-code");

  if (!verifyCode) {
    // ★★★ 调试重点：返回 500 的同时，把收到的所有头都吐出来 ★★★
    return responseJSON(500, "安全警告: 未检测到 WAF 验证结果", {
         tip: "请仔细检查下方 received_headers 中是否存在验证字段，或字段名是否有差异",
         // 打印所有头，让你看个清楚
         received_headers: allHeaders, 
         // 打印当前请求的方法和URL，确认没有被重定向
         request_info: {
             method: request.method,
             url: request.url
         }
    });
  }

  // 4. 正常逻辑
  return responseJSON(0, "验证通过", {
    req_id: crypto.randomUUID(),
    verify_code: verifyCode,
    // 调试模式下，成功了也顺便看看头（可选）
    // debug_headers: allHeaders 
  });
}
