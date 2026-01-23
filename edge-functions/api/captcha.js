/**
 * EdgeOne Functions - 验证码验签微服务
 * 逻辑：ESA WAF 负责拦截非法请求 -> EdgeOne 负责校验 ESA 身份
 */

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

  // 1. 获取并检查环境变量
  const SERVER_SECRET = env.SERVER_SECRET; // 业务接口密钥
  const ESA_SECRET = env.ESA_SECRET;       // ESA 回源信任密钥

  if (!SERVER_SECRET || !ESA_SECRET) {
    return responseJSON(500, "Service Configuration Error: Missing Environment Variables");
  }

  // 2. 仅允许 GET 请求
  if (request.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  // 3. 第一道防线：Query Secret (业务鉴权)
  // 校验 URL 参数 ?secret=xxx
  if (url.searchParams.get("secret") !== SERVER_SECRET) {
    return responseJSON(403, "Forbidden: Invalid Query Secret");
  }

  // 4. 第二道防线：ESA Secret (来源鉴权)
  // 校验 ESA 回源时携带的 Header x-esa-secret
  // 只要这个 Header 正确，说明请求通过了 ESA WAF 的验证码/滑块检查
  const headerSecret = request.headers.get("x-esa-secret");
  
  if (headerSecret !== ESA_SECRET) {
    return responseJSON(403, "Forbidden: Invalid ESA Origin Secret", {
      tip: "Request must pass through Alibaba ESA WAF"
    });
  }

  // 5. 验证通过
  // 能走到这里，说明 ESA WAF 没有拦截该请求，直接返回成功状态
  return responseJSON(0, "验证通过", {
    req_id: crypto.randomUUID(),
    verify_code: "T001" 
  });
}
