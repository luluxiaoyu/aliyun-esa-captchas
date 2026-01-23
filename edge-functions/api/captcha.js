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

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const serverSecret = env.SERVER_SECRET;
  const esaDomain = env.ESA_DOMAIN;

  const responseHeaders = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "*"
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: responseHeaders });
  }

  if (!serverSecret || !esaDomain) {
    return new Response(JSON.stringify({ code: 500, msg: "服务端配置错误：环境变量丢失" }), { status: 500, headers: responseHeaders });
  }

  const inputSecret = url.searchParams.get("secret");
  const verifyParam = url.searchParams.get("captcha_verify_param");

  if (inputSecret !== serverSecret) {
    return new Response(JSON.stringify({ code: 403, msg: "鉴权失败：密钥错误" }), { status: 403, headers: responseHeaders });
  }

  if (!verifyParam) {
    return new Response(JSON.stringify({ code: 400, msg: "参数丢失：缺少 captcha_verify_param" }), { status: 400, headers: responseHeaders });
  }

  try {
    const targetUrl = `https://${esaDomain}/api/verify?secret=${inputSecret}&captcha_verify_param=${encodeURIComponent(verifyParam)}`;
    
    const verifyResponse = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'User-Agent': request.headers.get('User-Agent') || 'EdgeOne-Function'
      }
    });

    const verifyCode = verifyResponse.headers.get("x-captcha-verify-code");
    const msg = ERROR_MAP[verifyCode] || `未知错误: ${verifyCode}`;

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
    return new Response(JSON.stringify({ code: 500, msg: "内部错误", data: e.message }), { status: 500, headers: responseHeaders });
  }
}
