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

// 获取客户端IP
function getClientIP(request) {
  return request.headers.get("x-client-ip") || 
         request.headers.get("x-real-ip") || 
         request.headers.get("x-forwarded-for") || 
         "0.0.0.0";
}

// 签名 Ticket
async function signTicket(payload, secret) {
  const encoder = new TextEncoder();
  const algorithm = { name: "HMAC", hash: "SHA-256" };
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), algorithm, false, ["sign"]);
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = btoa(JSON.stringify(payload));
  const data = encoder.encode(`${header}.${body}`);
  const signatureBuffer = await crypto.subtle.sign(algorithm, key, data);
  const signature = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${header}.${body}.${signature}`;
}

// 验证 Ticket
async function verifyTicketSignature(token, secret) {
  try {
    const [headerB64, bodyB64, sigB64] = token.split('.');
    if (!headerB64 || !bodyB64 || !sigB64) return null;
    const encoder = new TextEncoder();
    const algorithm = { name: "HMAC", hash: "SHA-256" };
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret), algorithm, false, ["verify"]);
    const data = encoder.encode(`${headerB64}.${bodyB64}`);
    let signatureStr = sigB64.replace(/-/g, '+').replace(/_/g, '/');
    while (signatureStr.length % 4) signatureStr += '=';
    const signature = Uint8Array.from(atob(signatureStr), c => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify(algorithm, key, signature, data);
    if (!isValid) return null;
    return JSON.parse(atob(bodyB64));
  } catch (e) {
    return null;
  }
}

// 主逻辑
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS 处理
    if (request.method === "OPTIONS") {
      return new Response(null, {
          headers: {
              "Access-Control-Allow-Origin": "*",
              "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
              "Access-Control-Allow-Headers": "Content-Type"
          }
      });
    }

    const SECRET = env.SECRET_KEY || "default_dev_secret";
    const EXPIRE = env.TICKET_EXPIRE ? parseInt(env.TICKET_EXPIRE) : 60;

    // === 接口 1: 获取 Ticket (GET) ===
    if (url.pathname === "/api/get_ticket" && request.method === "GET") {
      
      const verifyCode = request.headers.get("x-captcha-verify-code"); // Header key 大小写不敏感
      
      if (verifyCode === "T001") {
        const clientIP = getClientIP(request);
        const now = Math.floor(Date.now() / 1000);
        
        const payload = {
          iss: "esa-edge",
          iat: now,
          exp: now + EXPIRE,
          ip: clientIP,
          req_id: crypto.randomUUID()
        };

        const ticket = await signTicket(payload, SECRET);

        return responseJSON(0, "验证通过", {
          ticket: ticket,
          expire_in: EXPIRE
        });
      } else {
        // ★★★ 调试代码开始：收集所有 Header ★★★
        const allHeaders = {};
        for (const [key, value] of request.headers) {
            allHeaders[key] = value;
        }
        // ★★★ 调试代码结束 ★★★

        return responseJSON(400, "验证码校验失败", {
          reason_code: verifyCode || "MISSING_HEADER",
          // 在这里输出所有收到的 Header，方便排查
          debug_headers: allHeaders,
          // 同时也输出一下当前请求的方法和URL，确认没有被重定向或者改写
          request_info: {
              method: request.method,
              url: request.url
          }
        });
      }
    }

    // === 接口 2: 验签 (POST) ===
    else if (url.pathname === "/api/verify_ticket" && request.method === "POST") {
      try {
        const body = await request.json();
        const ticket = body.ticket;
        const userIpFromBackend = body.client_ip; 

        if (!ticket) return responseJSON(400, "参数错误：缺少 Ticket");
        if (!userIpFromBackend) return responseJSON(400, "参数错误：缺少 client_ip");

        const payload = await verifyTicketSignature(ticket, SECRET);
        
        if (payload) {
          const now = Math.floor(Date.now() / 1000);
          
          if (payload.exp < now) {
            return responseJSON(401, "验证失败：Ticket 已过期");
          }

          if (payload.ip !== userIpFromBackend) {
              return responseJSON(403, "安全警告：IP 地址不匹配", {
                  registered_ip: payload.ip,
                  current_ip: userIpFromBackend
              });
          }

          return responseJSON(0, "Ticket 有效", { 
              req_id: payload.req_id,
              verified_ip: payload.ip 
          });
        } else {
          return responseJSON(403, "验证失败：无效的签名");
        }

      } catch (e) {
        return responseJSON(500, "服务器内部错误: " + e.message);
      }
    }

    // 404 处理
    if (url.pathname === "/404.html") {
        return fetch(request);
    }

    return Response.redirect(new URL("/404.html", request.url).toString(), 302);
  }
};
