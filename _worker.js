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

// 获取客户端真实IP
function getClientIP(request) {
  return request.headers.get("x-client-ip") || 
         request.headers.get("x-real-ip") || 
         request.headers.get("x-forwarded-for") || 
         "0.0.0.0";
}

// jwt
async function signTicket(payload, secret) {
  const encoder = new TextEncoder();
  const algorithm = { name: "HMAC", hash: "SHA-256" };
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret), algorithm, false, ["sign"]
  );
  
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = btoa(JSON.stringify(payload));
  const data = encoder.encode(`${header}.${body}`);
  
  const signatureBuffer = await crypto.subtle.sign(algorithm, key, data);
  const signature = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    
  return `${header}.${body}.${signature}`;
}

// jwt 验签
async function verifyTicketSignature(token, secret) {
  try {
    const [headerB64, bodyB64, sigB64] = token.split('.');
    if (!headerB64 || !bodyB64 || !sigB64) return null;

    const encoder = new TextEncoder();
    const algorithm = { name: "HMAC", hash: "SHA-256" };
    const key = await crypto.subtle.importKey(
      "raw", encoder.encode(secret), algorithm, false, ["verify"]
    );

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

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  
  if (request.method === "OPTIONS") {
    return new Response(null, {
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
        }
    });
  }

  const SECRET = (typeof SECRET_KEY !== 'undefined') ? SECRET_KEY : "default_dev_secret";
  const EXPIRE = (typeof TICKET_EXPIRE !== 'undefined') ? parseInt(TICKET_EXPIRE) : 300;

  // 获取ticket
  if (url.pathname === "/api/get_ticket" && request.method === "POST") {
    
    // 检查 ESA 网关层的验证结果
    const verifyCode = request.headers.get("X-Captcha-Verify-Code");
    
    if (verifyCode === "T001") {
      // 获取用户 IP
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
      let errorMsg = "验证失败";
      if (verifyCode === "F019") errorMsg = "验证超时或未验证";
      if (verifyCode === "F020") errorMsg = "票据不匹配";
      
      return responseJSON(400, "验证码校验失败: " + errorMsg, {
        reason_code: verifyCode || "MISSING_HEADER"
      });
    }
  }

  // 验签接口
  else if (url.pathname === "/api/verify_ticket" && request.method === "POST") {
    try {
      const body = await request.json();
      const ticket = body.ticket;
      const userIpFromBackend = body.client_ip; 

      if (!ticket) return responseJSON(400, "参数错误：缺少 Ticket");
      if (!userIpFromBackend) return responseJSON(400, "参数错误：缺少 client_ip");

      // 验证签名
      const payload = await verifyTicketSignature(ticket, SECRET);
      
      if (payload) {
        const now = Math.floor(Date.now() / 1000);
        
        // 检查过期时间
        if (payload.exp < now) {
          return responseJSON(401, "验证失败：Ticket 已过期");
        }

        // 检查 IP 是否一致
        if (payload.ip !== userIpFromBackend) {
             return responseJSON(403, "安全警告：IP 地址不匹配", {
                 registered_ip: payload.ip,
                 current_ip: userIpFromBackend
             });
        }

        return responseJSON(0, "Ticket 有效", { uid: payload.uid });
      } else {
        return responseJSON(403, "验证失败：无效的签名");
      }

    } catch (e) {
      return responseJSON(500, "服务器内部错误: " + e.message);
    }
  }

  return responseJSON(404, "接口不存在", null, 404);
}
