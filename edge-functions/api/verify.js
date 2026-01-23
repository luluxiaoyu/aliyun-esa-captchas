export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const serverSecret = env.SERVER_SECRET;

  if (url.searchParams.get("secret") !== serverSecret) {
    return new Response(JSON.stringify({ code: 403, msg: "鉴权失败" }), { 
      status: 403, 
      headers: { "Content-Type": "application/json" } 
    });
  }

  return new Response(JSON.stringify({ code: 0, msg: "ESA检测通过" }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
