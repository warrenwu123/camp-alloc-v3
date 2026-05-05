// backend/src/utils/response.js
// Shared response helpers and CORS configuration

export const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Refresh-Token',
  'Access-Control-Expose-Headers':'X-New-Access-Token',
};

export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS, ...extraHeaders },
  });
}

export function ok(data = {}, extraHeaders = {}) {
  return json({ ok: true, ...data }, 200, extraHeaders);
}

export function err(message, status = 400, detail = {}) {
  return json({ ok: false, error: message, ...detail }, status);
}

export function unauthorized(msg = 'Unauthorised') { return err(msg, 401); }
export function forbidden(msg = 'Forbidden')       { return err(msg, 403); }
export function notFound(msg = 'Not found')        { return err(msg, 404); }

export function preflight() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}
