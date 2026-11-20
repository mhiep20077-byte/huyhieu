/**
 * Locket Real Badge Sniffer (Read-Only Passthrough + iOS Notification Preview)
 * Chạy trên Shadowrocket (http-request & http-response) cho api.locketcamera.com & Cloud Functions.
 * - Tự động che toàn bộ Token / Header nhạy cảm trước khi in log & hiện thông báo.
 * - Bắn $notification.post cho các API quan trọng (changeProfileInfo, postMomentV2, getAccountInfo, getMomentOverlayData, getUser)
 *   hoặc mọi JSON response có chứa trường `badge`.
 * - 100% Passthrough ($done({})), không làm thay đổi dữ liệu gốc của Locket.
 */
(function () {
    const MAX_LEN = 15000;
    const TRUNC_LEN = 12000;
    const MASK = "[MASKED_FOR_SAFETY]";

    const SENSITIVE_HEADER_KEYS = new Set([
        "authorization",
        "x-firebase-appcheck",
        "firebase-instance-id-token",
        "x-firebase-gmpid",
        "cookie",
        "set-cookie",
        "x-api-key"
    ]);

    const SENSITIVE_BODY_KEYS = new Set([
        "idtoken",
        "id_token",
        "refreshtoken",
        "refresh_token",
        "accesstoken",
        "access_token",
        "password"
    ]);

    const NOTIFY_API_RE = /\/(changeProfileInfo|postMoment|getAccountInfo|getMomentOverlayData|getUser)/i;

    function maskHeaders(headers) {
        const out = {};
        if (!headers || typeof headers !== "object") return out;
        for (const key of Object.keys(headers)) {
            if (SENSITIVE_HEADER_KEYS.has(String(key).toLowerCase())) {
                out[key] = MASK;
            } else {
                out[key] = headers[key];
            }
        }
        return out;
    }

    function deepMaskJson(val) {
        if (Array.isArray(val)) return val.map(deepMaskJson);
        if (val && typeof val === "object") {
            const out = {};
            for (const k of Object.keys(val)) {
                if (SENSITIVE_BODY_KEYS.has(String(k).toLowerCase())) {
                    out[k] = MASK;
                } else {
                    out[k] = deepMaskJson(val[k]);
                }
            }
            return out;
        }
        return val;
    }

    function hasBadgeField(rawBody) {
        if (!rawBody || typeof rawBody !== "string") return false;
        return /"badge"\s*:/i.test(rawBody);
    }

    function formatBody(rawBody, compact) {
        if (rawBody === undefined || rawBody === null || rawBody === "") return "<empty>";
        let text = typeof rawBody === "string" ? rawBody : String(rawBody);
        try {
            const parsed = JSON.parse(text);
            const masked = deepMaskJson(parsed);
            text = compact ? JSON.stringify(masked) : JSON.stringify(masked, null, 2);
        } catch (_) {
            // Không phải JSON, giữ nguyên text
        }
        if (text.length > MAX_LEN) {
            return text.slice(0, TRUNC_LEN) + "\n... [TRUNCATED]";
        }
        return text;
    }

    try {
        const req = typeof $request !== "undefined" && $request ? $request : {};
        const url = req.url || "";
        const method = req.method || "GET";
        const shortPath = url.replace(/^https?:\/\/[^\/]+/i, "").slice(0, 60) || url;
        const hasNotifyFn =
            typeof $notification !== "undefined" &&
            $notification &&
            typeof $notification.post === "function";

        if (typeof $response === "undefined") {
            const safeHeaders = maskHeaders(req.headers);
            const bodyText = formatBody(req.body, false);
            console.log(
                `[REAL-SNIFFER][REQ] ${method} ${url}\n` +
                `Headers: ${JSON.stringify(safeHeaders, null, 2)}\n` +
                `Body:\n${bodyText}`
            );
            if (hasNotifyFn && (NOTIFY_API_RE.test(url) || hasBadgeField(req.body))) {
                const compact = formatBody(req.body, true).slice(0, 900);
                $notification.post(`[REQ] ${shortPath}`, method, compact);
            }
        } else {
            const status = ($response && ($response.status || $response.statusCode)) || 200;
            const rawResBody = $response ? $response.body : "";
            const bodyText = formatBody(rawResBody, false);
            console.log(
                `[REAL-SNIFFER][RES] ${status} ${url}\n` +
                `Body:\n${bodyText}`
            );
            if (hasNotifyFn && (NOTIFY_API_RE.test(url) || hasBadgeField(rawResBody))) {
                const compact = formatBody(rawResBody, true).slice(0, 900);
                $notification.post(`[RES ${status}] ${shortPath}`, "JSON Response", compact);
            }
        }
    } catch (err) {
        console.log(`[REAL-SNIFFER][ERR] ${err && err.message ? err.message : String(err)}`);
    }

    $done({});
})();
