/**
 * AegisAgent API Client
 * Wraps fetch with CSRF protection, error handling, and session expiration checks.
 */
var api = (function () {
  function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  function request(url, options) {
    options = options || {};
    var headers = options.headers || {};
    var method = (options.method || "GET").toUpperCase();

    headers["Accept"] = "application/json";

    if (method !== "GET" && method !== "HEAD") {
      headers["X-CSRF-Token"] = getCsrfToken();
      if (options.body && typeof options.body === "object" && !(options.body instanceof FormData)) {
        headers["Content-Type"] = "application/json";
        options.body = JSON.stringify(options.body);
      }
    }

    options.headers = headers;
    options.credentials = "same-origin";

    return fetch(url, options)
      .then(function (response) {
        if (response.status === 401) {
          window.location.href = "/login?expired=1";
          return Promise.reject(new Error("Session expired"));
        }
        return response.json().then(function (data) {
          if (!response.ok) {
            var errMsg = (data && data.error) || "Request failed (" + response.status + ")";
            return Promise.reject(new Error(errMsg));
          }
          return data;
        });
      });
  }

  return {
    get: function (url) {
      return request(url, { method: "GET" });
    },
    post: function (url, body) {
      return request(url, { method: "POST", body: body });
    },
    getCsrfToken: getCsrfToken,
    // Helper shortcuts
    getHealth: function () {
      return request("/api/health", { method: "GET" });
    },
    getOverview: function () {
      return request("/api/overview", { method: "GET" });
    },
    getPendingApprovals: function () {
      return request("/api/approvals/pending", { method: "GET" });
    },
    getApprovalHistory: function () {
      return request("/api/approvals/history", { method: "GET" });
    },
    decideApproval: function (requestId, requestHash, approved) {
      return request("/api/approvals/decide", {
        method: "POST",
        body: { request_id: requestId, request_hash: requestHash, approved: approved },
      });
    },
    sendChat: function (text) {
      return request("/api/console/send", {
        method: "POST",
        body: { text: text },
      });
    },
    newSession: function () {
      return request("/api/console/new_session", { method: "POST" });
    },
    clearThreat: function () {
      return request("/api/console/clear_threat", { method: "POST" });
    },
    startWorker: function () {
      return request("/api/worker/start", { method: "POST" });
    },
    actuateHardware: function (command) {
      return request("/api/hardware/actuate", {
        method: "POST",
        body: { command: command },
      });
    },
    getHardwareStatus: function () {
      return request("/api/hardware/status", { method: "GET" });
    },
    verifyAudit: function () {
      return request("/api/audit/verify", { method: "GET" });
    },
    switchRole: function (role) {
      return request("/api/auth/switch_role", {
        method: "POST",
        body: { role: role },
      });
    },
  };
})();

// Provide AegisAPI as an alias for compatibility
var AegisAPI = api;
