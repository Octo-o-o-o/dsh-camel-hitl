window.__ModuleLoader__.load({ id: "dsh-camel-hitl", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
if (typeof document !== "undefined") { const sheets = {"client.css":"/* src/camel.module.css */\n.camel_overlayBackdrop {\n  position: fixed;\n  inset: 0;\n  z-index: 9999;\n  background: rgba(0, 0, 0, 0.62);\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  padding: 20px;\n}\n.camel_modal {\n  width: min(560px, 100%);\n  max-height: 85vh;\n  overflow: auto;\n  border-radius: var(--dsw-radius-md, 14px);\n  background: var(--dsw-alias-bg-layer-2, #1e293b);\n  color: var(--dsw-alias-label-primary, inherit);\n  border: 2px solid #dc2626;\n  box-shadow: 0 24px 48px rgba(0, 0, 0, 0.45);\n  padding: 20px 22px;\n  display: flex;\n  flex-direction: column;\n  gap: 14px;\n}\n.camel_modalHeader {\n  display: flex;\n  justify-content: space-between;\n  align-items: flex-start;\n  gap: 12px;\n}\n.camel_modalTitle {\n  margin: 0;\n  font-size: 16px;\n  font-weight: 700;\n  color: #ef4444;\n}\n.camel_badgeRow {\n  display: flex;\n  gap: 6px;\n  flex-wrap: wrap;\n}\n.camel_badgeDanger {\n  padding: 2px 8px;\n  border-radius: 999px;\n  font-size: 11px;\n  font-weight: 600;\n  background: rgba(239, 68, 68, 0.18);\n  color: #f87171;\n}\n.camel_badgeWarn {\n  padding: 2px 8px;\n  border-radius: 999px;\n  font-size: 11px;\n  font-weight: 600;\n  background: rgba(245, 158, 11, 0.18);\n  color: #fbbf24;\n}\n.camel_previewBox {\n  background: var(--dsw-alias-bg-layer-1, rgba(148, 163, 184, 0.08));\n  border: 1px solid var(--dsw-alias-border-l3, rgba(148, 163, 184, 0.25));\n  border-radius: var(--dsw-radius-sm, 8px);\n  padding: 10px 12px;\n  font-family: var(--ds-font-family-code, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);\n  font-size: 11px;\n  white-space: pre-wrap;\n  word-break: break-all;\n}\n.camel_digestLine {\n  font-family: var(--ds-font-family-code, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);\n  font-size: 11px;\n  color: var(--dsw-alias-label-secondary, #94a3b8);\n}\n.camel_modalActions {\n  display: flex;\n  justify-content: flex-end;\n  gap: 10px;\n}\n.camel_btn {\n  padding: 7px 13px;\n  border-radius: var(--dsw-radius-sm, 8px);\n  border: 1px solid var(--dsw-alias-border-l3, rgba(148, 163, 184, 0.3));\n  background: var(--dsw-alias-bg-layer-2, rgba(148, 163, 184, 0.1));\n  color: var(--dsw-alias-label-primary, inherit);\n  font-size: 13px;\n  font-weight: 500;\n  cursor: pointer;\n}\n.camel_btnDanger {\n  background: #dc2626;\n  border-color: #dc2626;\n  color: #ffffff;\n}\n.camel_panelRoot {\n  display: flex;\n  flex-direction: column;\n  height: 100%;\n  padding: 20px 24px;\n  gap: 16px;\n  overflow: auto;\n  font-family: var(--dsw-font-family, system-ui, -apple-system, sans-serif);\n  color: var(--dsw-alias-label-primary, inherit);\n  background: var(--dsw-alias-bg-base, transparent);\n}\n.camel_card {\n  background: var(--dsw-alias-bg-layer-2, rgba(148, 163, 184, 0.06));\n  border: 1px solid var(--dsw-alias-border-l3, rgba(148, 163, 184, 0.22));\n  border-radius: var(--dsw-radius-md, 10px);\n  padding: 14px 16px;\n}\n.camel_header {\n  display: flex;\n  justify-content: space-between;\n  align-items: center;\n  flex-wrap: wrap;\n  gap: 12px;\n}\n.camel_list {\n  margin: 8px 0 0;\n  padding-left: 18px;\n  font-size: 12px;\n  line-height: 1.7;\n}\n.camel_mono {\n  font-family: var(--ds-font-family-code, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);\n  font-size: 11px;\n}\n"}; for (const sheetPath of Object.keys(sheets)) { const tagId = "dsh-camel-hitl" + ":" + sheetPath; if (document.querySelector("style[data-plugin-css=" + JSON.stringify(tagId) + "]") === null) { const tag = document.createElement("style"); tag.dataset.plugin = "dsh-camel-hitl"; tag.dataset.pluginCss = tagId; tag.textContent = sheets[sheetPath]; document.head.appendChild(tag); } } }
"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/client.tsx
var client_exports = {};
__export(client_exports, {
  apply: () => apply,
  inject: () => inject
});
module.exports = __toCommonJS(client_exports);

// src/CamelPanel.tsx
var import_react = require("react");

// src/camel.module.css
var camel_default = {
  overlayBackdrop: "camel_overlayBackdrop",
  modal: "camel_modal",
  modalHeader: "camel_modalHeader",
  modalTitle: "camel_modalTitle",
  badgeRow: "camel_badgeRow",
  badgeDanger: "camel_badgeDanger",
  badgeWarn: "camel_badgeWarn",
  previewBox: "camel_previewBox",
  digestLine: "camel_digestLine",
  modalActions: "camel_modalActions",
  btn: "camel_btn",
  btnDanger: "camel_btnDanger",
  panelRoot: "camel_panelRoot",
  card: "camel_card",
  header: "camel_header",
  list: "camel_list",
  mono: "camel_mono"
};

// src/CamelPanel.tsx
var import_jsx_runtime = require("react/jsx-runtime");
function CamelPanel({ rpc, t }) {
  const [state, setState] = (0, import_react.useState)(null);
  const [busy, setBusy] = (0, import_react.useState)(false);
  const refresh = (0, import_react.useCallback)(async () => {
    setBusy(true);
    try {
      const next = await rpc.call("getState");
      setState(next);
    } finally {
      setBusy(false);
    }
  }, [rpc]);
  (0, import_react.useEffect)(() => {
    void refresh();
  }, [refresh]);
  const toggleMode = async () => {
    if (!state) return;
    const nextMode = state.mode === "enforce" ? "shadow" : "enforce";
    await rpc.call("setMode", { mode: nextMode });
    await refresh();
  };
  return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: camel_default.panelRoot, children: [
    /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: camel_default.header, children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", { style: { margin: 0, fontSize: 18 }, children: t("title") }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { style: { margin: "4px 0 0", fontSize: 12, opacity: 0.72 }, children: t("subtitle") })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { style: { display: "flex", gap: 8 }, children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("button", { type: "button", className: camel_default.btn, disabled: busy || !state, onClick: () => void toggleMode(), children: [
          t("action.mode"),
          ": ",
          state?.mode ?? "\u2026"
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", { type: "button", className: camel_default.btn, disabled: busy, onClick: () => void refresh(), children: t("action.refresh") })
      ] })
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: camel_default.card, children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: t("section.taint") }),
      state && Object.keys(state.taintBySession).length > 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", { className: camel_default.list, children: Object.entries(state.taintBySession).map(([sid, list]) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", { children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: camel_default.mono, children: sid }),
        ":",
        " ",
        [...new Set(list.map((i) => `${i.origin}(${i.toolName})`))].join(", ")
      ] }, sid)) }) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { style: { fontSize: 12, opacity: 0.7 }, children: t("empty.taint") })
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: camel_default.card, children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)("strong", { children: t("section.protected") }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", { className: camel_default.list, children: (state?.protectedRules ?? []).map((rule) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { className: camel_default.mono, children: rule }, rule)) })
    ] })
  ] });
}

// src/StrongConfirmOverlay.tsx
var import_react2 = require("react");
var import_jsx_runtime2 = require("react/jsx-runtime");
function StrongConfirmOverlay({ rpc, t }) {
  const [pending, setPending] = (0, import_react2.useState)([]);
  const [submitting, setSubmitting] = (0, import_react2.useState)(false);
  const [nowMs, setNowMs] = (0, import_react2.useState)(() => Date.now());
  (0, import_react2.useEffect)(() => {
    let active = true;
    const poll = async () => {
      try {
        const res = await rpc.call("listPending");
        if (active) setPending(res.pending);
      } catch {
      }
    };
    void poll();
    const id = setInterval(() => {
      if (typeof document !== "undefined" && document.visibilityState === "visible") {
        setNowMs(Date.now());
      }
      void poll();
    }, 1500);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [rpc]);
  const current = pending[0];
  if (!current) return null;
  const remainingSec = Math.max(0, Math.floor((Date.parse(current.expiresAt) - nowMs) / 1e3));
  const expired = remainingSec <= 0;
  const respond = async (decision) => {
    if (submitting) return;
    setSubmitting(true);
    try {
      await rpc.call("respondConfirm", {
        requestId: current.requestId,
        decision,
        expectedDigest: current.argsDigest
      });
      const res = await rpc.call("listPending");
      setPending(res.pending);
    } finally {
      setSubmitting(false);
    }
  };
  return /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: camel_default.overlayBackdrop, role: "dialog", "aria-modal": "true", "aria-label": t("overlay.title"), children: /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: camel_default.modal, children: [
    /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: camel_default.modalHeader, children: [
      /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("h3", { className: camel_default.modalTitle, children: [
        t("overlay.title"),
        ": ",
        current.toolName
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { className: camel_default.badgeDanger, children: current.tier.toUpperCase() })
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: camel_default.badgeRow, children: [
      /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { className: camel_default.badgeDanger, children: t("overlay.noRemember") }),
      /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("span", { className: camel_default.badgeDanger, children: t("overlay.localOnly") }),
      current.untrustedOrigins.map((origin) => /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("span", { className: camel_default.badgeWarn, children: [
        "taint:",
        origin
      ] }, origin))
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("p", { style: { margin: 0, fontSize: 13 }, children: current.reason }),
    /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: camel_default.previewBox, children: JSON.stringify(current.preview, void 0, 2) }),
    /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: camel_default.digestLine, children: [
      "SHA-256: ",
      current.argsDigest,
      " \xB7 ",
      t("overlay.expiresIn"),
      " ",
      remainingSec,
      "s"
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: camel_default.modalActions, children: [
      /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("button", { type: "button", className: camel_default.btn, disabled: submitting, onClick: () => void respond("reject"), children: t("overlay.reject") }),
      /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(
        "button",
        {
          type: "button",
          className: `${camel_default.btn} ${camel_default.btnDanger}`,
          disabled: submitting || expired,
          onClick: () => void respond("approve"),
          children: t("overlay.approveOnce")
        }
      )
    ] })
  ] }) });
}

// src/client.tsx
var import_jsx_runtime3 = require("react/jsx-runtime");
var NS = "dshCamelHitl";
var PANEL_ID = "dsh-camel-hitl";
function CamelIcon() {
  return /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("svg", { width: "16", height: "16", viewBox: "0 0 16 16", fill: "none", "aria-hidden": "true", children: [
    /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("path", { d: "M8 1.5L13.5 3.8V8.2C13.5 11.5 11.1 14 8 14.8C4.9 14 2.5 11.5 2.5 8.2V3.8L8 1.5Z", stroke: "currentColor", strokeWidth: "1.4", strokeLinejoin: "round" }),
    /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("path", { d: "M8 5.2V8.8", stroke: "currentColor", strokeWidth: "1.5", strokeLinecap: "round" }),
    /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("circle", { cx: "8", cy: "11.2", r: "0.9", fill: "currentColor" })
  ] });
}
var inject = ["slots", "locale", "layout", "connection"];
function apply(ctx) {
  ctx.effect(() => {
    const disposeZh = ctx.locale.register(NS, "zh", {
      nav: "CaMeL \u5F3A\u5BA1\u6279",
      title: "CaMeL \u6C61\u70B9\u8FFD\u8E2A\u4E0E\u5F3A HITL \u5B88\u536B",
      subtitle: "\u6301\u4E45\u5316\u4E0D\u53EF\u4FE1\u6765\u6E90\u8FFD\u8E2A \xB7 ctx.tools.guard() \u5355\u8C03\u5B88\u536B \xB7 \u53C2\u6570\u6458\u8981\u7ED1\u5B9A\u5F3A\u786E\u8BA4",
      "action.mode": "\u8FD0\u884C\u6A21\u5F0F",
      "action.refresh": "\u5237\u65B0",
      "section.taint": "\u6D3B\u8DC3\u4F1A\u8BDD\u6C61\u70B9\u6765\u6E90\uFF08\u91CD\u542F/fork \u81EA\u52A8\u6062\u590D\uFF09",
      "section.protected": "\u5355\u8C03\u5B88\u536B\u654F\u611F\u8DEF\u5F84\u9ED1\u540D\u5355",
      "empty.taint": "\u5F53\u524D\u6CA1\u6709\u5DF2\u67D3\u8272\u7684\u6D3B\u8DC3\u4F1A\u8BDD",
      "overlay.title": "\u9AD8\u5371\u64CD\u4F5C\u5F3A\u786E\u8BA4",
      "overlay.noRemember": "\u5355\u6B21\u751F\u6548 \xB7 \u4E0D\u53EF\u8BB0\u4F4F",
      "overlay.localOnly": "\u4EC5\u9650\u672C\u673A\u786E\u8BA4 \xB7 \u7981\u8FDC\u7A0B\u5BA1\u6279",
      "overlay.expiresIn": "\u5269\u4F59",
      "overlay.reject": "\u62D2\u7EDD\u6267\u884C",
      "overlay.approveOnce": "\u6838\u5BF9\u6458\u8981\u5E76\u5355\u6B21\u653E\u884C"
    });
    const disposeEn = ctx.locale.register(NS, "en", {
      nav: "CaMeL HITL",
      title: "CaMeL Taint & Strong HITL Guard",
      subtitle: "Persistent taint lineage \xB7 monotonic ctx.tools.guard() \xB7 digest-bound confirmations",
      "action.mode": "Mode",
      "action.refresh": "Refresh",
      "section.taint": "Active Session Taint Lineage (Survives Restart & Fork)",
      "section.protected": "Monotonic Guard Protected Path Rules",
      "empty.taint": "No tainted active sessions",
      "overlay.title": "Strong Confirmation Required",
      "overlay.noRemember": "One-shot only \xB7 Non-rememberable",
      "overlay.localOnly": "Local UI only \xB7 Remote IM disabled",
      "overlay.expiresIn": "Expires in",
      "overlay.reject": "Deny",
      "overlay.approveOnce": "Verify Digest & Approve Once"
    });
    return () => {
      disposeZh();
      disposeEn();
    };
  }, "dsh-camel-hitl: dictionaries");
  const t = ctx.locale.bind(NS);
  const rpc = {
    async call(method, payload) {
      const res = await ctx.connection.rpc.call("/api", "dshCamelHitl", {
        method,
        payload: payload ?? {}
      });
      if (!res.ok) throw new Error(res.error?.message ?? `RPC failed: ${method}`);
      return res.value;
    }
  };
  ctx.slots.inject("shell.overlay", () => ctx.slots.register({
    name: "shell.overlay",
    id: `${PANEL_ID}.strong-confirm`,
    locale: NS,
    inject: () => ({ rpc, t })
  }, StrongConfirmOverlay));
  ctx.slots.inject("main", () => ctx.slots.register({
    name: "main",
    key: PANEL_ID,
    locale: NS,
    inject: () => ({ rpc, t })
  }, CamelPanel));
  ctx.slots.inject("sidebar.panellist", () => ctx.slots.register({
    name: "sidebar.panellist",
    id: PANEL_ID,
    order: 63,
    locale: NS,
    label: () => t("nav")
  }, CamelIcon));
}

return module.exports; } });
