/* InfraScope remote access. All records and operations come from the authenticated gateway. */
(function () {
  "use strict";
  const base = "/api/remote-access",
    esc = (v) =>
      String(v ?? "").replace(
        /[&<>"']/g,
        (c) =>
          ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;",
          })[c],
      ),
    uid = () => crypto.randomUUID(),
    size = (n) =>
      n >= 1073741824
        ? (n / 1073741824).toFixed(2) + " GiB"
        : n >= 1048576
          ? (n / 1048576).toFixed(2) + " MiB"
          : n >= 1024
            ? (n / 1024).toFixed(1) + " KiB"
            : n + " B";
  const S = {
    user: null,
    csrf: "",
    tab: "access",
    access: [],
    assets: [],
    assetQuery: "",
    assetOffset: 0,
    assetFilters: {},
    assetGroups: [],
    assetGroupOffset: 0,
    organizations: [],
    organizationOffset: 0,
    imports: [],
    mode: "remote",
    renderEpoch: 0,
    viewEpoch: 0,
    people: [],
    peopleQuery: "",
    peopleOffset: 0,
    terms: new Map(),
    active: null,
    visible: new Set(),
    files: null,
    uploads: new Map(),
    window: uid(),
    layout: "horizontal",
    mounted: false,
  };
  let root, view, refreshTimer;
  async function api(
    url,
    method = "GET",
    data,
    headers = {},
    signal,
    gateway = "",
  ) {
    const epoch = S.renderEpoch;
    const r = await fetch(
      (gateway ? "/gateways/" + encodeURIComponent(gateway) : "") + (url.startsWith("/api/v1/") ? "" : base) + url,
      {
        method,
        credentials: "same-origin",
        cache: "no-store",
        headers: {
          ...(method === "GET" ? {} : { "X-CSRF-Token": S.csrf }),
          ...(data === undefined
            ? {}
            : {
                "Content-Type":
                  data instanceof Blob
                    ? "application/octet-stream"
                    : "application/json",
              }),
          ...headers,
        },
        body:
          data === undefined
            ? undefined
            : data instanceof Blob
              ? data
              : JSON.stringify(data),
        signal,
      },
    );
    let v;
    try {
      v = await r.json();
    } catch {
      throw Error(
        "远程接入网关未提供有效响应，请检查同源网关部署（HTTP " +
          r.status +
          "）",
      );
    }
    if (!r.ok && v.code === "gateway_route_required" && v.gatewayId && !gateway)
      return api(url, method, data, headers, signal, v.gatewayId);
    if ((v.gatewayId || gateway) && v.id && epoch === S.renderEpoch && S.user) {
      S.routes ??= new Map();
      S.routes.set(v.id, v.gatewayId || gateway);
    }
    if (!r.ok) {
      const e = Error(v.error || "请求失败");
      e.code = v.code;
      e.status = r.status;
      throw e;
    }
    return v;
  }
  function msg(s) {
    const e = root?.querySelector("#ra-message");
    if (e) e.textContent = s;
  }
  function button(text, action, id = "", extra = "") {
    return `<button data-ra="${action}" data-id="${esc(id)}" ${extra}>${text}</button>`;
  }
  function table(head, rows) {
    return `<table><thead><tr>${head.map((x) => "<th>" + x + "</th>").join("")}</tr></thead><tbody>${rows.join("") || `<tr><td colspan="${head.length}"><div class="ra-empty">没有可访问的记录</div></td></tr>`}</tbody></table>`;
  }
  function card(s) {
    return '<section class="ra-card">' + s + "</section>";
  }
  function input(label, name, value = "", type = "text") {
    return `<label>${label}<input name="${name}" type="${type}" value="${esc(value)}" ${type === "password" ? 'autocomplete="new-password"' : type === "datetime-local" ? 'step="any"' : ""}></label>`;
  }
  function select(label, name, options, value) {
    return `<label>${label}<select name="${name}">${options.map(([k, v]) => `<option value="${esc(k)}" ${k === value ? "selected" : ""}>${esc(v)}</option>`).join("")}</select></label>`;
  }
  function check(label, name, value) {
    return `<label><input type="checkbox" name="${name}" ${value ? "checked" : ""}> ${label}</label>`;
  }
  const categories = [["server", "服务器"], ["nas", "NAS"], ["pve", "PVE"], ["switch", "交换机"], ["printer", "打印机"], ["scanner", "扫描仪"], ["other", "其他"]];
  const ownershipRoles = [["userId", "使用人"], ["claimantId", "待认领负责人"], ["operationsId", "运维负责人"], ["businessId", "业务负责人"], ["notificationIds", "通知人"], ["backupIds", "备用联系人"]];
  function personLabel(person) {
    return `${person.display_name} · ${person.department || "未填写部门"} · ${person.id}${person.enabled ? "" : " [已停用]"}`;
  }
  function ownershipStatus(asset) {
    if (asset.ownershipLegacy) return "历史资产 · 责任待补录";
    return asset.ownership?.state === "assigned" ? "已分配" : asset.ownership?.state === "pending" ? "待认领" : "责任信息缺失";
  }
  function contactEmail(person) {
    if (S.user.role !== "admin") return person.email_configured ? "已配置邮箱（仅管理员可见地址）" : "未配置可投递邮箱";
    return person.email ? esc(person.email) + '<small>仅记录地址 · 未验证可投递性</small>' : '<span class="ra-warning">未填写可投递邮箱</span>';
  }
  function dialog(title, body, submit, action) {
    if (!S.user || S.logoutPending) throw Error("身份已失效，请重新读取登录状态");
    const epoch = S.renderEpoch;
    const d = document.createElement("dialog");
    d.innerHTML = `<h3>${esc(title)}</h3><form>${body}<p class="ra-error" role="alert"></p><div class="ra-bar"><button class="primary" type="submit">${esc(submit)}</button><button type="button" data-close>取消</button></div></form>`;
    root.append(d);
    d.querySelector("[data-close]").onclick = () => d.close();
    d.onclose = () => d.remove();
    d.querySelector("form").onsubmit = async (e) => {
      e.preventDefault();
      if (epoch !== S.renderEpoch || !S.user || S.logoutPending) return;
      if (window.InfraRemoteAssets.submitDisabled(d.dataset.submitting === "true", d.dataset.submitBlocked !== "true")) return;
      const b = d.querySelector("[type=submit]");
      d.dataset.submitting = "true";
      b.disabled = true;
      try {
        await action(new FormData(e.target), e.target, d);
        d.close();
      } catch (e) {
        d.querySelector(".ra-error").textContent = e.message;
      } finally {
        d.dataset.submitting = "false";
        b.disabled = window.InfraRemoteAssets.submitDisabled(false, d.dataset.submitBlocked !== "true");
      }
    };
    d.showModal();
    return d;
  }
  function jsonEditor(title, value, url, method = "POST") {
    dialog(
      title,
      '<label>配置（JSON）<textarea name="json" rows="18">' +
        esc(JSON.stringify(value, null, 2)) +
        "</textarea></label>",
      "保存",
      async (f) => {
        await api(url, method, JSON.parse(f.get("json")));
        await show(S.tab);
      },
    );
  }
  async function reauth() {
    return new Promise((resolve, reject) => {
      const d = dialog(
        "验证平台身份",
        input("当前平台密码", "password", "", "password"),
        "验证",
        async (f) => {
          await api("/auth/reauth", "POST", { password: f.get("password") });
          resolve();
        },
      );
      d.addEventListener("close", () => reject(Error("操作已取消")), {
        once: true,
      });
    });
  }
  async function render(initialTab, mode = S.mode) {
    if (mode === "remote" && S.mode !== "remote" && !initialTab) S.tab = "access";
    window.InfraOnboarding?.leave();
    const epoch = ++S.renderEpoch;
    ++S.viewEpoch;
    clearInterval(refreshTimer);
    S.mode = mode;
    if (initialTab) S.tab = initialTab;
    root =
      document.getElementById("io-content") ||
      document.getElementById("ra-root");
    root.classList.add("ra");
    const heading = mode === "onboarding" ? ["接入第一台 Linux 主机", "四步完成资产登记、客户端注册与首次真实上报"] : mode === "telemetry" ? ["Agent 与真实采集", "Rust 主机 / Docker / PVE · 同一资产 ID · HTTPS 签名上报 · PostgreSQL 持久化"] : mode === "inventory" ? ["设备与使用人", "统一资产 ID · 与远程资产同源 · 指标未采集不推断设备健康"] : mode === "people" ? ["组织与人员", "真实手工联系人目录 · 企业微信组织同步尚未接入 · 不等于平台账号"] : ["远程接入工作台", "账号级授权 · LinuxTab · SFTP · 用户电脑 RDP"];
    root.innerHTML =
      `<div class="page-heading"><div><small>INFRASTRUCTURE / ${mode === "remote" ? "REMOTE ACCESS" : "UNIFIED INVENTORY"}</small><h2>${heading[0]}</h2><p>${heading[1]}</p></div></div><div id="ra-message" role="status" aria-live="polite"></div><div id="ra-body"></div>`;
    root.onclick = click;
    view = root.querySelector("#ra-body");
    S.mounted = true;
    if (S.logoutPending) {
      view.innerHTML = card("注销请求仍在处理，尚未确认服务端会话状态。" + button("重新读取登录状态", "reload"));
      return;
    }
    let authenticated = false;
    try {
      const user = await api("/auth/me");
      if (epoch !== S.renderEpoch || !S.mounted) return;
      S.user = user;
      S.csrf = S.user.csrf;
      authenticated = true;
      if (S.user.mustChangePassword) {
        passwordDialog();
        view.innerHTML = card("请先更改初始密码。");
        return;
      }
      shell();
      if (!tabAllowed(S.tab) && !(mode === "people" && initialTab === "people")) S.tab = "access";
      const quickIntent = mode === "remote" && window.InfraQuickLaunch?.parseIntent(location.search);
      if (quickIntent) {
        const identity = S.user;
        if (quickIntent.userId !== identity.id) {
          const error = Error("当前浏览器登录用户与快捷启动器配对用户不同。请使用配对的平台账号登录后重试，未发起连接。");
          error.status = 403;
          throw error;
        }
        const access = await api("/my/access");
        if (epoch !== S.renderEpoch || !S.mounted || S.user !== identity) return;
        const selected = window.InfraQuickLaunch.authorizedAccount(access, quickIntent);
        S.access = access;
        // Consume the page intent before creating a session so refresh never repeats a command.
        history.replaceState(null, "", location.pathname);
        if (quickIntent.protocol === "sftp") {
          S.files = { account: quickIntent.accountId, path: "", offset: 0 };
          S.tab = "files";
        } else {
          let session;
          try { session = await api("/ssh/sessions", "POST", { assetId: quickIntent.assetId, accountId: quickIntent.accountId, cols: 100, rows: 28 }); }
          catch (error) {
            if (epoch === S.renderEpoch && S.mounted && S.user === identity) {
              await show("access");
              if (epoch !== S.renderEpoch || !S.mounted || S.user !== identity) return;
              msg("快捷 SSH 未连接：" + error.message + "。请在这台服务器的连接面板处理后重试。");
              await assetRemote(quickIntent.assetId);
            }
            return;
          }
          if (epoch !== S.renderEpoch || !S.mounted || S.user !== identity) {
            if (S.user === identity && !S.logoutPending) await api("/ssh/sessions/" + encodeURIComponent(session.id), "DELETE").catch(() => {});
            return;
          }
          await addTerminal(session.id, selected.asset_name + " / " + selected.username);
          S.tab = "terminal";
        }
      }
      const session = new URLSearchParams(location.search).get("sessionId");
      if (mode === "remote" && session && !S.terms.has(session)) {
        const data = await api("/ssh/sessions/" + encodeURIComponent(session));
        if (epoch !== S.renderEpoch || !S.mounted) return;
        await addTerminal(data.id, "接续会话", true);
        S.tab = "terminal";
      }
      await show(S.tab);
    } catch (e) {
      if (epoch !== S.renderEpoch || !S.mounted) return;
      if (e.status === 401) login();
      else if (authenticated) {
        const target = root.querySelector("#ra-view");
        if (target) target.innerHTML = card(`<h3>${e.status === 403 ? "没有此目录或页面的权限" : "当前页面读取失败"}</h3><p>${esc(e.message)}</p>${button("我的接入", "tab", "access")}${button("重新读取", "reload")}`);
      } else {
        invalidateIdentity();
        view.innerHTML = card(
          "<h3>远程网关尚不可用</h3><p>" +
            esc(e.message) +
            "</p><p>本模块需要启用同一项目中的 Go 服务与 PostgreSQL。现有监控演示数据不会被自动导入为远程连接目标。</p>" +
            button("重新检查", "reload"),
        );
      }
    }
    if (epoch !== S.renderEpoch || !S.mounted) return;
    clearInterval(refreshTimer);
    refreshTimer = setInterval(() => {
      if (S.mounted && ["transfers", "connectors"].includes(S.tab))
        show(S.tab).catch((e) => msg(e.message));
    }, 5000);
  }
  function tabAllowed(tab) {
    if (["getting-started", "access", "terminal", "files", "transfers", "assets", "connectors", "agents"].includes(tab)) return true;
    if (["people", "grants", "imports"].includes(tab)) return ["admin", "asset_manager"].includes(S.user?.role);
    if (["users", "groups", "sessions", "asset-groups", "organizations"].includes(tab)) return S.user?.role === "admin" && (!["asset-groups", "organizations"].includes(tab) || can("user.manage"));
    if (["audit", "health"].includes(tab)) return ["admin", "auditor"].includes(S.user?.role);
    return false;
  }
  function invalidateIdentity() {
    window.InfraOnboarding?.leave();
    ++S.renderEpoch;
    ++S.viewEpoch;
    clearInterval(refreshTimer);
    for (const term of S.terms.values()) {
      term.stopped = true;
      term.ws?.close();
      clearInterval(term.heartbeat);
      term.term?.dispose();
      term.panel?.remove();
    }
    for (const controller of S.uploadControllers?.values() || []) controller.abort();
    for (const controller of S.downloadControllers?.values() || []) controller.abort();
    for (const key of ["terms", "visible", "uploads", "uploadControllers", "downloadControllers", "routes", "rates"]) S[key]?.clear();
    for (const key of ["assets", "people", "access", "assetGroups", "organizations", "imports", "accountRows", "records"]) S[key] = [];
    for (const key of ["assetOffset", "peopleOffset", "assetGroupOffset", "organizationOffset"]) S[key] = 0;
    S.assetQuery = S.peopleQuery = S.csrf = "";
    S.assetFilters = {};
    S.user = S.files = S.active = null;
    S.fileEmbedded = false;
    S.tab = S.mode === "onboarding" ? "getting-started" : S.mode === "inventory" ? "assets" : S.mode === "people" ? "people" : S.mode === "telemetry" ? "agents" : "access";
    for (const d of root?.querySelectorAll("dialog") || []) { d.close(); d.remove(); }
    msg("");
  }
  async function logout() {
    if (S.logoutPending) return;
    const csrf = S.csrf;
    S.logoutPending = true;
    invalidateIdentity();
    const epoch = S.renderEpoch;
    view.innerHTML = card("正在注销；已清除本地身份数据，等待服务端确认…");
    try {
      await api("/auth/logout", "POST", {}, { "X-CSRF-Token": csrf });
      if (epoch === S.renderEpoch && S.mounted) login();
    } catch (e) {
      if (epoch === S.renderEpoch && S.mounted) view.innerHTML = card('<h3>注销未确认</h3><p>' + esc(e.message) + '</p><p>本地缓存已清除，但服务端会话可能仍有效。请重新读取真实会话状态，不会恢复旧缓存或假定已注销。</p>' + button("重新读取登录状态", "reload"));
    } finally {
      S.logoutPending = false;
    }
  }
  function shell() {
    const tabs = [
      ["getting-started", "逐步接入 Linux"],
      ["access", "我的接入"],
      ["terminal", "LinuxTab"],
      ["files", "SFTP 文件"],
      ["transfers", "传输任务"],
      ["assets", "资产与账号"],
      ["agents", "Agent 与采集"],
      ["connectors", "我的 Windows 设备"],
    ];
    if (["admin", "asset_manager"].includes(S.user.role))
      tabs.push(["grants", "账号分配"], ["people", "人员与责任"], ["imports", "导入与发现"]);
    if (S.user.role === "admin")
      tabs.push(
        ["asset-groups", "资产组可见范围"],
        ["organizations", "组织范围"],
        ["users", "平台用户"],
        ["groups", "用户组"],
        ["sessions", "会话管理"],
      );
    if (["admin", "auditor"].includes(S.user.role))
      tabs.push(["audit", "审计"], ["health", "网关状态"]);
    view.innerHTML = `<div class="ra-bar"><strong>${esc(S.user.displayName)}</strong><small>${esc(S.user.role)} · ${esc(S.user.gatewayId)}</small>${button("修改密码", "password")}${button("退出", "logout")}</div><div class="ra-tabs">${(S.mode === "onboarding" ? tabs.filter(([k]) => ["getting-started", "assets", "agents", "people"].includes(k)) : tabs).map(([k, v]) => button(v, "tab", k)).join("")}${S.mode === "onboarding" ? '<button data-page="help">使用手册</button>' : ""}</div><div id="ra-view"></div>`;
  }
  function login() {
    invalidateIdentity();
    const epoch = S.renderEpoch;
    view.innerHTML = card(
      '<form id="ra-login" class="ra-login"><small>INFRASCOPE</small><h3>登录 InfraScope 平台</h3>' +
        input("平台用户名", "username") +
        input("平台密码", "password", "", "password") +
        '<p class="ra-error" role="alert"></p><button class="primary">登录</button><p class="muted">平台身份与目标主机账号相互独立。</p></form>',
    );
    view.querySelector("form").onsubmit = async (e) => {
      e.preventDefault();
      const f = new FormData(e.target),
        b = e.target.querySelector("button");
      b.disabled = true;
      try {
        await api("/auth/login", "POST", {
          username: f.get("username"),
          password: f.get("password"),
        });
        if (epoch !== S.renderEpoch || !S.mounted) return;
        e.target.reset();
        await render();
      } catch (err) {
        e.target.querySelector(".ra-error").textContent = err.message;
      } finally {
        b.disabled = false;
      }
    };
  }
  function passwordDialog() {
    const epoch = S.renderEpoch;
    dialog(
      "修改平台密码",
      input("当前密码", "currentPassword", "", "password") +
        input("新密码（至少 12 字节）", "newPassword", "", "password"),
      "更新并重新登录",
      async (f) => {
        await api("/auth/password", "POST", Object.fromEntries(f));
        if (epoch === S.renderEpoch && S.mounted) login();
      },
    );
  }
  async function show(tab) {
    if (!S.user || !S.mounted) return;
    window.InfraOnboarding?.leave();
    const epoch = ++S.viewEpoch, mount = S.renderEpoch;
    const current = () => S.mounted && epoch === S.viewEpoch && mount === S.renderEpoch;
    if (tab === "files" && S.tab === "terminal" && S.fileEmbedded) {
      await filesView(root.querySelector("#ra-terminal-files"));
      return;
    }
    S.tab = tab;
    const target = root.querySelector("#ra-view");
    if (!target) return;
    try {
    if (!tabAllowed(tab)) {
      const error = Error(tab === "asset-groups" ? "仅平台管理员可管理资产组可见范围" : "当前角色无权读取此页面或人员目录");
      error.status = 403;
      throw error;
    }
    for (const t of S.terms.values()) t.panel.remove();
    for (const b of root.querySelectorAll("[data-ra=tab]"))
      b.classList.toggle("selected", b.dataset.id === tab);
    target.innerHTML = '<p class="muted">正在读取服务器记录…</p>';
    if (tab === "getting-started") {
      await window.InfraOnboarding.mount(target, { api, user: S.user, current, details: async asset => {
        if (!current()) return;
        if (!S.assets.some(a => a.id === asset.id)) S.assets.push(asset);
        await assetTelemetry(asset.id);
      } });
      return;
    }
    if (tab === "terminal") {
      terminalView(target);
      return;
    }
    if (tab === "agents") {
      const assets = await api("/api/v1/assets?" + assetParams(true));
      if (!current()) return;
      S.assets = assets;
      target.innerHTML = '<div class="guide-banner"><div><strong>第一次安装 Linux 客户端？</strong><p>通过引导完成资产、责任人、令牌和上报检查。</p></div><button data-page="getting-started" class="primary">逐步接入 Linux</button></div>' + card('<h3>从已登记的服务器开始</h3><p>选择资产 → 生成一次性注册令牌 → 在目标机器配置并注册客户端 → 运行采集 → 查看真实数据和配置回执。注册不代表采集成功。</p><p>主机 Agent 支持 Windows / Linux；Docker 采集器读 Engine API；PVE 采集器读节点、QEMU、LXC API。虚拟机内部指标需在虚拟机中另装主机 Agent。</p><p class="ra-warning">当前只下发采集周期和启停，不下发命令、端点或密钥。不代表演示监控页面已接入。PVE 实机、开机自启及生产负载验收仍需单独验证。</p>') +
        '<form id="ra-agent-search">' + input("搜索真实资产", "query", S.assetQuery) + '<button>搜索</button></form>' +
        card(table(["统一资产", "系统 / 责任", "采集接入"], assets.map(a => `<tr><td>${esc(a.name)}<small>${esc(a.id)}</small></td><td>${esc(a.os_family)}<small>${esc(ownershipStatus(a))}</small></td><td>${button("查看指标与 Agent", "asset-telemetry", a.id)}${assetManage(a) ? button("注册客户端", "agent-enrollment", a.id) : ""}</td></tr>`))) +
        `<div class="ra-bar">${button("上一页", "agents-prev", "", S.assetOffset ? "" : "disabled")}<span>第 ${Math.floor(S.assetOffset / 100) + 1} 页</span>${button("下一页", "agents-next", "", assets.length === 100 ? "" : "disabled")}</div>`;
      target.querySelector("#ra-agent-search").onsubmit = async event => {
        event.preventDefault();
        S.assetQuery = new FormData(event.target).get("query").trim(); S.assetOffset = 0;
        await show("agents").catch(e => { if (current()) msg(e.message); });
      };
      return;
    }
    if (tab === "access") {
      const access = await api("/my/access");
      if (!current()) return;
      S.access = access;
      target.innerHTML =
        '<div class="ra-grid">' +
        S.access
          .map((a) =>
            card(
              `<div class="ra-asset"><span class="ra-icon">${a.os_family === "windows" ? "⊞" : "›_"}</span><div><strong>${esc(a.asset_name)}</strong><p>${esc(a.account_name)} · <code>${esc(a.username)}</code></p></div></div><small>最早授权到期 ${new Date(Math.min(...a.grants.map((g) => Date.parse(g.expiresAt)))).toLocaleString()}</small><div class="ra-bar">${allowed(a, "ssh.connect") ? button("打开 SSH", "ssh", a.account_id) : ""}${allowed(a, "credential.temporary") ? button("临时凭据 SSH", "ssh-temporary", a.account_id) : ""}${allowed(a, "sftp.list") ? button("文件管理", "files", a.account_id) : ""}${allowed(a, "rdp.launch") ? button("本机 RDP · 需 Windows", "rdp", a.account_id) : ""}</div>${!allowed(a, "sftp.list") ? "<small>网页文件通道未配置或未授权；RDP 文件传输使用已授权的本地磁盘映射。</small>" : ""}`,
            ),
          )
          .join("") +
        "</div>";
      if (!S.access.length)
        target.innerHTML = card(
          '尚无有效的账号授权。管理员也需要获得明确的远程账号使用授权。<p>如果你要安装 Linux 采集客户端，请使用逐步接入；采集不需要远程账号授权。</p><button data-page="getting-started">接入 Linux 客户端</button><button data-page="help">使用手册</button>',
        );
      return;
    }
    if (tab === "assets") {
      const assets = await api("/api/v1/assets?" + assetParams(true));
      if (!current()) return;
      S.assets = assets;
      target.innerHTML =
        '<p class="muted">此处读取真实统一资产，与“资产与账号”使用同一资产 ID 和权限范围。可见资产不等于获得远程账号授权；在线状态与指标仍需真实采集。</p>' +
        '<form id="ra-asset-search"><div class="ra-grid">' + input("搜索资产（名称 / 标签 / 分组）", "query", S.assetQuery) +
        select("设备类别", "category", [["", "全部类别"], ...categories], S.assetFilters.category || "") +
        [["environment", "环境"], ["site", "地点"], ["business", "业务"], ["ownerId", "责任联系人 ID"], ["groupId", "资产组 ID"]].map(([key, label]) => input(label, key, S.assetFilters[key] || "")).join("") +
        '</div><button type="submit">筛选真实资产</button></form>' +
        `<div class="ra-bar">${S.user.role === "admin" ? button("＋ 添加服务器并连接", "server-onboard", "", 'class="primary"') : ""}${can("asset.manage") ? button("＋ 添加资产", "asset-new") : ""}${button("导出当前筛选 CSV", "assets-export")}<small>最多 1000 项；超限会拒绝，不截断结果</small></div>` +
        card(
          table(
            ["资产 / 分组", "类别 / 责任", "系统 / 类型", "协议端点", "操作"],
            S.assets.map(
              (a) =>
                `<tr><td><strong>${esc(a.name)}</strong><small>${esc(a.group_name)}</small><code>${esc(a.id)}</code></td><td>${esc(categories.find(([key]) => key === a.category)?.[1] || "未分类")}<small>${esc(ownershipStatus(a))}</small></td><td>${esc(a.os_family)} · ${esc(a.kind)}<small>${a.archived ? "已归档" : a.enabled ? "已启用" : "停用"}</small></td><td>${a.endpoints.map((e) => `<div><code>${esc(e.protocol)} ${esc(e.host)}:${e.port}</code></div>`).join("") || '<span class="muted">无远程端点 · 仅登记资产<br>不代表在线、离线或已采集</span>'}</td><td>${button("连接 / 文件", "asset-remote", a.id, 'class="primary"')}${button("真实详情", "asset-detail", a.id)}${assetManage(a) && can("remoteAccount.manage") ? button("账号", "accounts", a.id) : ""}${assetManage(a) ? button("编辑", "asset-edit", a.id) + button("责任历史", "ownership-history", a.id) + (a.endpoints.length ? button("主机指纹", "hostkey", a.id) + button("测试端点", "asset-test", a.id) : "") : '<small>仅能使用明确授权的远程账号；连接面板会显示缺少的条件</small>'}</td></tr>`,
            ),
          ),
        ) +
        `<div class="ra-bar">${button("上一页", "assets-prev", "", S.assetOffset ? "" : "disabled")}<span>第 ${Math.floor(S.assetOffset / 100) + 1} 页 · 本页 ${S.assets.length} 项</span>${button("下一页", "assets-next", "", S.assets.length === 100 ? "" : "disabled")}</div>`;
      target.querySelector("#ra-asset-search").onsubmit = async (event) => {
        event.preventDefault();
        S.assetQuery = new FormData(event.target).get("query").trim();
        for (const key of ["category", "environment", "site", "business", "ownerId", "groupId"]) S.assetFilters[key] = new FormData(event.target).get(key).trim();
        S.assetOffset = 0;
        try {
          await show("assets");
        } catch (e) {
          msg(e.message);
        }
      };
      return;
    }
    if (tab === "people") {
      if (!["admin", "asset_manager"].includes(S.user.role)) throw Error("当前角色无权读取人员目录");
      const people = await api("/people?offset=" + S.peopleOffset + "&q=" + encodeURIComponent(S.peopleQuery));
      if (!current()) return;
      S.people = people;
      target.innerHTML = '<p class="muted">手工维护的责任联系人，不是平台登录账号；绑定责任不会授予远程访问权限。当前未对接企业微信，也不会发送邮件。</p>' +
        (S.user.role === "asset_manager" ? '<p class="muted">资产管理员可查看并在资产中选择人员，创建或修改人员须由平台管理员操作。</p>' : "") +
        `<form id="ra-people-search">${input("搜索人员（姓名 / 部门）", "query", S.peopleQuery)}<button type="submit">搜索</button></form>` +
        `<div class="ra-bar">${S.user.role === "admin" ? button("＋ 添加联系人", "person-new") : ""}</div>` +
        card(table(["姓名 / 部门", "类型 / 来源", "邮箱", "状态", "操作"], S.people.map((person) =>
          `<tr><td><strong>${esc(person.display_name)}</strong><small>${esc(person.department || "未填写部门")}</small><code>${esc(person.id)}</code></td><td>${person.contact_type === "external" ? "外部联系人" : "内部人员"}<small>${person.source === "manual" ? "手工录入" : "来源未识别"}</small></td><td>${contactEmail(person)}</td><td>${person.enabled ? "启用" : "已停用"}</td><td>${S.user.role === "admin" ? button("编辑", "person-edit", person.id) : "只读"}</td></tr>`))) +
        `<div class="ra-bar">${button("上一页", "people-prev", "", S.peopleOffset ? "" : "disabled")}<span>第 ${Math.floor(S.peopleOffset / 100) + 1} 页 · 本页 ${S.people.length} 项</span>${button("下一页", "people-next", "", S.people.length === 100 ? "" : "disabled")}</div>`;
      target.querySelector("#ra-people-search").onsubmit = async (event) => {
        event.preventDefault();
        S.peopleQuery = new FormData(event.target).get("query").trim();
        S.peopleOffset = 0;
        try { await show("people"); } catch (e) { msg(e.message); }
      };
      return;
    }
    if (tab === "asset-groups") {
      if (S.user.role !== "admin" || !can("user.manage")) throw Error("仅平台管理员可管理资产组可见范围");
      const groups = await api("/asset-groups?offset=" + S.assetGroupOffset);
      if (!current()) return;
      S.assetGroups = groups;
      target.innerHTML = '<p class="muted">资产组只授予统一资产只读可见范围，不授予 SSH / SFTP / RDP、远程账号、凭据或人员目录权限。用户与用户组成员在有效期内生效；停用、到期或移除后不再通过本组授予可见性。</p>' +
        button("＋ 添加资产组", "asset-group-new") + card(table(["资产组 / ID", "资产 / 直接用户 / 用户组", "状态 / 有效期", "操作"], groups.map((g) =>
          `<tr><td><strong>${esc(g.name)}</strong><small>${esc(g.description)}</small><code>${esc(g.id)}</code></td><td>${g.asset_ids.length} / ${g.user_ids.length} / ${g.group_ids.length}</td><td>${g.enabled ? "启用" : "停用"}<small>${esc(new Date(g.starts_at).toLocaleString())} 至 ${esc(new Date(g.expires_at).toLocaleString())}</small></td><td>${button("编辑可见范围", "asset-group-edit", g.id)}</td></tr>`))) +
        `<div class="ra-bar">${button("上一页", "asset-groups-prev", "", S.assetGroupOffset ? "" : "disabled")}<span>第 ${Math.floor(S.assetGroupOffset / 100) + 1} 页 · 本页 ${groups.length} 项</span>${button("下一页", "asset-groups-next", "", groups.length === 100 ? "" : "disabled")}</div>`;
      return;
    }
    if (tab === "imports") {
      const jobs = await api("/api/v1/asset-imports");
      if (!current()) return;
      S.imports = jobs;
      target.innerHTML = '<p class="muted">先读取候选，再逐行选择、确认入库。CSV 导入不等于自动发现；预览不创建资产，不自动覆盖已有资产，不生成远程端点或账号授权。</p>' +
        '<p class="ra-warning">本机发现仅只读采集运行 Go 网关的 WSL Linux 本机摘要，不扫描网络；非 WSL Linux 本轮不支持。尚不代表 Rust Agent、Windows、NAS / PVE 或外部设备实机链路已验收。</p>' +
        `<div class="ra-bar">${button("CSV 批量导入预览", "import-new")}${button("发现网关本机候选", "discovery-new")}${button("下载 CSV 模板", "import-template")}${button("刷新真实任务", "tab", "imports")}</div>` +
        card(table(["任务 / 来源", "真实状态", "行数 / 结果", "预览有效期", "操作"], jobs.map((job) =>
          `<tr><td><code>${esc(job.id)}</code><small>${esc(importSource(job.source))}</small></td><td>${esc(importState(job.state))}</td><td>${esc(job.rows?.length ?? 0)} 行<small>待确认 ${esc(job.counts?.ready ?? 0)} · 无效 ${esc(job.counts?.invalid ?? 0)} · 重复 ${esc(job.counts?.duplicate ?? 0)} · 已创建 ${esc(job.counts?.created ?? 0)}</small></td><td>${esc(new Date(job.expiresAt).toLocaleString())}</td><td>${button("读取详情 / 选择候选", "import-detail", job.id)}</td></tr>`))) +
        '<p class="muted">显示服务端返回的最近 100 项任务；任务及资产结果均以刷新回读为准。确认失败请保留任务 ID，重新读取后核对，禁止把超时当作全部失败重复另建资产。</p>';
      return;
    }
    if (tab === "organizations") {
      const organizations = await api("/organizations?offset=" + S.organizationOffset);
      if (!current()) return;
      S.organizations = organizations;
      target.innerHTML = '<p class="muted">手工组织范围与联系人部门、平台用户组相互独立，尚未企业微信同步。组织成员只获得直接绑定资产的元数据只读权限；不授予资产修改、人员目录、远程账号、凭据、SSH / SFTP / RDP。父组织仅分类，不继承子组织或父组织权限。</p>' +
        button("＋ 添加组织范围", "organization-new") + card(table(["组织 / ID", "父组织 / 成员", "状态 / 版本", "操作"], organizations.map((org) =>
          `<tr><td><strong>${esc(org.name)}</strong><small>${esc(org.description)}</small><code>${esc(org.id)}</code></td><td><code>${esc(org.parent_id || "无父组织")}</code><small>${esc(org.member_ids?.length ?? 0)} 位平台用户</small></td><td>${org.enabled ? "启用" : "停用"}<small>版本 ${esc(org.version)}</small></td><td>${button("编辑组织与成员", "organization-edit", org.id)}</td></tr>`))) +
        `<div class="ra-bar">${button("上一页", "organizations-prev", "", S.organizationOffset ? "" : "disabled")}<span>第 ${Math.floor(S.organizationOffset / 100) + 1} 页 · 本页 ${organizations.length} 项</span>${button("下一页", "organizations-next", "", organizations.length === 100 ? "" : "disabled")}</div>`;
      return;
    }
    if (tab === "files") {
      await filesView(target);
      return;
    }
    if (tab === "transfers") {
      const list = await api("/transfers");
      if (!current()) return;
      target.innerHTML = card(
        '<h3>传输任务</h3><p class="muted">进度为网关已确认写入 / 读取字节。上传达到 100% 后仍须校验与提交；下载写入本地完成另行确认。</p>' +
          table(
            ["方向 / 任务", "状态", "已确认字节", "更新", "操作"],
            list.map(
              (t) =>
                `<tr><td>${esc(t.direction)}<small><code>${esc(t.id)}</code></small><small>${esc(t.target_path)} · ${esc(t.account_id)}</small></td><td>${esc(t.state)}<small>${esc(t.error_code)}</small></td><td><progress class="ra-progress" value="${t.done_bytes}" max="${Math.max(t.total_bytes, 1)}"></progress><small>${size(t.done_bytes)} / ${t.state === "scanning" ? "计算中" : size(t.total_bytes)}</small><small>${transferRate(t)}</small></td><td>${new Date(t.updated_at).toLocaleString()}</td><td>${button("明细", "task", t.id)}${["completed", "failed", "cancelled", "partial"].includes(t.state) ? button("清除显示", "hide-task", t.id) : ""}${t.direction === "upload" && t.state === "running" ? button("暂停", "pause-task", t.id) : ""}${t.direction === "upload" && t.state === "partial" ? button("重试冲突项", "retry-task", t.id) : ""}${t.direction === "upload" && ["paused", "running", "queued", "partial"].includes(t.state) ? button("续传", "resume", t.id) : ""}${["paused", "running", "queued", "scanning"].includes(t.state) ? button("取消", "cancel-task", t.id) : ""}</td></tr>`,
            ),
          ),
      );
      return;
    }
    if (tab === "connectors") {
      const [devices, launches] = await Promise.all([
        api("/my/connectors"),
        api("/rdp/launches"),
      ]);
      if (!current()) return;
      target.innerHTML =
        card(
          '<h3>每位用户自己的 Windows 连接器</h3><p>在你的 Windows 电脑运行本项目 windows-connector，配置批准的平台 HTTPS 地址。每次新的浏览器登录需要重新配对，以绑定当前会话。</p><p><a href="http://127.0.0.1:4173/" target="_blank" rel="noopener noreferrer">打开本人电脑的本机连接器（默认端口 4173）</a></p>' +
            button("生成 120 秒配对码", "pair") +
            table(
              ["设备", "最近心跳", "绑定", "操作"],
              devices.map(
                (d) =>
                  `<tr><td>${esc(d.name)}<small><code>${esc(d.id)}</code></small></td><td>${d.last_seen ? new Date(d.last_seen).toLocaleString() : "未上线"}</td><td>${d.revoked ? "已撤销" : "有效"}</td><td>${button("撤销", "connector-revoke", d.id)}</td></tr>`,
              ),
            ),
        ) +
        card(
          '<h3>RDP 启动记录</h3><p class="muted">started 仅表示进程已启动。临时凭据清理完成不会结束 RDP 会话。</p>' +
            table(
              ["任务", "设备", "状态", "PID", "错误"],
              launches.map(
                (x) =>
                  `<tr><td><code>${esc(x.id)}</code></td><td><code>${esc(x.connector_id)}</code></td><td>${esc(x.state)}<small>${esc(x.cleanup_state)}</small></td><td>${esc(x.pid)}</td><td>${esc(x.error_code)}</td></tr>`,
              ),
            ),
        );
      return;
    }
    if (tab === "health") {
      const h = await api("/health");
      if (!current()) return;
      target.innerHTML = card(
        "<h3>网关实际状态</h3><pre>" +
          esc(JSON.stringify(h, null, 2)) +
          "</pre>",
      );
      return;
    }
    const endpoints = {
      users: "/users",
      groups: "/groups",
      grants: "/grants",
      audit: "/audit-events",
      sessions: "/admin/sessions",
    };
    const records = await api(endpoints[tab]);
    if (!current()) return;
    S.records = records;
    target.innerHTML =
      '<div class="ra-bar">' +
      ({
        users: button("＋ 平台用户", "user-new"),
        groups: button("＋ 用户组", "group-new"),
        grants: button("＋ 账号分配", "grant-new"),
      }[tab] || "") +
      "</div>" +
      card(
        table(
          tab === "users"
            ? ["用户名", "角色", "状态", "操作"]
            : tab === "groups"
              ? ["名称", "成员", "操作"]
              : tab === "grants"
                ? ["主体", "资产 / 账号", "动作 / 有效期", "操作"]
                : tab === "sessions"
                  ? ["用户 / 会话", "状态 / 网关", "时间", "操作"]
                  : ["时间", "动作 / 主体", "对象", "结果"],
          records.map((x) => {
            if (tab === "users")
              return `<tr><td>${esc(x.username)} · ${esc(x.display_name)}</td><td>${esc(x.role)}</td><td>${x.enabled ? "启用" : "停用"}</td><td>${button("编辑 / 重置", "user-edit", x.id)}</td></tr>`;
            if (tab === "groups")
              return `<tr><td>${esc(x.name)}</td><td>${esc(JSON.stringify(x.members))}</td><td>${button("编辑成员", "group-edit", x.id)}</td></tr>`;
            if (tab === "grants")
              return `<tr><td><code>${esc(x.user_id || x.group_id)}</code></td><td><code>${esc(x.asset_id)}<br>${esc(x.account_id)}</code></td><td>${esc(x.actions.join(", "))}<small>${new Date(x.expires_at).toLocaleString()} ${x.revoked ? "已撤销" : ""}</small></td><td>${button("编辑", "grant-edit", x.id)}${!x.revoked ? button("撤销", "grant-revoke", x.id) : ""}</td></tr>`;
            if (tab === "sessions")
              return `<tr><td><code>${esc(x.user_id)} / ${esc(x.id)}</code></td><td>${esc(x.state)} · ${esc(x.gateway_id)}</td><td>${new Date(x.created_at).toLocaleString()}</td><td>${button("终止", "session-terminate", x.id)}</td></tr>`;
            return `<tr><td>${new Date(x.created_at).toLocaleString()}</td><td>${esc(x.action)}<small>${esc(x.actor_id)}</small></td><td><code>${esc(x.object_id)}</code></td><td>${esc(x.result)}</td></tr>`;
          }),
        ),
      );
    } catch (e) {
      if (current()) {
        if (e.status === 401) login();
        else throw e;
      }
    }
  }
  function assetParams(withOffset = false) {
    const params = new URLSearchParams();
    if (withOffset) params.set("offset", String(S.assetOffset));
    if (S.assetQuery) params.set("q", S.assetQuery);
    for (const [key, value] of Object.entries(S.assetFilters)) if (value) params.set(key, value);
    return params;
  }
  async function assetTelemetry(id) {
    const mount = S.renderEpoch, identity = S.user;
    const d = dialog("真实指标与客户端", '<div data-telemetry>正在读取已持久化样本…</div>', "关闭", async () => {});
    const current = () => d.open && d.isConnected && S.mounted && S.user === identity && S.renderEpoch === mount;
    try {
      const result = await api("/api/v1/assets/" + encodeURIComponent(id) + "/telemetry?limit=20");
      if (!current()) return;
      const target = d.querySelector("[data-telemetry]"), manage = assetManage(S.assets.find(a => a.id === id));
      target.innerHTML = '<p><strong>' + esc({ fresh: "有新鲜样本", stale: "样本已过期", empty: "尚无样本" }[result.dataState] || "状态未知") + '</strong> · 仅表示样本新鲜度，不等于全部采集器正常或设备健康。默认显示最近一小时、最多 20 个样本。</p>' +
        '<div class="ra-telemetry-table" role="region" aria-label="客户端配置列表（窄屏可横向滚动）" tabindex="0">' + table(["客户端 / 类型", "配置期望 / 已应用", "最后通信", "管理"], result.agents.map(a => `<tr><td>${esc(a.hostname)} / ${esc(a.kind)}<small>${esc(a.id)} · ${esc(a.agentVersion)}</small>${a.revoked ? "已撤销" : a.enabled ? "允许采集" : "采集已暂停"}</td><td>${esc(a.desiredVersion)} / ${esc(a.appliedVersion)}<small>${esc(a.intervalSeconds)} 秒</small></td><td>${esc(a.lastSeen || "未收到签名请求")}</td><td>${manage && !a.revoked ? `<button type="button" data-agent-config="${esc(a.id)}">配置</button><button type="button" data-agent-revoke="${esc(a.id)}">撤销</button>` : "只读"}</td></tr>`)) + '</div>' +
        result.samples.map(sample => '<details><summary>' + esc(sample.kind + " · " + sample.observedAt + " · 健康 " + (sample.health?.status || "未知") + " · 序列 " + sample.sequence) + '</summary><p>入库时间 ' + esc(sample.receivedAt) + ' · 配置版本 ' + esc(sample.configVersion) + '</p><pre style="white-space:pre-wrap;overflow-wrap:anywhere">' + esc(JSON.stringify(sample.metrics, null, 2)) + '</pre><pre>' + esc(JSON.stringify(sample.health)) + '</pre></details>').join("") +
        (result.hasMore ? '<p>还有历史样本；本面板不是完整导出。</p>' : "") + '<button type="button" data-telemetry-refresh>重新读取</button>';
      target.querySelector("[data-telemetry-refresh]").onclick = () => { d.close(); assetTelemetry(id).catch(e => msg(e.message)); };
      for (const b of target.querySelectorAll("[data-agent-config]")) b.onclick = () => {
        if (!current()) return;
        const a = result.agents.find(a => a.id === b.dataset.agentConfig);
        dialog("下发采集配置", input("采集周期（秒，1–3600）", "interval", a.intervalSeconds, "number") + check("启用采集", "enabled", a.enabled) + '<p>保存后需客户端下一次拉取并回报版本；不能将期望版本当作已应用。</p>', "保存期望配置", async form => {
          const intervalSeconds = Number(form.get("interval"));
          if (!Number.isInteger(intervalSeconds) || intervalSeconds < 1 || intervalSeconds > 3600) throw Error("周期必须是 1–3600 的整数");
          await api("/api/v1/agents/" + encodeURIComponent(a.id) + "/config", "PATCH", { version: a.desiredVersion, intervalSeconds, enabled: form.has("enabled"), collectors: [a.kind] });
          if (current()) { d.close(); await assetTelemetry(id); }
        });
      };
      for (const b of target.querySelectorAll("[data-agent-revoke]")) b.onclick = async () => {
        if (!current() || !confirm("撤销客户端后拒绝后续上报，历史样本仍保留。确认？")) return;
        b.disabled = true;
        try { await api("/api/v1/agents/" + encodeURIComponent(b.dataset.agentRevoke) + "/revoke", "POST", { confirm: true }); if (current()) { d.close(); await assetTelemetry(id); } }
        catch (e) { if (current()) d.querySelector(".ra-error").textContent = e.message; }
        finally { b.disabled = false; }
      };
    } catch (e) { if (current()) d.querySelector("[data-telemetry]").textContent = "真实数据读取失败，不使用模拟数据替代：" + e.message; }
  }
  function agentEnrollment(id) {
    requireAssetManage(id);
    const mount = S.renderEpoch;
    dialog("为资产注册 Rust 客户端", select("客户端类型", "kind", [["host", "Windows / Linux 主机"], ["docker", "Docker 采集器"], ["pve", "PVE 采集器"]], "host") + '<p>资产必须启用且责任信息完整。令牌绑定此资产和类型，10 分钟有效；不在浏览器保存。</p>', "生成注册令牌", async form => {
      const kind = form.get("kind"), response = await api("/api/v1/agents/enrollments", "POST", { assetId: id, kind, expiresInSeconds: 600 });
      if (!S.mounted || !S.user || S.renderEpoch !== mount) return;
      dialog("注册令牌（关闭后不再展示）", '<p>仅交给目标机器；不要发送到聊天、日志或命令参数。</p><pre style="white-space:pre-wrap;overflow-wrap:anywhere">' + esc(response.token) + '</pre><p>有效期至 ' + esc(response.expiresAt) + '</p><p>从发布包选择对应二进制和 TOML 配置。将 server_url 设置为此服务的可信 HTTPS 地址（当前：' + esc(location.origin) + '），跨机器不可填写 127.0.0.1。每个采集器使用独立 state_dir，自签名证书需要配置 ca_cert。</p><p>在运行客户端的进程环境设置 INFRASCOPE_ENROLLMENT_TOKEN，依次执行 enroll --config 配置文件、once --config 配置文件，确认入库后执行 run --config 配置文件。不要以注册成功代替采集成功。</p><p>当前类型：' + esc(kind) + '。PVE API token、Docker mTLS 和服务自启配置见发布包 README。</p>', "关闭并清除显示", async () => {});
    });
  }
  function assetManage(asset) {
    return asset?.canManage === true && can("asset.manage");
  }
  function requireAssetManage(id) {
    if (!assetManage(S.assets.find((asset) => asset.id === id))) throw Error("当前资产仅可查看，不能管理资产或远程账号");
  }
  async function exportAssets() {
    const epoch = S.renderEpoch;
    const response = await fetch("/api/v1/assets/export?" + assetParams(), { credentials: "same-origin", cache: "no-store" });
    if (!response.ok) {
      let error;
      try { error = await response.json(); } catch {}
      throw Error(error?.error || "资产导出失败（HTTP " + response.status + "）");
    }
    if (!response.headers.get("Content-Type")?.includes("text/csv")) throw Error("服务器未提供 CSV；不会下载错误页作为导出结果");
    const data = await response.blob();
    if (!S.mounted || epoch !== S.renderEpoch) return;
    const url = URL.createObjectURL(data), link = document.createElement("a");
    link.href = url;
    link.download = "infrascope-assets.csv";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    msg("已下载当前筛选和权限范围内的资产 CSV；导出不是采集或健康验证。");
  }
  async function assetDetails(id) {
    const epoch = S.renderEpoch, viewEpoch = S.viewEpoch;
    const a = await api("/api/v1/assets/" + encodeURIComponent(id));
    if (!S.mounted || epoch !== S.renderEpoch || viewEpoch !== S.viewEpoch) return;
    const fields = [["统一资产 ID", a.id], ["版本", a.version], ["类别", categories.find(([key]) => key === a.category)?.[1] || "未分类"],
      ["环境", a.environment], ["地点", a.site], ["业务", a.business], ["分组标签", a.group_name], ["直接组织 ID（只读范围）", a.organization_id],
      ["系统 / 物理类型", (a.os_family || "未确认") + " / " + (a.kind || "未确认")], ["责任状态", ownershipStatus(a)]];
    const origin = a.origin;
    fields.push(["来源", origin?.kind === "csv" ? "CSV 导入" : origin?.kind === "local_discovery" ? "WSL 本机发现一次快照" : origin ? "未识别的来源记录（待核实）" : "手工 / 旧记录待核实（无来源记录，不推断采集）"]);
    if (origin) fields.push(["来源任务 ID", origin.jobId], [origin.kind === "local_discovery" ? "一次观测时间（服务端原值）" : "来源记录时间（服务端原值）", origin.observedAt]);
    const roles = ownershipRoles.map(([key, label]) => [label, Array.isArray(a.ownership?.[key]) ? a.ownership[key].join("；") : a.ownership?.[key]]);
    const d = dialog(a.name + " · 真实资产详情", '<p class="muted">直接读取服务端统一资产记录。责任人员仅显示该资产保存的人员 ID，不会因此开放完整人员目录；远程连接仍需独立账号授权。</p>' +
      '<dl class="ra-details">' + [...fields, ...roles].map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value || "未填写")}</dd></div>`).join("") + '</dl>' +
      '<p class="ra-warning">CPU、内存、磁盘、网络的持续指标及当前在线状态：未知 / 未采集。来源记录仅追溯本次登记；WSL 本机快照不是实时趋势或持续采集。登记资产或配置端点不能证明设备当前在线，也不能当作完整实机验收通过。</p>' +
      '<h4>登记端点（非探测结果）</h4>' + table(["协议", "地址", "网关"], a.endpoints.map((endpoint) => `<tr><td>${esc(endpoint.protocol)}</td><td>${esc(endpoint.host)}:${esc(endpoint.port)}</td><td>${esc(endpoint.gatewayId)}</td></tr>`)) + '<div class="ra-bar">' + button("连接此服务器 / 管理文件", "asset-remote", a.id, 'class="primary"') + '</div>',
      "关闭", async () => {});
    d.querySelector("[data-close]").hidden = true;
  }
  const importSource = (source) => source === "csv" ? "CSV 手工导入" : source === "local_discovery" ? "网关本机只读发现" : "未知来源（不可作为已验证采集）";
  const importState = (state) => ({ preview: "待确认预览", partial: "部分已处理", confirmed: "所选项已确认", cancelled: "已取消剩余候选", ready: "可选择", invalid: "字段无效", duplicate: "已存在 / 重复", created: "已创建", failed: "失败（修复原因后可重试）" })[state] || state;
  function requireImportManage() {
    if (!tabAllowed("imports") || !can("asset.manage")) throw Error("仅有资产管理权限的管理员可生成和确认候选");
  }
  function downloadImportTemplate() {
    requireImportManage();
    const data = "inventoryId,name,category,kind,osFamily,environment,site,business,description\r\n";
    const url = URL.createObjectURL(new Blob(["\ufeff", data], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a"); link.href = url; link.download = "infrascope-asset-import-template.csv"; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function organizationOptions(current) {
    const result = new Map();
    for (let offset = 0; offset < 10000; offset += 100) {
      const rows = await api("/organizations/options" + (offset ? "?offset=" + offset : ""));
      if (!current()) return [];
      for (const row of rows) result.set(row.id, row);
      if (rows.length < 100) return [...result.values()];
    }
    throw Error("组织目录超过 10000 项，不能静默截断；请先缩小目录规模后重试");
  }
  function organizationPicker(d, existingId, updateReady) {
    const mount = S.renderEpoch, select = d.querySelector('[name="organizationId"]');
    let ready = false;
    const current = () => d.isConnected && mount === S.renderEpoch && S.user && !S.logoutPending;
    select.innerHTML = '<option value="">不绑定组织（不新增组织可见范围）</option>' + (existingId ? `<option value="${esc(existingId)}" selected>${esc(existingId)} [原组织，待读取]</option>` : "");
    async function load() {
      if (!current()) return;
      const chosen = select.value || "";
      ready = false; updateReady(false);
      select.disabled = true;
      d.querySelector("#ra-organization-retry").disabled = true;
      d.querySelector("#ra-organization-error").textContent = "正在读取真实组织范围…";
      try {
        const rows = await organizationOptions(current);
        if (!current()) return;
        const all = new Map(rows.map((org) => [org.id, org]));
        if (chosen && !all.has(chosen)) all.set(chosen, { id: chosen, name: "[原组织缺失或不可访问]", enabled: false });
        select.innerHTML = '<option value="">不绑定组织（不新增组织可见范围）</option>' + [...all.values()].map((org) =>
          `<option value="${esc(org.id)}" ${org.id === chosen ? "selected" : ""} ${!org.enabled && org.id !== chosen ? "disabled" : ""}>${esc(org.name + " · " + org.id + (org.enabled ? "" : " [已停用 / 缺失]"))}</option>`).join("");
        ready = true;
        d.querySelector("#ra-organization-error").textContent = "";
      } catch (e) {
        if (current()) d.querySelector("#ra-organization-error").textContent = "组织读取失败，保留原选择并禁止保存：" + e.message;
      } finally {
        if (current()) {
          select.disabled = false; d.querySelector("#ra-organization-retry").disabled = false; updateReady(ready);
        }
      }
    }
    d.querySelector("#ra-organization-retry").onclick = () => { void load(); };
    void load();
  }
  function organizationFields() {
    return '<fieldset><legend>组织可见范围</legend><label>直接绑定组织<select name="organizationId"></select></label><p class="muted">组织成员只读此资产元数据，不继承任何远程权限；留空不新增组织可见范围。</p><button type="button" id="ra-organization-retry">重新读取组织</button><p id="ra-organization-error" class="ra-error" role="alert"></p></fieldset>';
  }
  function refreshImportListOnClose(mount, viewEpoch) {
    if (!S.mounted || !S.user || S.logoutPending || mount !== S.renderEpoch || viewEpoch !== S.viewEpoch || S.tab !== "imports") return;
    const refresh = show("imports"), refreshEpoch = S.viewEpoch;
    void refresh.catch((e) => {
      if (S.mounted && mount === S.renderEpoch && refreshEpoch === S.viewEpoch && S.tab === "imports") msg("任务详情已关闭，但真实任务列表刷新失败；请重试读取，不会显示旧列表为最新结果：" + e.message);
    });
  }
  function importEditor(source = "csv") {
    requireImportManage();
    const mount = S.renderEpoch, viewEpoch = S.viewEpoch, people = new Map();
    let previewCreated = false, detailOpened = false;
    let page = [], offset = 0, query = "", request = 0, peopleReady = false, organizationReady = false, fileReading = false;
    const d = dialog(source === "csv" ? "CSV 批量导入 · 先预览" : "发现网关本机 · 先预览",
      '<p class="muted">预览有效 30 分钟，不创建资产。必须在下一步明确选择候选后才入库；导入为待认领资产，不自动生成端点、账号或授权。</p>' +
      (source === "csv" ? '<p class="muted">仅接受 UTF-8 CSV，最多 512 KiB、200 数据行。必填表头 inventoryId,name；其他允许表头 category,kind,osFamily,environment,site,business,description。资产类别默认 server、类型 physical、系统 other；同工作空间 inventoryId 重复不会覆盖。</p><label>读取本地 CSV（不会直接上传或确认）<input type="file" id="ra-import-file" accept=".csv,text/csv"></label><label>CSV 内容<textarea name="csv" rows="8" spellcheck="false"></textarea></label><p id="ra-file-read-status" role="status"></p>' : '<p class="ra-warning">仅读取 Go 网关所在 WSL Linux 本机 OS、网卡、挂载点摘要；非 WSL Linux 本轮不支持。不扫描网段，不执行远程命令，不等于 Rust Agent 或外部设备采集已完成。</p>') +
      '<fieldset><legend>待认领负责人（必须明确选择）</legend>' + input("搜索真实联系人（姓名 / 部门）", "import-people-query") +
      '<div class="ra-bar"><button type="button" id="ra-import-people-search">搜索 / 重试</button><button type="button" id="ra-import-people-prev">上一页</button><span id="ra-import-people-page" role="status"></span><button type="button" id="ra-import-people-next">下一页</button></div>' +
      '<label>本批待认领负责人<select name="claimantId"><option value="">请选择负责人</option></select></label><p class="muted">搜索和翻页保留已选负责人。真实联系人目录为空时，先由平台管理员登记联系人；责任绑定不授予平台登录或远程权限。</p><p id="ra-import-people-error" class="ra-error" role="alert"></p></fieldset>' + organizationFields(),
      "生成候选预览（不创建资产）", async (form) => {
        if (!peopleReady || !organizationReady || fileReading) throw Error("请等待真实目录和本地文件读取完成");
        const payload = window.InfraRemoteAssets.importPreviewPayload(Object.fromEntries(form), [...people.values()], source);
        const job = await api(source === "csv" ? "/api/v1/asset-imports/preview" : "/api/v1/discovery/local-preview", "POST", payload);
        previewCreated = true;
        if (!current()) return;
        try { detailOpened = Boolean(await importDetails(job.id, current)); } catch (e) { throw Error("候选任务已生成（" + job.id + "），但详情读取失败；请关闭后在真实任务列表刷新核对：" + e.message); }
      });
    const current = () => d.open && d.isConnected && mount === S.renderEpoch && S.user && !S.logoutPending;
    d.onclose = () => { d.remove(); if (previewCreated && !detailOpened) refreshImportListOnClose(mount, viewEpoch); };
    function gate() {
      const ready = peopleReady && organizationReady && !fileReading;
      d.dataset.submitBlocked = String(!ready);
      d.querySelector("[type=submit]").disabled = window.InfraRemoteAssets.submitDisabled(d.dataset.submitting === "true", ready);
    }
    async function loadPeople(nextOffset = 0) {
      if (!current()) return;
      const generation = ++request;
      const chosen = d.querySelector('[name="claimantId"]').value;
      peopleReady = false; gate();
      d.querySelector('[name="claimantId"]').disabled = true;
      for (const id of ["search", "prev", "next"]) d.querySelector("#ra-import-people-" + id).disabled = true;
      d.querySelector("#ra-import-people-error").textContent = "";
      try {
        const rows = await api("/people?offset=" + nextOffset + "&q=" + encodeURIComponent(query));
        if (!current() || generation !== request) return;
        page = rows; offset = nextOffset;
        for (const person of rows) people.set(person.id, person);
        d.querySelector('[name="claimantId"]').innerHTML = '<option value="">请选择负责人</option>' + [...new Set([...(chosen ? [chosen] : []), ...page.map((person) => person.id)])].map((id) => {
          const person = people.get(id);
          return `<option value="${esc(id)}" ${id === chosen ? "selected" : ""} ${!person?.enabled ? "disabled" : ""}>${esc(person ? personLabel(person) : "[缺失] " + id)}</option>`;
        }).join("");
        peopleReady = true;
        d.querySelector("#ra-import-people-page").textContent = `第 ${Math.floor(offset / 100) + 1} 页 · ${page.length} 项`;
      } catch (e) {
        if (current() && generation === request) d.querySelector("#ra-import-people-error").textContent = "人员读取失败，保留输入，禁止预览：" + e.message;
      } finally {
        if (current() && generation === request) {
          gate();
          d.querySelector('[name="claimantId"]').disabled = false;
          d.querySelector("#ra-import-people-search").disabled = false;
          d.querySelector("#ra-import-people-prev").disabled = offset === 0;
          d.querySelector("#ra-import-people-next").disabled = page.length !== 100;
        }
      }
    }
    d.querySelector("#ra-import-people-search").onclick = () => { query = d.querySelector('[name="import-people-query"]').value.trim(); void loadPeople(); };
    d.querySelector('[name="import-people-query"]').onkeydown = (event) => { if (event.key === "Enter") { event.preventDefault(); d.querySelector("#ra-import-people-search").click(); } };
    d.querySelector("#ra-import-people-prev").onclick = () => { void loadPeople(Math.max(0, offset - 100)); };
    d.querySelector("#ra-import-people-next").onclick = () => { void loadPeople(offset + 100); };
    if (source === "csv") d.querySelector("#ra-import-file").onchange = async (event) => {
      const file = event.target.files?.[0];
      if (!file || !current() || d.dataset.submitting === "true") return;
      fileReading = true; gate(); event.target.disabled = true;
      const textarea = d.querySelector('[name="csv"]'); textarea.disabled = true;
      try {
        if (file.size > 512 * 1024) throw Error("CSV 文件不能超过 512 KiB");
        const data = new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer());
        if (!current()) return;
        textarea.value = data;
        d.querySelector("#ra-file-read-status").textContent = `已在浏览器本地读取 ${file.name}；尚未发送服务器或创建资产。`;
      } catch (e) {
        if (current()) d.querySelector("#ra-file-read-status").textContent = "文件读取失败，保留原 CSV 内容：" + e.message;
      } finally {
        if (current()) { fileReading = false; gate(); event.target.disabled = false; textarea.disabled = false; }
      }
    };
    gate();
    organizationPicker(d, "", (ready) => { organizationReady = ready; gate(); });
    void loadPeople();
  }
  async function importDetails(id, originAlive = () => true) {
    requireImportManage();
    if (!originAlive()) return;
    const mount = S.renderEpoch, viewEpoch = S.viewEpoch;
    const job = await api("/api/v1/asset-imports/" + encodeURIComponent(id));
    if (!originAlive() || !S.user || !S.mounted || mount !== S.renderEpoch || viewEpoch !== S.viewEpoch) return;
    let replaced = false, mutationCommitted = "";
    const canConfirm = ["preview", "partial"].includes(job.state) && Date.parse(job.expiresAt) > Date.now();
    const facts = job.facts || {};
    const factsHtml = job.source === "local_discovery" ? '<details><summary>本次真实本机观测摘要（不代表健康或外设验收）</summary>' +
      `<p>主机：${esc(facts.hostname || "未提供")} · 内核：${esc(facts.kernel || "未提供")}<br>OS：${esc(typeof facts.osRelease === "string" ? facts.osRelease : Object.entries(facts.osRelease || {}).map(([key, value]) => key + "=" + value).join(" · "))}<br>观测时间：${esc(facts.observedAt || "未提供")}</p>` +
      '<p>网卡：' + esc((facts.interfaces || []).map((entry) => typeof entry === "string" ? entry : [entry.name, ...(entry.addresses || []), entry.addressState === "unavailable" ? "地址读取失败" : ""].filter(Boolean).join(" · ")).join("；") || "未提供") + '</p><p>挂载点：' + esc((facts.mounts || []).map((entry) => typeof entry === "string" ? entry : [entry.mountPoint || entry.mountpoint || entry.path, entry.filesystem || entry.fsType || entry.type, entry.state === "unavailable" ? "容量读取失败" : entry.totalBytes ? "总量 " + size(Number(entry.totalBytes)) + " / 可用 " + size(Number(entry.availableBytes)) : ""].filter(Boolean).join(" · ")).join("；") || "未提供") + '</p>' +
      (facts.mountsTruncated || facts.mountState === "partial" ? '<p class="ra-warning">挂载点摘要' + (facts.mountsTruncated ? "已达到 128 项上限，结果已截断；" : "") + (facts.mountState === "partial" ? "读取不完整；" : "") + '不能据此声称全部磁盘已验证。</p>' : "") + '</details>' : "";
    const d = dialog("候选预览与真实处理结果",
      `<p>任务 <code>${esc(job.id)}</code> · ${esc(importSource(job.source))} · <strong>${esc(importState(job.state))}</strong><br>有效至 ${esc(new Date(job.expiresAt).toLocaleString())}</p>` +
      '<p class="ra-warning">不默认选择任何行。请逐行核对来源、资产标识和责任，勾选后再确认入库。已创建项不会重复创建；重复 / 无效项禁止确认。失败项须先修复原因再明确选择重试。未选择项不会自动创建。</p>' + factsHtml +
      '<div class="ra-import-rows">' + table(["选择", "数据行 / 标识", "名称 / 分类", "责任 / 组织", "状态 / 服务端说明"], (job.rows || []).map((row) => {
        const payload = row.payload || {};
        return `<tr><td><input type="checkbox" name="importRow" value="${esc(row.rowNumber)}" aria-label="选择第 ${esc(row.rowNumber)} 行 ${esc(row.name)}" ${canConfirm && ["ready", "failed"].includes(row.state) ? "" : "disabled"}></td><td>${esc(row.rowNumber)}<small><code>${esc(row.inventoryId)}</code></small></td><td>${esc(row.name)}<small>${esc(payload.category || "")} · ${esc(payload.kind || "")} · ${esc(payload.osFamily || "")}</small><details><summary>环境 / 地点 / 业务 / 说明</summary>${[["环境", payload.environment], ["地点", payload.site], ["业务", payload.business], ["说明", payload.description]].map(([label, value]) => `<div>${label}：${esc(value || "未填写")}</div>`).join("")}</details></td><td><code>${esc(payload.ownership?.claimantId || job.claimantId || "见任务预览责任")}</code><small>${esc(payload.organizationId || job.organizationId || "无组织")}</small></td><td>${esc(importState(row.state))}<small>${esc(row.message || "")}</small>${row.assetId ? `<code>${esc(row.assetId)}</code>` : ""}</td></tr>`;
      })) + '</div><p id="ra-import-selected" role="status">已选 0 行；尚未提交确认。</p>' +
      (!canConfirm ? '<p class="ra-warning">当前任务已处理、取消或预览过期，不可继续选择创建；可刷新读取真实结果。</p>' : "") +
      '<div class="ra-bar"><button type="button" id="ra-import-refresh">重新读取真实结果</button>' + (["preview", "partial"].includes(job.state) ? '<button type="button" id="ra-import-cancel">取消剩余候选（不删除已创建资产）</button>' : "") + '</div>',
      "确认创建所选候选", async (form) => {
        if (mutationCommitted) throw Error("本任务操作已提交，请先重新读取真实结果");
        const payload = window.InfraRemoteAssets.importSelection(job, form.getAll("importRow"));
        await api("/api/v1/asset-imports/" + encodeURIComponent(id) + "/confirm", "POST", payload);
        if (!current()) return;
        mutationCommitted = "confirm"; gate();
        try { replaced = Boolean(await importDetails(id, current)); } catch (e) { throw Error("服务器已处理本次确认，但结果回读失败；请重新读取任务 " + id + "，不要把此错误当作全部创建失败：" + e.message); }
      });
    const current = () => d.open && d.isConnected && mount === S.renderEpoch && S.user && !S.logoutPending;
    d.onclose = () => {
      d.remove();
      if (!replaced) refreshImportListOnClose(mount, viewEpoch);
    };
    function gate() {
      const count = d.querySelectorAll('[name="importRow"]:checked').length;
      const ready = canConfirm && !mutationCommitted && count > 0;
      d.dataset.submitBlocked = String(!ready);
      d.querySelector("[type=submit]").disabled = window.InfraRemoteAssets.submitDisabled(d.dataset.submitting === "true", ready);
      d.querySelector("#ra-import-selected").textContent = mutationCommitted ? `任务 ${id} 的${mutationCommitted === "cancel" ? "取消" : "确认"}已提交，结果待回读；旧候选禁止再次提交，请重新读取真实结果。` : `已选 ${count} 行；只有点击确认后才请求创建。`;
      const cancelButton = d.querySelector("#ra-import-cancel");
      if (cancelButton) cancelButton.disabled = Boolean(mutationCommitted) || d.dataset.submitting === "true";
    }
    d.addEventListener("change", gate); gate();
    async function action(kind) {
      if (!current() || d.dataset.submitting === "true") return;
      if (kind === "cancel" && mutationCommitted) return;
      if (kind === "cancel" && !confirm("取消尚未创建的候选？已经创建的资产会保留，不会删除。")) return;
      d.dataset.submitting = "true"; gate();
      for (const selector of ["#ra-import-refresh", "#ra-import-cancel"]) { const button = d.querySelector(selector); if (button) button.disabled = true; }
      try {
        if (kind === "cancel") {
          await api("/api/v1/asset-imports/" + encodeURIComponent(id) + "/cancel", "POST", { confirm: true });
          mutationCommitted = "cancel"; if (current()) gate();
        }
        if (!current()) return;
        replaced = Boolean(await importDetails(id, current));
        if (current()) d.close();
      } catch (e) {
        if (current()) d.querySelector(".ra-error").textContent = mutationCommitted === "cancel" ? "取消已提交；任务 " + id + " 的真实结果待回读，请重新读取，不能继续确认旧候选：" + e.message : mutationCommitted === "confirm" ? "确认已提交；任务 " + id + " 的真实结果待回读，请重新读取：" + e.message : e.message;
      } finally {
        if (current()) {
          d.dataset.submitting = "false";
          for (const selector of ["#ra-import-refresh", "#ra-import-cancel"]) { const button = d.querySelector(selector); if (button) button.disabled = false; }
          gate();
        }
      }
    }
    d.querySelector("#ra-import-refresh").onclick = () => { void action("refresh"); };
    if (["preview", "partial"].includes(job.state)) d.querySelector("#ra-import-cancel").onclick = () => { void action("cancel"); };
    return d;
  }
  function organizationEditor(org) {
    if (!tabAllowed("organizations")) throw Error("仅平台管理员可管理组织成员与范围");
    const mount = S.renderEpoch;
    let loaded = false;
    const d = dialog(org ? "编辑组织与只读成员" : "添加组织与只读成员",
      '<p class="ra-warning">成员只获得直接绑定资产的元数据只读范围，不获得远程操作或管理权限。父组织仅分类，不产生权限继承。手工组织不等于企业微信同步；每个组织最多 500 位平台用户。</p>' +
      (org ? `<p>组织 <code>${esc(org.id)}</code> · 版本 ${esc(org.version)}。版本冲突时保留输入，不自动覆盖；取消并刷新核对后再编辑。</p>` : "") +
      input("组织名称", "name", org?.name || "") + input("说明", "description", org?.description || "") + check("启用此组织只读范围", "enabled", org?.enabled ?? true) +
      '<label>父组织（仅分类）<select name="parentId"><option value="">无父组织</option></select></label><label>组织成员（平台用户，可多选）<select name="memberIds" multiple size="10"></select></label><p class="muted">Ctrl / Command 多选；空选择不代表所有用户。已有缺失或停用成员保留显示，不会因目录加载而静默移除。保存仍以服务端完整校验为准。</p><button type="button" id="ra-organization-directory-retry">重新读取真实用户与组织</button><p id="ra-organization-directory-error" class="ra-error" role="alert"></p>',
      "保存组织只读范围", async (form) => {
        if (!loaded) throw Error("真实用户与组织目录未成功读取，请重试");
        const memberIds = form.getAll("memberIds"), name = form.get("name").trim();
        if (!name || memberIds.length > 500) throw Error("组织名称不能为空，成员最多 500 位");
        await api(org ? "/organizations/" + encodeURIComponent(org.id) : "/organizations", org ? "PATCH" : "POST", {
          ...(org ? { version: org.version } : {}), name, description: form.get("description").trim(), parentId: form.get("parentId"), memberIds, enabled: form.has("enabled"),
        });
        if (current() && S.tab === "organizations") try { await show("organizations"); } catch (e) { msg("组织已保存，但列表读取失败：" + e.message); }
      });
    const current = () => d.isConnected && mount === S.renderEpoch && S.user && !S.logoutPending;
    d.querySelector('[name="memberIds"]').innerHTML = (org?.member_ids || []).map((id) => `<option value="${esc(id)}" selected>${esc(id)}</option>`).join("");
    if (org?.parent_id) d.querySelector('[name="parentId"]').innerHTML += `<option value="${esc(org.parent_id)}" selected>${esc(org.parent_id)}</option>`;
    function gate() { d.dataset.submitBlocked = String(!loaded); d.querySelector("[type=submit]").disabled = window.InfraRemoteAssets.submitDisabled(d.dataset.submitting === "true", loaded); }
    async function load() {
      if (!current()) return;
      const selected = new Set([...d.querySelector('[name="memberIds"]').selectedOptions].map((option) => option.value));
      const parentId = d.querySelector('[name="parentId"]').value;
      loaded = false; gate(); d.querySelector("#ra-organization-directory-retry").disabled = true;
      for (const key of ["parentId", "memberIds"]) d.querySelector(`[name="${key}"]`).disabled = true;
      d.querySelector("#ra-organization-directory-error").textContent = "正在读取真实目录…";
      try {
        const [users, organizations] = await Promise.all([api("/users"), organizationOptions(current)]);
        if (!current()) return;
        const userMap = new Map(users.map((user) => [user.id, user]));
        d.querySelector('[name="memberIds"]').innerHTML = [...new Set([...selected, ...userMap.keys()])].map((id) => {
          const user = userMap.get(id);
          return `<option value="${esc(id)}" ${selected.has(id) ? "selected" : ""}>${esc((user ? `${user.display_name} / ${user.username}${user.enabled ? "" : " [已停用]"}` : "[缺失或不可访问]") + " · " + id)}</option>`;
        }).join("");
        const orgMap = new Map(organizations.filter((row) => row.id !== org?.id).map((row) => [row.id, row]));
        if (parentId && !orgMap.has(parentId)) orgMap.set(parentId, { id: parentId, name: "[原父组织缺失或不可访问]", enabled: false });
        d.querySelector('[name="parentId"]').innerHTML = '<option value="">无父组织</option>' + [...orgMap.values()].map((row) => `<option value="${esc(row.id)}" ${row.id === parentId ? "selected" : ""}>${esc(row.name + " · " + row.id + (row.enabled ? "" : " [已停用]"))}</option>`).join("");
        loaded = true; d.querySelector("#ra-organization-directory-error").textContent = "";
      } catch (e) {
        if (current()) d.querySelector("#ra-organization-directory-error").textContent = "读取失败，保留输入并禁止保存：" + e.message;
      } finally {
        if (current()) { gate(); d.querySelector("#ra-organization-directory-retry").disabled = false; for (const key of ["parentId", "memberIds"]) d.querySelector(`[name="${key}"]`).disabled = false; }
      }
    }
    gate(); d.querySelector("#ra-organization-directory-retry").onclick = () => { void load(); }; void load();
  }
  function localDate(value) {
    const date = new Date(value);
    return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, -1);
  }
  function assetGroupEditor(group) {
    if (S.user.role !== "admin" || !can("user.manage")) throw Error("仅平台管理员可管理资产组可见范围");
    const selected = new Set(group?.asset_ids || []), assets = new Map();
    const initialTimes = { startsAt: localDate(group?.starts_at || Date.now()), expiresAt: localDate(group?.expires_at || Date.now() + 30 * 86400000) };
    const mount = S.renderEpoch;
    let page = [], offset = 0, query = "", request = 0, assetsReady = false, principalsReady = false;
    const d = dialog(group ? "编辑资产组可见范围" : "添加资产组可见范围",
      '<p class="ra-warning">只读资产，不含账号连接权限。不会授予凭据、SSH / SFTP / RDP 或人员目录访问。空选择不表示全部；每组最多 500 个资产、100 个用户、100 个用户组。</p>' +
      (group ? `<p class="muted">资产组 ID：${esc(group.id)} · 版本 ${esc(group.version)}。冲突时保留输入；请取消并重新读取核对，不自动覆盖。</p>` : "") +
      input("资产组名称", "name", group?.name || "") + input("说明", "description", group?.description || "") +
      check("启用可见范围", "enabled", group?.enabled ?? true) +
      '<div class="ra-grid">' + input("开始时间（本地时区）", "startsAt", initialTimes.startsAt, "datetime-local") +
      input("到期时间（本地时区）", "expiresAt", initialTimes.expiresAt, "datetime-local") + '</div>' +
      '<p class="muted">时间按浏览器本地时区显示，修改后以 UTC 提交，可精确到毫秒。未修改时间时原样保留服务器时间（含更高精度），修改名称不会改变授权起止时间。</p>' +
      '<p class="muted">组内成员统一使用此有效期；未到开始时间、已到期或停用均不授予可见性。其他有效授权仍独立生效。</p>' +
      '<fieldset><legend>资产范围</legend>' + input("搜索真实资产", "scope-query") +
      '<div class="ra-bar"><button type="button" id="ra-scope-search">搜索 / 重试</button><button type="button" id="ra-scope-prev">上一页</button><span id="ra-scope-page" role="status"></span><button type="button" id="ra-scope-next">下一页</button></div>' +
      '<label>选择资产（可多选）<select name="assetIds" multiple size="8"></select></label><p class="muted">搜索与翻页保留所有已选资产；可见选项包括已选项与当前页。Ctrl / Command 多选，取消选中才能移除。未能读取的既有 ID 会保留并标记，不会静默丢失。</p><p id="ra-scope-count" role="status"></p><p id="ra-scope-error" class="ra-error" role="alert"></p></fieldset>' +
      '<div class="ra-grid"><label>直接平台用户（可多选）<select name="userIds" multiple size="6"></select></label><label>平台用户组（可多选）<select name="groupIds" multiple size="6"></select></label></div>' +
      '<button type="button" id="ra-principals-retry">重新读取用户与用户组</button><p id="ra-principals-error" class="ra-error" role="alert"></p>',
      "保存只读可见范围", async (form) => {
        if (!assetsReady || !principalsReady) throw Error("真实目录未成功读取，请重试后保存");
        const userIds = form.getAll("userIds"), groupIds = form.getAll("groupIds");
        if (selected.size > 500 || userIds.length > 100 || groupIds.length > 100) throw Error("每组最多 500 个资产、100 个用户、100 个用户组");
        const start = Date.parse(form.get("startsAt")), end = Date.parse(form.get("expiresAt"));
        if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) throw Error("请填写有效时间，且到期时间必须晚于开始时间");
        const name = form.get("name").trim();
        if (!name) throw Error("资产组名称不能为空");
        await api(group ? "/asset-groups/" + encodeURIComponent(group.id) : "/asset-groups", group ? "PATCH" : "POST", {
          ...(group ? { version: group.version } : {}), name, description: form.get("description").trim(), enabled: form.has("enabled"),
          startsAt: group && start === Date.parse(initialTimes.startsAt) ? group.starts_at : new Date(start).toISOString(),
          expiresAt: group && end === Date.parse(initialTimes.expiresAt) ? group.expires_at : new Date(end).toISOString(), assetIds: [...selected], userIds, groupIds,
        });
        if (d.isConnected && mount === S.renderEpoch) try { await show("asset-groups"); } catch (e) { msg("资产组已保存，但列表读取失败：" + e.message); }
      });
    function gate() {
      d.dataset.submitBlocked = String(!assetsReady || !principalsReady);
      d.querySelector("[type=submit]").disabled = window.InfraRemoteAssets.submitDisabled(d.dataset.submitting === "true", assetsReady && principalsReady);
    }
    function drawAssets() {
      const ids = [...new Set([...selected, ...page.map((asset) => asset.id)])];
      d.querySelector('[name="assetIds"]').innerHTML = ids.map((id) => `<option value="${esc(id)}" ${selected.has(id) ? "selected" : ""}>${esc((assets.get(id)?.name || "[缺失或不可访问]") + " · " + id)}</option>`).join("");
      d.querySelector("#ra-scope-count").textContent = `已选 ${selected.size} / 500 个资产`;
    }
    async function loadAssets(nextOffset = 0) {
      const current = ++request;
      assetsReady = false;
      gate();
      d.querySelector("#ra-scope-error").textContent = "";
      d.querySelector("#ra-scope-page").textContent = "正在读取真实资产…";
      for (const id of ["ra-scope-search", "ra-scope-prev", "ra-scope-next"]) d.querySelector("#" + id).disabled = true;
      try {
        const missing = [...selected].filter((id) => !assets.has(id));
        for (let i = 0; i < missing.length; i += 100) {
          const known = await api("/api/v1/assets?ids=" + encodeURIComponent(missing.slice(i, i + 100).join(",")));
          if (!d.isConnected || current !== request) return;
          for (const asset of known) assets.set(asset.id, asset);
        }
        const rows = await api("/api/v1/assets?offset=" + nextOffset + "&q=" + encodeURIComponent(query));
        if (!d.isConnected || current !== request) return;
        page = rows; offset = nextOffset;
        for (const asset of rows) assets.set(asset.id, asset);
        drawAssets();
        assetsReady = true;
        d.querySelector("#ra-scope-page").textContent = `第 ${Math.floor(offset / 100) + 1} 页 · ${rows.length} 项`;
      } catch (e) {
        if (!d.isConnected || current !== request) return;
        d.querySelector("#ra-scope-error").textContent = "资产目录读取失败，已选 ID 与输入均保留：" + e.message;
        d.querySelector("#ra-scope-page").textContent = "读取失败";
      } finally {
        if (d.isConnected && current === request) {
          gate();
          d.querySelector("#ra-scope-search").disabled = false;
          d.querySelector("#ra-scope-prev").disabled = offset === 0;
          d.querySelector("#ra-scope-next").disabled = page.length !== 100;
        }
      }
    }
    async function loadPrincipals() {
      const prior = new Map(["userIds", "groupIds"].map((key) => [key, [...d.querySelector(`[name="${key}"]`).selectedOptions].map((option) => option.value)]));
      principalsReady = false;
      gate();
      for (const key of ["userIds", "groupIds"]) d.querySelector(`[name="${key}"]`).disabled = true;
      d.querySelector("#ra-principals-retry").disabled = true;
      d.querySelector("#ra-principals-error").textContent = "正在读取真实用户与用户组…";
      try {
        const [users, groups] = await Promise.all([api("/users"), api("/groups")]);
        if (!d.isConnected) return;
        for (const [key, rows] of [["userIds", users], ["groupIds", groups]]) {
          const picked = new Set(prior.get(key));
          const records = new Map(rows.map((row) => [row.id, row]));
          d.querySelector(`[name="${key}"]`).innerHTML = [...new Set([...picked, ...records.keys()])].map((id) => {
            const row = records.get(id);
            const label = row ? key === "userIds" ? `${row.display_name} / ${row.username}${row.enabled ? "" : " [已停用]"}` : row.name : "[缺失或不可访问]";
            return `<option value="${esc(id)}" ${picked.has(id) ? "selected" : ""}>${esc(label + " · " + id)}</option>`;
          }).join("");
        }
        principalsReady = true;
        d.querySelector("#ra-principals-error").textContent = "";
      } catch (e) {
        if (d.isConnected) d.querySelector("#ra-principals-error").textContent = "用户目录读取失败，禁止保存并保留输入：" + e.message;
      } finally {
        if (d.isConnected) {
          gate(); d.querySelector("#ra-principals-retry").disabled = false;
          for (const key of ["userIds", "groupIds"]) d.querySelector(`[name="${key}"]`).disabled = false;
        }
      }
    }
    for (const [key, ids] of [["userIds", group?.user_ids || []], ["groupIds", group?.group_ids || []]]) d.querySelector(`[name="${key}"]`).innerHTML = ids.map((id) => `<option value="${esc(id)}" selected>${esc(id)}</option>`).join("");
    d.querySelector('[name="assetIds"]').onchange = (event) => {
      selected.clear();
      for (const option of event.target.selectedOptions) selected.add(option.value);
      d.querySelector("#ra-scope-count").textContent = `已选 ${selected.size} / 500 个资产`;
    };
    d.querySelector("#ra-scope-search").onclick = () => { query = d.querySelector('[name="scope-query"]').value.trim(); void loadAssets(0); };
    d.querySelector('[name="scope-query"]').onkeydown = (event) => { if (event.key === "Enter") { event.preventDefault(); d.querySelector("#ra-scope-search").click(); } };
    d.querySelector("#ra-scope-prev").onclick = () => { void loadAssets(Math.max(0, offset - 100)); };
    d.querySelector("#ra-scope-next").onclick = () => { void loadAssets(offset + 100); };
    d.querySelector("#ra-principals-retry").onclick = () => { void loadPrincipals(); };
    drawAssets();
    gate();
    void loadAssets();
    void loadPrincipals();
  }
  function transferRate(t) {
    S.rates ??= new Map();
    const now = performance.now(),
      old = S.rates.get(t.id);
    let rate = old?.rate || 0;
    if (old && now - old.time > 500 && t.done_bytes >= old.bytes)
      rate = (t.done_bytes - old.bytes) / ((now - old.time) / 1000);
    S.rates.set(t.id, { time: now, bytes: t.done_bytes, rate });
    return t.state === "running" && rate > 0
      ? size(rate) +
          "/s · 约 " +
          Math.ceil((t.total_bytes - t.done_bytes) / rate) +
          " 秒"
      : "—（等待实际传输采样）";
  }
  const can = (p) => S.user?.permissions?.includes(p),
    allowed = (a, p) => {
      const protocol = p.startsWith("sftp.") ? "sftp" : p.startsWith("rdp.") ? "rdp" : p.startsWith("ssh.") || p === "credential.temporary" ? "ssh" : "";
      return Boolean(a?.grants?.some((g) => g.actions?.includes(p) && (!protocol || (g.protocols?.includes(protocol) && g.actions.includes("remoteAccount.use")))));
    };
  function terminalView(target) {
    target.innerHTML =
      '<div class="ra-bar">' +
      button("新建连接", "tab", "access") +
      button("横向分屏", "layout", "horizontal") +
      button("纵向分屏", "layout", "vertical") +
      button("仅当前", "single") +
      button("关闭其他", "close-others") +
      button("关闭全部", "close-all") +
      button("文件面板", "terminal-files") +
      button("传输任务", "tab", "transfers") +
      '</div><div class="ra-tabs" id="ra-term-tabs"></div><div class="ra-panes ' +
      (S.layout === "vertical" ? "vertical" : "") +
      '" id="ra-panes"></div><section class="ra-card" id="ra-terminal-files" hidden></section>';
    drawTerms();
  }
  function drawTerms() {
    if (S.tab !== "terminal") return;
    const tabs = root.querySelector("#ra-term-tabs"),
      panes = root.querySelector("#ra-panes");
    if (!tabs || !panes) return;
    tabs.innerHTML = "";
    panes.replaceChildren();
    for (const [id, t] of S.terms) {
      const b = document.createElement("button");
      b.textContent = t.title;
      b.className = id === S.active ? "selected" : "";
      b.draggable = true;
      b.onclick = () => {
        S.active = id;
        if (S.visible.size <= 1) {
          S.visible.clear();
          S.visible.add(id);
        } else S.visible.add(id);
        drawTerms();
      };
      b.ondragstart = (e) => e.dataTransfer.setData("text/plain", id);
      b.ondragover = (e) => e.preventDefault();
      b.ondrop = (e) => {
        e.preventDefault();
        const from = e.dataTransfer.getData("text/plain");
        if (!S.terms.has(from)) return;
        const reordered = new Map();
        for (const [k, v] of S.terms) {
          if (k === id) reordered.set(from, S.terms.get(from));
          if (k !== from) reordered.set(k, v);
        }
        S.terms = reordered;
        drawTerms();
      };
      b.ondblclick = () => renameTerm(id);
      tabs.append(b);
      if (S.visible.has(id)) {
        panes.append(t.panel);
        t.panel.classList.toggle("active", id === S.active);
        requestAnimationFrame(() => t.fit.fit());
      }
    }
    if (!S.terms.size)
      panes.innerHTML =
        '<div class="ra-empty">从“我的接入”选择已授权账号创建 SSH 会话。</div>';
  }
  function renameTerm(id) {
    const t = S.terms.get(id);
    dialog(
      "重命名标签",
      input("标签名称", "title", t.title),
      "保存",
      async (f) => {
        const title = f.get("title").trim();
        if (!title || title.length > 80) throw Error("标签名称需为 1–80 字符");
        t.title = title;
        t.titleEl.textContent = title;
        drawTerms();
      },
    );
  }
  async function addTerminal(id, title, recover = false) {
    if (S.terms.has(id)) {
      S.active = id;
      S.visible.add(id);
      await show("terminal");
      return;
    }
    const term = new Terminal({
        cursorBlink: true,
        scrollback: 5000,
        fontFamily: '"Cascadia Code", "SFMono-Regular", Consolas, monospace',
        fontSize: 13,
        allowProposedApi: false,
        theme: { background: "#101b25", foreground: "#d9e7ef" },
      }),
      fit = new FitAddon.FitAddon(),
      search = new SearchAddon.SearchAddon(),
      serialize = new SerializeAddon.SerializeAddon();
    term.loadAddon(fit);
    term.loadAddon(search);
    term.loadAddon(serialize);
    term.parser.registerOscHandler(52, () => true);
    term.parser.registerOscHandler(8, () => true);
    const panel = document.createElement("section");
    panel.className = "ra-pane";
    panel.innerHTML = `<div class="ra-pane-head"><strong></strong><span class="ra-term-state">连接中</span>${button("重命名", "term-rename", id)}${button("新窗口", "popout", id)}${button("重连", "reconnect", id)}${button("搜索", "term-search", id)}${button("复制", "term-copy", id)}${button("A+", "font-up", id)}${button("A−", "font-down", id)}${button("清屏", "term-clear", id)}${button("关闭", "term-close", id)}</div><div class="ra-terminal"></div>`;
    const t = {
      id,
      title,
      panel,
      term,
      fit,
      search,
      serialize,
      seq: 0,
      inputSeq: 0,
      lease: 0,
      ws: null,
      stopped: false,
      titleEl: panel.querySelector("strong"),
      state: panel.querySelector(".ra-term-state"),
    };
    t.titleEl.textContent = title;
    S.terms.set(id, t);
    S.active = id;
    S.visible.add(id);
    await show("terminal");
    term.open(panel.querySelector(".ra-terminal"));
    fit.fit();
    const ro = new ResizeObserver(() => {
      if (panel.isConnected) {
        try {
          fit.fit();
        } catch {}
      }
    });
    ro.observe(panel);
    t.ro = ro;
    term.onResize(({ cols, rows }) => send(t, { type: "resize", cols, rows }));
    term.onData((data) => {
      if (t.lease && !t.stopped && t.ws?.readyState === WebSocket.OPEN)
        send(t, { type: "input", sequence: ++t.inputSeq, data });
    });
    panel.onclick = () => {
      S.active = id;
    };
    panel.addEventListener(
      "paste",
      (e) => {
        e.preventDefault();
        e.stopImmediatePropagation();
        const value = e.clipboardData?.getData("text/plain") || "";
        if (!value) return;
        if (value.length > 30000) {
          msg("粘贴超过 30,000 字符，请分批粘贴");
          return;
        }
        dialog(
          "确认向远端粘贴",
          "<p>多行文本可能包含会立即执行的命令。请检查后确认。</p><pre>" +
            esc(value) +
            "</pre>",
          "发送到终端",
          async () => term.paste(value),
        );
      },
      true,
    );
    if (recover && window.opener) {
      await new Promise((resolve) => {
        const timeout = setTimeout(resolve, 1200);
        const listener = (event) => {
          if (
            event.origin !== location.origin ||
            event.source !== window.opener ||
            event.data?.type !== "infra-terminal-snapshot" ||
            event.data.id !== id
          )
            return;
          window.removeEventListener("message", listener);
          clearTimeout(timeout);
          term.write(event.data.screen, () => {
            t.seq = event.data.seq;
            resolve();
          });
        };
        window.addEventListener("message", listener);
        window.opener.postMessage(
          { type: "infra-terminal-snapshot-request", id },
          location.origin,
        );
      });
    }
    await attach(t);
  }
  function send(t, m) {
    if (t.ws?.readyState === WebSocket.OPEN && t.lease && !t.stopped)
      t.ws.send(JSON.stringify({ ...m, lease: t.lease }));
  }
  async function attach(t) {
    t.ws?.close();
    t.stopped = false;
    t.lease = 0;
    t.inputSeq = 0;
    t.state.textContent = "正在授权";
    const auth = await api(
      "/ssh/sessions/" + t.id + "/attach-authorizations",
      "POST",
      { windowId: S.window },
    );
    const gateway = S.routes?.get(t.id) || S.user.gatewayId;
    const url = new URL(
      (gateway !== S.user.gatewayId
        ? "/gateways/" + encodeURIComponent(gateway)
        : "") +
        base +
        "/ssh/sessions/" +
        t.id +
        "/stream",
      location.href,
    );
    url.protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(url);
    t.ws = ws;
    ws.onopen = () =>
      ws.send(
        JSON.stringify({
          type: "attach",
          authorization: auth.authorization,
          lastSequence: t.seq,
        }),
      );
    ws.onmessage = (event) => {
      const m = JSON.parse(event.data);
      if (m.type === "status") {
        t.lease = m.lease;
        t.state.textContent = m.state;
        send(t, { type: "resize", cols: t.term.cols, rows: t.term.rows });
      } else if (m.type === "output") {
        if (m.sequence <= t.seq) return;
        const data = Uint8Array.from(atob(m.data), (c) => c.charCodeAt(0));
        t.term.write(data, () => {
          t.seq = m.sequence;
          send(t, { type: "ack", sequence: t.seq });
        });
      } else if (m.type === "error") {
        t.state.textContent = m.code;
        t.stopped = true;
        msg(m.message || m.code);
      }
    };
    ws.onclose = () => {
      if (t.ws !== ws) return;
      t.lease = 0;
      t.state.textContent = t.stopped
        ? "已移交 / 关闭"
        : "已断开；可在保留期内手动重连";
    };
    ws.onerror = () => (t.state.textContent = "连接错误");
    clearInterval(t.heartbeat);
    t.heartbeat = setInterval(() => send(t, { type: "heartbeat" }), 15000);
  }
  window.addEventListener("message", (event) => {
    if (
      event.origin !== location.origin ||
      event.data?.type !== "infra-terminal-snapshot-request"
    )
      return;
    const t = S.terms.get(event.data.id);
    if (!t || event.source !== t.child) return;
    t.stopped = true;
    t.ws?.close();
    event.source.postMessage(
      {
        type: "infra-terminal-snapshot",
        id: t.id,
        seq: t.seq,
        screen: t.serialize.serialize(),
      },
      location.origin,
    );
    t.state.textContent = "已移交到新窗口";
  });
  async function closeTerminal(id) {
    const t = S.terms.get(id);
    if (!t) return;
    await api("/ssh/sessions/" + id, "DELETE");
    t.stopped = true;
    t.ws?.close();
    clearInterval(t.heartbeat);
    t.ro.disconnect();
    t.term.dispose();
    S.terms.delete(id);
    S.visible.delete(id);
    S.active = S.terms.keys().next().value;
    if (!S.visible.size && S.active) S.visible.add(S.active);
    drawTerms();
  }
  async function filesView(target) {
    const epoch = S.renderEpoch, viewEpoch = S.viewEpoch;
    const current = () => S.mounted && epoch === S.renderEpoch && viewEpoch === S.viewEpoch && target?.isConnected;
    if (!S.access.length) {
      const access = await api("/my/access");
      if (!current()) return;
      S.access = access;
    }
    const a = S.files
      ? S.access.find((x) => x.account_id === S.files.account)
      : null;
    if (!a) {
      target.innerHTML = card(
        "<h3>选择 SFTP 账号</h3>" +
          S.access
            .filter((a) => allowed(a, "sftp.list"))
            .map(
              (a) =>
                '<div class="ra-bar">' +
                button(
                  esc(a.asset_name + " / " + a.account_name),
                  "files",
                  a.account_id,
                ) +
                "</div>",
            )
            .join(""),
      );
      return;
    }
    const f = S.files;
    const listing = await api(
      "/sftp/entries?" +
        new URLSearchParams({
          accountId: f.account,
          path: f.path || "",
          offset: String(f.offset || 0),
        }),
    );
    if (!current()) return;
    f.path = listing.path;
    f.list = listing.entries;
    target.innerHTML = card(
      `<div class="ra-bar"><strong>${esc(a.asset_name)} / ${esc(a.account_name)}</strong>${button("切换账号", "files-reset")}</div><form id="ra-path" class="ra-bar"><input class="ra-file-path" name="path" value="${esc(f.path)}" aria-label="远程路径"><button>前往</button>${button("上级", "files-up")}${button("刷新", "files-refresh")}</form><div class="ra-bar">${allowed(a, "sftp.mkdir") ? button("新建目录", "mkdir") : ""}${allowed(a, "sftp.upload") ? button("上传文件", "upload-files") + button("上传整个文件夹（含空目录）", "upload-folder") : ""}${button("下载选中（ZIP）", "download")}<select id="ra-conflict" aria-label="同名文件策略"><option value="ask">同名先报冲突</option><option value="skip">跳过同名文件</option><option value="rename">自动重命名</option><option value="overwrite">覆盖（需要确认与授权）</option></select></div>${allowed(a, "sftp.upload") ? '<div id="ra-drop" class="ra-drop">拖放文件或目录到此处；保留目录层级。空目录使用目录句柄或拖放目录接口采集。</div>' : ""}<small>允许读取：${esc(listing.readRoots.join(", "))}；允许写入：${esc(listing.writeRoots.join(", "))}</small>` +
        '<div class="ra-bar"><input id="ra-file-filter" placeholder="筛选当前页名称" style="width:220px"><label><input type="checkbox" id="ra-show-hidden"> 显示隐藏文件</label><select id="ra-file-sort"><option value="name">名称排序</option><option value="size">大小排序</option></select>' +
        button("全选当前可见", "file-select-all") +
        button("清空选择", "file-select-none") +
        "</div>" +
        table(
          ["选择", "名称", "大小", "修改时间", "权限", "操作"],
          listing.entries.map(
            (x, i) =>
              `<tr><td><input type="checkbox" name="ra-selected" value="${i}" aria-label="选择 ${esc(x.name)}" ${x.symlink ? "disabled" : ""}></td><td>${x.directory ? "▣" : "▤"} ${x.directory && !x.symlink ? button(esc(x.name), "file-open", String(i)) : esc(x.name)}${x.symlink ? " · 符号链接禁止跟随" : ""}</td><td>${x.directory ? "—" : size(x.size)}</td><td>${new Date(x.modified).toLocaleString()}</td><td><code>${esc(x.mode)}</code></td><td>${!x.directory && !x.symlink ? button("下载", "download-file", String(i)) : ""}${allowed(a, "sftp.rename") && !x.symlink ? button("重命名", "rename-file", String(i)) : ""}${allowed(a, "sftp.delete") && !x.symlink ? button("删除", "delete-file", String(i)) : ""}</td></tr>`,
          ),
        ) +
        `<div class="ra-bar">${button("上一页", "files-prev", "", f.offset ? "" : "disabled")}<small>${f.offset + 1}–${listing.nextOffset} / ${listing.total}</small>${button("下一页", "files-next", "", listing.nextOffset < listing.total ? "" : "disabled")}</div>`,
    );
    target.querySelector("#ra-path").onsubmit = (e) => {
      e.preventDefault();
      f.path = new FormData(e.target).get("path");
      f.offset = 0;
      show("files").catch((e) => msg(e.message));
    };
    const filter = target.querySelector("#ra-file-filter"),
      hidden = target.querySelector("#ra-show-hidden"),
      sort = target.querySelector("#ra-file-sort");
    const apply = () => {
      const tbody = target.querySelector("tbody");
      const rows = [...tbody.querySelectorAll("tr")].filter((r) =>
        r.querySelector("[name=ra-selected]"),
      );
      for (const row of rows) {
        const x = f.list[Number(row.querySelector("[name=ra-selected]").value)];
        row.hidden =
          (!hidden.checked && x.name.startsWith(".")) ||
          !x.name.toLowerCase().includes(filter.value.toLowerCase());
      }
      rows
        .sort((ra, rb) => {
          const a =
              f.list[Number(ra.querySelector("[name=ra-selected]").value)],
            b = f.list[Number(rb.querySelector("[name=ra-selected]").value)];
          return sort.value === "size"
            ? b.size - a.size
            : a.name.localeCompare(b.name);
        })
        .forEach((r) => tbody.append(r));
    };
    filter.oninput = apply;
    hidden.onchange = apply;
    sort.onchange = apply;
    apply();
    const drop = target.querySelector("#ra-drop");
    if (drop) {
      drop.ondragover = (e) => {
        e.preventDefault();
      };
      drop.ondrop = async (e) => {
        e.preventDefault();
        try {
          const intent = captureFileIntent("sftp.upload");
          const items = [...e.dataTransfer.items],
            all = [];
          for (const item of items) {
            const entry = item.webkitGetAsEntry?.();
            if (entry) await walkEntry(entry, "", all);
            else {
              const file = item.getAsFile();
              if (file) all.push({ path: file.name, file, directory: false });
            }
          }
          await startUpload(all, intent);
        } catch (e) {
          msg(e.message);
        }
      };
    }
  }
  const join = (a, b) => (a === "/" ? "" : a) + "/" + b;
  async function walkEntry(entry, parent, out) {
    const p = parent + entry.name;
    if (entry.isFile) {
      const file = await new Promise((resolve, reject) =>
        entry.file(resolve, reject),
      );
      out.push({ path: p, file, directory: false });
    } else {
      out.push({ path: p, directory: true });
      const reader = entry.createReader();
      let chunk;
      do {
        chunk = await new Promise((resolve, reject) =>
          reader.readEntries(resolve, reject),
        );
        for (const child of chunk) await walkEntry(child, p + "/", out);
      } while (chunk.length);
    }
    if (out.length > 10000) throw Error("选择的条目超过页面 10,000 项限制");
  }
  async function walkHandle(handle, parent, out) {
    const p = parent + handle.name;
    if (handle.kind === "file")
      out.push({ path: p, file: await handle.getFile(), directory: false });
    else {
      out.push({ path: p, directory: true });
      for await (const child of handle.values())
        await walkHandle(child, p + "/", out);
    }
    if (out.length > 10000) throw Error("条目超过 10,000 项限制");
  }
  async function pickFiles(folder = false) {
    const intent = captureFileIntent("sftp.upload");
    if (folder) {
      if (!window.showDirectoryPicker)
        throw Error(
          "当前浏览器不支持保留空目录的目录选择器。请拖放文件夹，或使用支持 File System Access 的桌面浏览器。",
        );
      const h = await showDirectoryPicker({ mode: "read" }),
        all = [];
      msg("正在扫描目录，尚未上传…");
      await walkHandle(h, "", all);
      await startUpload(all, intent);
      return;
    }
    const input = document.createElement("input");
    input.type = "file";
    input.multiple = true;
    input.onchange = () =>
      startUpload(
        [...input.files].map((file) => ({
          path: file.name,
          file,
          directory: false,
        })),
        intent,
      ).catch((e) => msg(e.message));
    input.click();
  }
  const hash = async (blob) =>
    Array.from(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", await blob.arrayBuffer()),
      ),
      (b) => b.toString(16).padStart(2, "0"),
    ).join("");
  function captureFileIntent(action) {
    const account = S.access.find((entry) => entry.account_id === S.files?.account);
    if (!S.user || S.logoutPending || !S.mounted || !account || !allowed(account, action))
      throw Error("当前身份或文件操作权限不可用，请重新读取授权后选择文件");
    return {
      userId: S.user.id, epoch: S.renderEpoch, viewEpoch: S.viewEpoch,
      assetId: account.asset_id, accountId: account.account_id, path: S.files.path,
      conflict: root.querySelector("#ra-conflict")?.value || "ask",
    };
  }
  function fileIntentCurrent(intent) {
    if (!S.mounted || S.logoutPending || S.user?.id !== intent.userId || S.renderEpoch !== intent.epoch ||
        S.viewEpoch !== intent.viewEpoch || S.files?.account !== intent.accountId || S.files?.path !== intent.path)
      throw Error("文件选择已失效：身份、页面或目标目录已变化；未转投新目标，请重新选择文件");
  }
  async function startUpload(all, intent) {
    if (!all.length) throw Error("未选择文件");
    fileIntentCurrent(intent);
    const conflict = intent.conflict;
    if (
      conflict === "overwrite" &&
      !confirm("覆盖策略会在上传和校验完成后原子替换同名文件，是否确认？")
    )
      return;
    fileIntentCurrent(intent);
    const access = await api("/my/access");
    fileIntentCurrent(intent);
    const account = access.find((entry) => entry.asset_id === intent.assetId && entry.account_id === intent.accountId);
    if (!allowed(account, "sftp.upload")) throw Error("该资产账号的上传权限已失效，请重新读取授权");
    const task = await api("/transfers", "POST", {
      accountId: intent.accountId,
      direction: "upload",
      target: intent.path,
      conflict,
      confirmOverwrite: conflict === "overwrite",
      paths: [],
    });
    const manifest = all.map((x) => ({
      path: x.path,
      directory: x.directory,
      size: x.file?.size || 0,
      modifiedMs: x.file?.lastModified || 0,
      sha256: "",
    }));
    try {
      // Never continue an accepted task under a later login or a different file selection.
      fileIntentCurrent(intent);
      for (let start = 0; start < manifest.length; start += 500) {
        await api("/transfers/" + task.id + "/items", "POST", {
          items: manifest.slice(start, start + 500),
          final: start + 500 >= manifest.length,
        });
        fileIntentCurrent(intent);
      }
      S.uploads.set(task.id, new Map(all.map((x) => [x.path, x])));
      await show("transfers");
      await runUpload(task.id);
    } catch (e) {
      msg("任务 " + task.id + "：" + e.message);
      throw e;
    }
  }
  async function runUpload(id) {
    if (S.uploadControllers?.has(id))
      throw Error("此任务已在上传，请先暂停后再续传。");
    const source = S.uploads.get(id);
    if (!source) throw Error("本地文件引用未保留；请重新选择原文件继续。");
    const userId = S.user?.id, epoch = S.renderEpoch, controller = new AbortController();
    const current = () => {
      if (!userId || S.user?.id !== userId || S.logoutPending || !S.mounted || S.renderEpoch !== epoch || controller.signal.aborted)
        throw Error("上传已停止：身份或页面已变化，或操作已暂停；请读取任务状态后重新关联文件");
    };
    current();
    S.uploadControllers ??= new Map();
    S.uploadControllers.set(id, controller);
    try {
      const task = await api("/transfers/" + id, "GET", undefined, {}, controller.signal);
      current();
      for (const item of task.items) {
        current();
        if (["completed", "skipped", "cancelled"].includes(item.state))
          continue;
        const local = source.get(item.relative_path);
        if (
          !local ||
          !!local.directory !== item.is_directory ||
          (!local.directory &&
            (local.file.size !== item.size ||
              local.file.lastModified !== item.modified_ms))
        )
          throw Error(
            "本地文件的路径、大小或修改时间与原任务不匹配：" +
              item.relative_path,
          );
        const url = "/transfers/" + id + "/items/" + item.id + "/content";
        if (item.is_directory) {
          await api(url, "PUT", new Blob([]), {}, controller.signal);
          current();
          continue;
        }
        let offset = item.offset_bytes;
        let verified = 0;
        for (const chunk of item.chunks || []) {
          if (
            chunk.offset !== verified ||
            chunk.size < 0 ||
            chunk.offset + chunk.size > offset
          )
            throw Error(
              "服务端续传分块记录不连续，请检查任务：" + item.relative_path,
            );
          if (controller.signal.aborted) throw Error("上传已暂停或取消");
          if (
            (await hash(
              local.file.slice(chunk.offset, chunk.offset + chunk.size),
            )) !== chunk.sha256
          )
            throw Error(
              "本地文件已上传部分的内容发生变化，不能续传：" +
                item.relative_path,
            );
          current();
          verified += chunk.size;
        }
        if (verified !== offset)
          throw Error("服务端续传分块记录不完整：" + item.relative_path);
        do {
          current();
          const blob = local.file.slice(offset, offset + 4 * 1024 * 1024);
          const digest = await hash(blob);
          current();
          const res = await api(
            url,
            "PUT",
            blob,
            {
              "Upload-Offset": String(offset),
              "Upload-SHA256": digest,
            },
            controller.signal,
          );
          current();
          offset = res.offset;
          msg(
            `上传 ${item.relative_path}：已确认 ${size(offset)} / ${size(item.size)}`,
          );
          if (item.size === 0) break;
        } while (offset < item.size);
      }
      current();
      const result = await api("/transfers/" + id + "/commit", "POST", {}, {}, controller.signal);
      current();
      msg("任务 " + id + "：" + result.state);
      if (S.tab === "transfers") await show("transfers");
    } finally {
      if (S.uploadControllers.get(id) === controller) S.uploadControllers.delete(id);
    }
  }
  async function resume(id) {
    if (S.uploads.has(id)) {
      await runUpload(id);
      return;
    }
    dialog(
      "重新关联本地文件",
      "<p>重新选择原文件或文件夹。页面和服务端分别核对已确认分块的 SHA-256，内容变化时拒绝续传。</p>" +
        select(
          "原上传方式",
          "sourceType",
          [
            ["files", "单个或多个文件"],
            ["folder", "整个文件夹"],
          ],
          "files",
        ) +
        '<label>原文件（文件夹模式请直接点击继续选择目录）<input name="sourceFiles" type="file" multiple></label>',
      "继续续传",
      async (f, form) => {
        const all = [];
        if (f.get("sourceType") === "folder") {
          if (!window.showDirectoryPicker)
            throw Error("此浏览器不支持目录句柄；请使用兼容桌面浏览器");
          await walkHandle(
            await showDirectoryPicker({ mode: "read" }),
            "",
            all,
          );
        } else {
          for (const file of form.elements.sourceFiles.files)
            all.push({ path: file.name, file, directory: false });
          if (!all.length) throw Error("请选择原文件");
        }
        S.uploads.set(id, new Map(all.map((x) => [x.path, x])));
        await runUpload(id);
      },
    );
  }
  async function download(indices, single = false) {
    const intent = captureFileIntent("sftp.download"),
      paths = indices.map((i) => S.files.list[i].name);
    if (!paths.length) throw Error("请选择文件或目录");
    let handle = null;
    if (window.showSaveFilePicker)
      handle = await showSaveFilePicker({
        suggestedName: single ? paths[0] : "infrascope-files.zip",
      });
    fileIntentCurrent(intent);
    const access = await api("/my/access");
    fileIntentCurrent(intent);
    const account = access.find((entry) => entry.asset_id === intent.assetId && entry.account_id === intent.accountId);
    if (!allowed(account, "sftp.download")) throw Error("该资产账号的下载权限已失效，请重新读取授权");
    const t = await api("/transfers", "POST", {
      accountId: intent.accountId,
      direction: "download",
      target: intent.path,
      conflict: "ask",
      paths,
      confirmOverwrite: false,
    });
    try { fileIntentCurrent(intent); }
    catch (e) { throw Error("任务 " + t.id + " 已接受，但本地下载未启动；" + e.message + "。请重新登录原账号查看任务状态。"); }
    const taskGateway = S.routes?.get(t.id);
    const url =
      (taskGateway && taskGateway !== S.user.gatewayId
        ? "/gateways/" + encodeURIComponent(taskGateway)
        : "") +
      base +
      "/transfers/" +
      t.id +
      "/content" +
      (single ? "?format=file" : "");
    if (!handle) {
      const link = document.createElement("a");
      link.href = url;
      link.download = single ? paths[0] : "infrascope-files.zip";
      link.click();
      msg("已交给浏览器下载。任务状态仅反映网关传输，请检查浏览器下载结果。");
      await show("transfers");
      return;
    }
    let writer, reader;
    const controller = new AbortController();
    const current = () => {
      if (!S.mounted || S.logoutPending || S.user?.id !== intent.userId || S.renderEpoch !== intent.epoch || controller.signal.aborted)
        throw Error("本地下载已停止：身份或页面已变化；任务结果请由原账号重新核对");
    };
    S.downloadControllers ??= new Map();
    S.downloadControllers.set(t.id, controller);
    try {
      writer = await handle.createWritable();
      current();
      const r = await fetch(url, { credentials: "same-origin", signal: controller.signal });
      current();
      if (!r.ok) {
        const v = await r.json();
        throw Error(v.error);
      }
      reader = r.body.getReader();
      let done = 0;
      while (true) {
        const part = await reader.read();
        current();
        if (part.done) break;
        await writer.write(part.value);
        current();
        done += part.value.length;
        msg("本地写入中：" + size(done));
      }
      const state = await api("/transfers/" + t.id, "GET", undefined, {}, controller.signal);
      current();
      if (state.state !== "completed")
        throw Error("网关传输未完整完成：" + state.state);
      await writer.close();
      writer = null;
      current();
      msg("文件已完成写入，请核对远端文件内容。");
    } catch (e) {
      controller.abort();
      await reader?.cancel().catch(() => {});
      await writer?.abort().catch(() => {});
      if (S.user?.id === intent.userId && S.renderEpoch === intent.epoch) msg("下载未完成：" + e.message);
    } finally {
      reader?.releaseLock();
      if (S.downloadControllers.get(t.id) === controller) S.downloadControllers.delete(t.id);
    }
    if (S.user?.id === intent.userId && S.renderEpoch === intent.epoch && S.mounted) await show("transfers");
  }
  function personEditor(person) {
    if (S.user.role !== "admin") throw Error("仅平台管理员可维护人员");
    const mount = S.renderEpoch;
    dialog(person ? "编辑责任联系人" : "添加责任联系人",
      '<p class="muted">此处只登记联系人，不创建登录账号、不同步企业微信、不发送邮件。部门与人员 ID 用于区分同名人员。</p>' +
      (person ? `<p class="muted">人员 ID：${esc(person.id)} · 版本 ${esc(person.version)}。发生并发冲突时输入会保留，请取消并重新读取后核对修改。</p>` : "") +
      '<div class="ra-grid">' + input("姓名（最多 180 个 UTF-8 字节）", "displayName", person?.display_name || "") +
      input("部门", "department", person?.department || "") +
      input("邮箱（可留空，未验证可投递性）", "email", person?.email || "", "email") +
      select("联系人类型", "contactType", [["internal", "内部人员"], ["external", "外部联系人"]], person?.contact_type || "internal") + '</div>' +
      check("启用人员（停用后不能新绑定责任；既有责任未变更时可保留）", "enabled", person?.enabled ?? true),
      "保存联系人", async (form) => {
        await api(person ? "/people/" + encodeURIComponent(person.id) : "/people", person ? "PATCH" : "POST",
          window.InfraRemoteAssets.personPayload({ ...Object.fromEntries(form), enabled: form.has("enabled") }, person));
        if (S.mounted && mount === S.renderEpoch) try { await show("people"); } catch (e) { msg("联系人已保存，但列表读取失败：" + e.message); }
      });
  }
  async function ownershipHistory(assetId) {
    requireAssetManage(assetId);
    const epoch = S.renderEpoch, viewEpoch = S.viewEpoch;
    const history = await api("/assets/" + encodeURIComponent(assetId) + "/ownership-history");
    if (!S.mounted || epoch !== S.renderEpoch || viewEpoch !== S.viewEpoch) return;
    const d = dialog("责任变更历史",
      '<p class="muted">最近最多 100 条服务端持久化责任快照；姓名与部门为变更当时记录，不代表当前仍启用。此页面不修改责任，也不授予访问权限。</p>' +
      table(["版本 / 时间", "责任状态", "责任人员快照", "操作人"], history.map((entry) => {
        const snapshots = new Map((entry.people_snapshot || []).map((person) => [person.id, person]));
        const roles = ownershipRoles.map(([field, label]) => {
          const raw = entry.ownership?.[field], ids = Array.isArray(raw) ? raw : raw ? [raw] : [];
          return ids.length ? `<div>${esc(label)}：${ids.map((id) => {
            const person = snapshots.get(id);
            return esc(person ? `${person.displayName} · ${person.department || "未填写部门"} · ${id}` : "[缺失快照] " + id);
          }).join("；")}</div>` : "";
        }).join("");
        return `<tr><td>${esc(entry.revision)}<small>${esc(new Date(entry.changed_at).toLocaleString())}</small></td><td>${esc(ownershipStatus(entry))}</td><td>${roles || "无责任快照"}</td><td><code>${esc(entry.changed_by)}</code></td></tr>`;
      })), "关闭", async () => {});
    d.querySelector("[data-close]").hidden = true;
  }
  function assetEditor(a, continuation) {
    if (a ? !assetManage(a) : !can("asset.manage")) throw Error("当前身份不能编辑此资产");
    const mount = S.renderEpoch;
    const endpointFields = ["ssh", "sftp", "rdp"].map((protocol) => {
      const endpoint = a?.endpoints.find((item) => item.protocol === protocol);
      const enabled = Boolean(endpoint);
      return `<fieldset class="ra-endpoint"><legend>${check(protocol.toUpperCase(), protocol + "-enabled", enabled)}</legend><div class="ra-grid" data-endpoint="${protocol}">` +
        input("主机名 / IP（不含端口）", protocol + "-host", endpoint?.host || "") +
        input("端口", protocol + "-port", endpoint?.port || (protocol === "rdp" ? 3389 : 22), "number") +
        input("网关 ID", protocol + "-gateway", endpoint?.gatewayId || S.user.gatewayId) + "</div></fieldset>";
    }).join("");
    const metadata = a?.metadata || {};
    const ownership = a?.ownership || {};
    const people = new Map();
    const selections = new Map(ownershipRoles.map(([field]) => [field, Array.isArray(ownership[field]) ? [...ownership[field]] : ownership[field] ? [ownership[field]] : []]));
    let peoplePage = [], peopleOffset = 0, peopleQuery = "", requestNumber = 0, peopleLoaded = false, organizationLoaded = false;
    const d = dialog(
      a ? "编辑资产" : "添加资产",
      `<p class="muted">保存仅登记资产，不会扫描、采集或认定目标在线。允许不配置远程端点；无端点也不代表离线。责任绑定不会授予账号访问权限。</p>` +
      (a ? `<p class="muted">资产 ID：${esc(a.id)} · 当前版本 ${esc(a.version)}。冲突时保留输入，取消并重新读取后核对修改。</p><p class="ra-warning">保存变更将终止该资产已有受控 SSH 会话，并使旧启动票据失效；请核对授权后重新连接。归档还会撤销关联授权。</p>` : "") +
      (a?.ownershipLegacy ? '<p class="ra-warning">历史资产尚未补录责任；本次保存必须明确选择责任状态及对应人员。取消不会修改历史记录。</p>' : "") +
      `<div class="ra-grid">` + input("资产名称", "name", a?.name || "") +
      input("分组", "groupName", a?.group_name || "") +
      select("资产类别（与物理 / 虚拟、操作系统独立）", "category", [["", "请选择类别"], ...categories], a?.category || "") +
      select("物理 / 虚拟类型", "kind", [["physical", "物理设备"], ["virtual", "虚拟机"]], a?.kind || "physical") +
      select("操作系统", "osFamily", [["linux", "Linux"], ["windows", "Windows"], ["other", "其他 / 待确认"]], a?.os_family || "other") +
      input("环境", "environment", a?.environment || "") + input("地点", "site", a?.site || "") + input("业务", "business", a?.business || "") +
      "</div>" + input("标签（逗号分隔）", "tags", (a?.tags || []).join(", ")) +
      input("说明", "description", a?.description || "") + organizationFields() +
      `<div class="ra-checks">${check("启用资产", "enabled", a?.enabled ?? true)}${check("归档（撤销关联授权并停止新连接）", "archived", a?.archived ?? false)}</div>` +
      '<fieldset class="ra-ownership"><legend>人员与责任</legend>' +
      select("责任状态（必须主动选择）", "ownership-state", [["", "请选择责任状态"], ["assigned", "已分配 · 必选使用人"], ["pending", "待认领 · 必选待认领负责人"]], a?.ownershipLegacy ? "" : ownership.state || "") +
      '<div class="ra-people-search">' + input("搜索人员（姓名 / 部门）", "people-query") + '<button type="button" id="ra-picker-search">搜索 / 重试读取</button></div>' +
      '<div class="ra-bar"><button type="button" id="ra-picker-prev">上一页</button><span id="ra-picker-page" role="status"></span><button type="button" id="ra-picker-next">下一页</button></div>' +
      '<p class="ra-error" id="ra-picker-error" role="alert"></p><p class="muted">选项显示姓名、部门和人员 ID；搜索或翻页不会清除已选人员。责任状态切换会清除不适用的使用人或待认领负责人；二者不可混用。通知人与备用联系人可多选，各最多 20 人。目录为空时请先由管理员在“人员与责任”登记真实联系人。</p>' +
      '<p class="muted">非历史待补录资产的责任内容完全不变时，保存其他字段会保留原责任，不新增责任历史；即使旧联系人已停用或缺失，也可停用或归档资产。修改任一责任字段后，全部责任人员都必须有效且启用。人员目录读取失败时仍禁止保存。</p>' +
      '<div class="ra-grid">' + ownershipRoles.map(([field, label]) => `<label>${label}<select name="ownership-${field}" ${field.endsWith("Ids") ? 'multiple size="4"' : ""}></select></label>`).join("") +
      '</div><p class="ra-warning" id="ra-picker-warning"></p></fieldset>' +
      '<h4>协议与独立端点（可选）</h4><p class="muted">仅在获得授权后配置真实端点。SSH/SFTP 由网关连接，RDP 由本人 Windows 电脑连接。配置端点不等于已完成实机验证。</p>' + endpointFields +
      "<details><summary>虚拟化元数据（不提供虚拟机控制）</summary><div class=\"ra-grid\">" +
      input("平台 / 厂商", "provider", metadata.provider || "") + input("虚拟机名称", "vmName", metadata.vmName || "") +
      input("实例 ID", "instanceId", metadata.instanceId || "") + input("宿主标记", "hypervisorLabel", metadata.hypervisorLabel || "") + "</div></details>" +
      (!a ? check("保存后继续配置连接（端点、远程账号和本人授权）", "continueRemote", true) : ""),
      "保存资产",
      async (form) => {
        if (!peopleLoaded || !organizationLoaded) throw Error("人员或组织目录尚未成功读取，请重试后保存；不能将读取失败当作目录缺失");
        const fields = Object.fromEntries(form);
        fields.enabled = form.has("enabled");
        fields.archived = form.has("archived");
        fields.ownership = { state: form.get("ownership-state") };
        for (const [field] of ownershipRoles) fields.ownership[field] = field.endsWith("Ids") ? form.getAll("ownership-" + field) : form.get("ownership-" + field);
        fields.endpoints = ["ssh", "sftp", "rdp"].map((protocol) => ({
          protocol, enabled: form.has(protocol + "-enabled"), host: form.get(protocol + "-host"),
          port: form.get(protocol + "-port"), gatewayId: form.get(protocol + "-gateway"),
        }));
        const saved = await api(a ? "/api/v1/assets/" + encodeURIComponent(a.id) : "/api/v1/assets", a ? "PATCH" : "POST", window.InfraRemoteAssets.assetPayload(fields, a, [...people.values()]));
        if (!d.isConnected || mount !== S.renderEpoch || !S.user || !S.mounted) return;
        if (continuation) { await continuation(); return; }
        try { await show("assets"); } catch (e) { msg("资产已保存，但列表读取失败：" + e.message); }
        if (!a && form.has("continueRemote") && d.isConnected && mount === S.renderEpoch && S.mounted) {
          d.close();
          await assetRemote(saved.id);
        }
      },
    );
    function editorGate() {
      d.dataset.submitBlocked = String(!peopleLoaded || !organizationLoaded);
      d.querySelector("[type=submit]").disabled = window.InfraRemoteAssets.submitDisabled(d.dataset.submitting === "true", peopleLoaded && organizationLoaded);
    }
    function pickerWarnings() {
      const selected = [...new Set([...selections.values()].flat())];
      const invalid = selected.filter((id) => !people.get(id)?.enabled);
      const noEmail = selected.filter((id) => people.get(id)?.enabled && !(people.get(id)?.email_configured || people.get(id)?.email));
      const current = { state: d.querySelector('[name="ownership-state"]').value };
      for (const [field] of ownershipRoles) current[field] = field.endsWith("Ids") ? selections.get(field) : selections.get(field)[0] || "";
      const unchanged = window.InfraRemoteAssets.ownershipUnchanged(a, current);
      d.querySelector("#ra-picker-warning").textContent = [
        !peopleLoaded ? "人员目录尚未成功读取，禁止保存；请等待或重试，不能据此认定人员缺失。" : "",
        peopleLoaded && invalid.length ? (unchanged ? `${invalid.length} 位既有责任人员缺失或停用，责任需补齐。当前责任未变更，可保存其他字段（包括停用、归档）；会保留原责任且不新增责任历史。` : `${invalid.length} 位责任人员缺失或停用；责任已变更或属于历史待补录，须全部改为有效且启用人员后保存。`) : "",
        noEmail.length ? `${noEmail.length} 位已选人员未填写可投递邮箱；本次只登记责任，不发送通知。` : "",
        selected.length && !noEmail.length ? "邮箱仅为登记信息，尚未验证投递，也未发送通知。" : "",
      ].filter(Boolean).join(" ");
    }
    function drawPeople() {
      for (const [field] of ownershipRoles) {
        const selected = selections.get(field);
        const ids = [...new Set([...selected, ...peoplePage.map((person) => person.id)])];
        d.querySelector(`[name="ownership-${field}"]`).innerHTML = (field.endsWith("Ids") ? "" : '<option value="">请选择 / 未设置</option>') + ids.map((id) => {
          const person = people.get(id), chosen = selected.includes(id);
          return `<option value="${esc(id)}" ${chosen ? "selected" : ""} ${person && !person.enabled && !chosen ? "disabled" : ""}>${esc(person ? personLabel(person) : "[缺失或不可访问] " + id)}</option>`;
        }).join("");
      }
      pickerWarnings();
    }
    async function loadPeople(offset = 0) {
      const request = ++requestNumber;
      const submit = d.querySelector("[type=submit]");
      let loaded = false;
      peopleLoaded = false;
      d.dataset.submitBlocked = "true";
      submit.disabled = true;
      pickerWarnings();
      for (const id of ["ra-picker-search", "ra-picker-prev", "ra-picker-next"]) d.querySelector("#" + id).disabled = true;
      d.querySelector("#ra-picker-page").textContent = "正在读取真实人员目录…";
      d.querySelector("#ra-picker-error").textContent = "";
      try {
        const missing = [...new Set([...selections.values()].flat())].filter((id) => !people.has(id));
        for (let i = 0; i < missing.length; i += 20) {
          const references = await api("/people?ids=" + encodeURIComponent(missing.slice(i, i + 20).join(",")));
          for (const person of references) people.set(person.id, person);
        }
        const list = await api("/people?offset=" + offset + "&q=" + encodeURIComponent(peopleQuery));
        if (request !== requestNumber || !d.isConnected) return;
        peopleOffset = offset;
        peoplePage = list;
        for (const person of list) people.set(person.id, person);
        peopleLoaded = true;
        drawPeople();
        loaded = true;
        d.querySelector("#ra-picker-page").textContent = `第 ${Math.floor(offset / 100) + 1} 页 · ${list.length} 项`;
      } catch (e) {
        if (!d.isConnected || request !== requestNumber) return;
        d.querySelector("#ra-picker-error").textContent = "人员目录读取失败：" + e.message + "。已保留表单，请重试；不会使用演示人员替代。";
        d.querySelector("#ra-picker-page").textContent = "读取失败";
      } finally {
        if (d.isConnected && request === requestNumber) {
          editorGate();
          d.querySelector("#ra-picker-search").disabled = false;
          d.querySelector("#ra-picker-prev").disabled = peopleOffset === 0;
          d.querySelector("#ra-picker-next").disabled = peoplePage.length !== 100;
        }
      }
    }
    d.querySelector("#ra-picker-search").onclick = () => {
      peopleQuery = d.querySelector('[name="people-query"]').value.trim();
      void loadPeople(0);
    };
    d.querySelector('[name="people-query"]').onkeydown = (event) => {
      if (event.key === "Enter") { event.preventDefault(); d.querySelector("#ra-picker-search").click(); }
    };
    d.querySelector("#ra-picker-prev").onclick = () => { void loadPeople(Math.max(0, peopleOffset - 100)); };
    d.querySelector("#ra-picker-next").onclick = () => { void loadPeople(peopleOffset + 100); };
    for (const [field] of ownershipRoles) d.querySelector(`[name="ownership-${field}"]`).onchange = (event) => {
      selections.set(field, [...event.target.selectedOptions].map((option) => option.value).filter(Boolean));
      pickerWarnings();
    };
    d.querySelector('[name="ownership-state"]').onchange = (event) => {
      if (event.target.value === "assigned") selections.set("claimantId", []);
      if (event.target.value === "pending") selections.set("userId", []);
      drawPeople();
    };
    const sync = () => {
      const state = d.querySelector('[name="ownership-state"]').value;
      d.querySelector('[name="ownership-userId"]').disabled = state !== "assigned";
      d.querySelector('[name="ownership-claimantId"]').disabled = state !== "pending";
      for (const protocol of ["ssh", "sftp", "rdp"]) {
        const enabled = d.querySelector(`[name="${protocol}-enabled"]`).checked;
        d.querySelectorAll(`[data-endpoint="${protocol}"] input`).forEach((field) => { field.disabled = !enabled; });
      }
    };
    d.addEventListener("change", sync);
    sync();
    drawPeople();
    organizationPicker(d, a?.organization_id || "", (ready) => { organizationLoaded = ready; editorGate(); });
    void loadPeople();
  }
  const remoteProtocolLabels = { ssh: "LinuxTab / SSH 终端", sftp: "SFTP 文件管理", rdp: "Windows RDP 桌面" };
  async function serverOnboarding() {
    if (S.user?.role !== "admin") throw Error("快捷添加服务器仅限管理员，其他用户请由管理员分配账号");
    const mount = S.renderEpoch, identity = S.user;
    const current = () => S.mounted && !S.logoutPending && S.user === identity && S.user?.role === "admin" && mount === S.renderEpoch;
    const people = [];
    for (let offset = 0; offset < 10000; offset += 100) {
      const page = await api("/people?offset=" + offset);
      if (!current()) return;
      people.push(...page.filter((person) => person.enabled));
      if (page.length < 100) break;
      if (offset === 9900) throw Error("人员目录过大，请使用高级资产配置；不会截断责任人选择");
    }
    const organizations = await organizationOptions(current);
    if (!current()) return;
    if (!people.length) throw Error("请先在人员与责任中登记至少一位真实责任联系人");
    let pending, saved;
    const d = dialog("添加服务器并继续连接",
      '<p class="muted">一次填写服务器、系统账号和密码/私钥，明确确认后同事务保存资产、加密凭据、本人限期授权，以及仅该 IP 和所选端口的网关许可。不会开放整个网段或自动信任 SSH 指纹。</p>' +
      '<div class="ra-grid">' + input("服务器名称", "name") + select("目标系统", "osFamily", [["linux", "Linux"], ["windows", "Windows"]], "linux") + input("服务器 IP（IPv4 / IPv6）", "host") + input("目标机用户名", "username") + '</div>' +
      '<div class="ra-checks">' + check("SSH 终端", "proto-ssh", true) + check("SFTP 文件", "proto-sftp", true) + check("RDP 桌面", "proto-rdp", false) + '</div><div class="ra-grid">' + input("SSH 端口", "sshPort", "22", "number") + input("SFTP 端口", "sftpPort", "22", "number") + input("RDP 端口", "rdpPort", "3389", "number") + '</div>' +
      select("认证方式", "authType", [["password", "目标账号密码"], ["private_key", "SSH 私钥"], ["interactive", "RDP 本机输入凭据"]], "password") +
      '<div data-onboard-secret="password">' + input("目标账号密码（仅经 HTTPS 加密保存，不回显）", "password", "", "password") + '</div>' +
      '<div data-onboard-secret="private_key" hidden><label>SSH 私钥<textarea name="privateKey" autocomplete="off" spellcheck="false"></textarea></label>' + input("私钥口令", "passphrase", "", "password") + '</div>' +
      select("明确待认领责任人", "claimantId", [["", "请选择责任人"], ...people.map((person) => [person.id, personLabel(person)])], "") +
      select("组织（成员仅只读资产，可不选）", "organizationId", [["", "不绑定组织"], ...organizations.filter((org) => org.enabled).map((org) => [org.id, org.name])], "") +
      '<div data-onboard-files>' + input("SFTP 可读根目录（必填，例如 /home/ops）", "readRoots") + check("明确允许文件写入（默认只读）", "allowFileWrite", false) + input("SFTP 可写根目录（启用写入时必填）", "writeRoots") + '</div>' +
      '<div data-onboard-rdp>' + check("允许 RDP 剪贴板", "allowClipboard", false) + check("允许 RDP 磁盘映射", "allowDrives", false) + check("允许 RDP 交互输入凭据", "allowInteractive", false) + '</div>' +
      input("本人使用授权小时数（1–720）", "hours", "8", "number") +
      '<p class="ra-warning">SSH 首次连接仍需独立核对主机指纹；Windows RDP 需本人在线连接器及目标启用远程桌面。IP/端口不能证明目标服务可用。所有秘密只进入本机 HTTPS 服务，不保存到浏览器存储。</p>' +
      check("确认保存加密凭据、限期授权本人，并仅允许上述 IP / 协议 / 端口", "confirm", false),
      "验证平台身份并保存，继续连接", async (f, form) => {
        if (!current()) return;
        if (saved) { d.close(); await assetRemote(saved.assetId); return; }
        const protocols = ["ssh", "sftp", "rdp"].filter((p) => f.has("proto-" + p));
        const hours = Number(f.get("hours")), authType = f.get("authType");
        if (!f.has("confirm") || !protocols.length || !f.get("claimantId")) throw Error("请选择协议和责任人，并明确确认本次保存与授权");
        if (!Number.isFinite(hours) || hours < 1 || hours > 720) throw Error("授权时长须为 1–720 小时");
        const roots = (key) => String(f.get(key) || "").split(",").map((v) => v.trim()).filter(Boolean);
        if (protocols.includes("sftp") && !roots("readRoots").length) throw Error("请明确填写 SFTP 可读目录，不会默认授权整台机器");
        const intent = { confirm:true, name:String(f.get("name")).trim(), osFamily:f.get("osFamily"), host:String(f.get("host")).trim(), username:String(f.get("username")).trim(), authType,
          protocols, sshPort:Number(f.get("sshPort")), sftpPort:Number(f.get("sftpPort")), rdpPort:Number(f.get("rdpPort")), claimantId:f.get("claimantId"), organizationId:f.get("organizationId") || "",
          secret: authType === "password" ? {password:f.get("password")} : authType === "private_key" ? {privateKey:f.get("privateKey"),passphrase:f.get("passphrase")} : {},
          readRoots:protocols.includes("sftp") ? roots("readRoots") : [], writeRoots:protocols.includes("sftp") && f.has("allowFileWrite") ? roots("writeRoots") : [], allowFileWrite:protocols.includes("sftp") && f.has("allowFileWrite"),
          allowClipboard:protocols.includes("rdp") && f.has("allowClipboard"), allowDrives:protocols.includes("rdp") && f.has("allowDrives"), allowInteractive:protocols.includes("rdp") && f.has("allowInteractive") };
        await reauth();
        if (!current() || !d.open || !d.isConnected) return;
        const fingerprint = JSON.stringify({ ...intent, hours });
        if (pending?.fingerprint !== fingerprint) pending = { fingerprint, payload: { ...intent, idempotencyKey:uid(), expiresAt:new Date(Date.now()+hours*3600000).toISOString() } };
        saved = await api("/api/v1/servers/onboard", "POST", pending.payload);
        pending = null; form.reset();
        if (!current() || !d.open || !d.isConnected) return;
        d.close();
        try { await show("assets"); if (current()) await assetRemote(saved.assetId); } catch (e) { if (current()) msg("服务器已保存，资产 ID " + saved.assetId + "。读取连接步骤失败，请从列表继续，不要重复创建：" + e.message); }
      });
    const sync = () => {
      const type = d.querySelector('[name="authType"]').value;
      for (const name of ["password", "private_key"]) d.querySelector(`[data-onboard-secret="${name}"]`).hidden = type !== name;
      d.querySelector('[data-onboard-files]').hidden = !d.querySelector('[name="proto-sftp"]').checked;
      d.querySelector('[data-onboard-rdp]').hidden = !d.querySelector('[name="proto-rdp"]').checked;
    };
    d.querySelector('[name="osFamily"]').onchange = (event) => {
      const windows = event.target.value === "windows";
      d.querySelector('[name="proto-ssh"]').checked = !windows;
      d.querySelector('[name="proto-sftp"]').checked = !windows;
      d.querySelector('[name="proto-rdp"]').checked = windows; sync();
    };
    d.addEventListener("change", sync);
    d.addEventListener("close", () => { pending = null; d.querySelector("form")?.reset(); }, { once:true });
    sync();
  }
  const remoteStateLabels = { asset_disabled: "资产已停用 / 归档", needs_endpoint: "缺少协议端点", needs_account: "需要远程账号", needs_credential: "需要目标机凭据", needs_grant: "需要本人账号授权", needs_host_key: "需要核实主机指纹", needs_gateway_policy: "网关网络策略未就绪", needs_connector: "需要本人 Windows 连接器", ready_to_attempt: "配置就绪，可尝试连接" };
  const remoteAction = (text, action, protocol = "", account = "") => `<button type="button" data-remote-action="${action}" data-protocol="${esc(protocol)}" data-account="${esc(account)}">${text}</button>`;
  async function assetRemote(assetId) {
    const mount = S.renderEpoch, viewEpoch = S.viewEpoch, identity = S.user;
    const current = () => S.mounted && S.user && !S.logoutPending && mount === S.renderEpoch && viewEpoch === S.viewEpoch;
    const data = await api("/api/v1/assets/" + encodeURIComponent(assetId) + "/remote-readiness");
    if (!current()) return;
    if (data.assetId !== assetId) throw Error("连接准备结果不属于当前资产，已停止操作");
    const d = dialog(data.assetName + " · 连接 / 文件", '<p class="muted">所有操作绑定这台服务器。登记资产不等于已连接；请按缺少的条件配置，实际认证、读写或桌面登录成功后才算连接成功。</p><div id="ra-remote-cards"></div><p class="muted">SSH 需要目标机运行 SSH 服务；Windows 文件管理需要另外启用 OpenSSH / SFTP。RDP 只适用于启用远程桌面的目标，并由你本人已配对的 Windows 电脑连接。</p>', "关闭", async () => {});
    d.classList.add("ra-remote-dialog");
    d.querySelector("[data-close]").hidden = true;
    const alive = () => current() && d.isConnected && d.open;
    let readiness = data, request = 0, actionBusy = false;
    function draw() {
      d.querySelector("#ra-remote-cards").innerHTML = readiness.protocols.map((p) => {
        const managed = readiness.canManage && can("remoteAccount.manage");
        const rows = (p.accounts || []).map((a) => '<div class="ra-remote-account"><strong>' + esc(a.name) + '</strong><code>' + esc(a.username) + '</code>' +
          `<small>${esc(a.authType)} · ${a.credentialConfigured ? "凭据已保存（不回显）" : a.authType === "interactive" ? "交互式输入凭据" : "凭据未保存"} · ${a.authorized ? "本人已获此协议授权" : "本人未获此协议授权"}</small>` +
          `<p class="${a.state === "ready_to_attempt" ? "muted" : "ra-warning"}">${esc(remoteStateLabels[a.state] || a.state)}：${esc(a.reason || "")}</p><div class="ra-bar">` +
          (a.state === "ready_to_attempt" ? remoteAction(p.protocol === "ssh" ? "打开终端" : p.protocol === "sftp" ? "打开文件" : "选择本机并发起 RDP", "connect", p.protocol, a.id) : "") +
          (managed ? remoteAction("编辑账号", "account-edit", p.protocol, a.id) + (a.authType !== "interactive" ? remoteAction(a.credentialConfigured ? "更新凭据" : "设置凭据", "credential", p.protocol, a.id) : "") : "") +
          (readiness.canGrantSelf && S.user.role === "admin" ? remoteAction("明确授权给我", "grant", p.protocol, a.id) : "") + '</div></div>').join("");
        return `<section class="ra-remote-protocol"><h4>${esc(remoteProtocolLabels[p.protocol] || p.protocol)}</h4><code>${p.endpoint ? esc(p.endpoint.host) + ":" + esc(p.endpoint.port) : "未配置目标地址"}</code><p>${esc(remoteStateLabels[p.state] || p.state)}：${esc(p.reason || "")}</p>` + rows + '<div class="ra-bar">' +
          (readiness.canManage && can("asset.manage") ? remoteAction("配置端点", "endpoint", p.protocol) : "") +
          (managed && p.endpoint ? remoteAction("添加远程账号", "account-new", p.protocol) : "") +
          (readiness.canManage && p.endpoint && ["ssh", "sftp"].includes(p.protocol) ? remoteAction("核实主机指纹", "hostkey", p.protocol) : "") +
          (p.protocol === "rdp" && !readiness.connectorReady ? remoteAction("查看本人 Windows 设备", "connector", p.protocol) : "") + '</div>' +
          (!readiness.canGrantSelf && (p.accounts || []).some((a) => !a.authorized) ? '<small>请管理员在“账号分配”授予此账号和协议；资产只读范围不能自行授权。</small>' : "") + '</section>';
      }).join("") + '<p class="muted">SSH / SFTP 只连接明确允许的目标；快捷添加会按确认的 IP / 协议 / 端口配置许可，不放开整个 CIDR 网段。RDP 受控配对要求受信 HTTPS 与本人 Windows 连接器，签名就绪也不等于远端登录成功。</p>' + remoteAction("刷新这台服务器的连接条件", "refresh");
      for (const button of d.querySelectorAll("[data-remote-action]")) button.disabled = actionBusy;
    }
    async function refresh() {
      const n = ++request;
      const latest = await api("/api/v1/assets/" + encodeURIComponent(assetId) + "/remote-readiness");
      if (!alive() || n !== request) return null;
      if (latest.assetId !== assetId) throw Error("返回了其他资产的连接条件，已停止操作");
      readiness = latest; draw(); return latest;
    }
    d.onclick = async (event) => {
      const b = event.target.closest("[data-remote-action]");
      if (!b || b.disabled || actionBusy || !alive()) return;
      event.preventDefault(); event.stopPropagation(); actionBusy = true; b.disabled = true;
      const action = b.dataset.remoteAction, protocol = b.dataset.protocol, accountId = b.dataset.account;
      d.querySelector(".ra-error").textContent = "";
      try {
        if (action === "refresh") { await refresh(); return; }
        if (action === "connector") { d.close(); await show("connectors"); return; }
        const latest = await refresh();
        if (!latest || !alive()) return;
        const p = latest.protocols.find((item) => item.protocol === protocol);
        const account = p?.accounts?.find((item) => item.id === accountId);
        if (action === "connect") {
          if (!account || account.state !== "ready_to_attempt" || !p.endpoint) throw Error(account?.reason || p?.reason || "连接条件已变化，请重新配置");
          const access = await api("/my/access");
          if (!alive()) return;
          const selected = access.find((item) => item.asset_id === assetId && item.account_id === accountId);
          const required = { ssh: "ssh.connect", sftp: "sftp.list", rdp: "rdp.launch" }[protocol];
          if (!selected || !required || !allowed(selected, required)) throw Error("当前会话的账号授权已变化，请重新读取，不会使用其他资产的缓存账号");
          S.access = access;
          if (protocol === "ssh") {
            const session = await api("/ssh/sessions", "POST", { assetId, accountId, cols: 100, rows: 28 });
            if (!alive()) {
              // A dismissed connect dialog must not leave its newly created PTY running.
              if (S.user === identity && !S.logoutPending) {
                try { await api("/ssh/sessions/" + encodeURIComponent(session.id), "DELETE", undefined, {}, undefined, session.gatewayId || ""); }
                catch (e) { if (S.user === identity && S.mounted) msg("连接已创建但未附着，回收未确认：" + e.message + "。请在会话管理中核对；不能视为连接成功。"); }
              }
              return;
            }
            d.close(); await addTerminal(session.id, selected.asset_name + " / " + selected.username);
          } else if (protocol === "sftp") {
            S.files = { account: accountId, path: "", offset: 0 };
            d.close(); await show("files");
          } else await rdp(accountId, alive, () => d.close());
          return;
        }
        if (!latest.canManage) throw Error("当前资产只有只读权限，不能配置连接");
        if (action === "grant") {
          if (!account || !latest.canGrantSelf || S.user.role !== "admin") throw Error("只有管理员能显式授予本人远程账号权限");
          grantSelf(assetId, account, protocol, latest, refresh, alive); return;
        }
        if (action === "credential") {
          if (!account || !can("remoteAccount.manage")) throw Error("没有此账号管理权限");
          await credential(accountId, refresh, alive); return;
        }
        if (action === "hostkey") { await remoteHostKey(assetId, protocol, refresh, alive); return; }
        const asset = await api("/api/v1/assets/" + encodeURIComponent(assetId));
        if (!alive()) return;
        if (asset.id !== assetId || !assetManage(asset)) throw Error("资产管理权限已变化");
        if (action === "endpoint") assetEditor(asset, refresh);
        if (action === "account-new") accountEditor(null, asset, refresh, alive, protocol);
        if (action === "account-edit") {
          if (!account) throw Error("账号已不在当前资产可用范围");
          const details = await api("/accounts/" + encodeURIComponent(accountId));
          if (!alive()) return;
          if (details.asset_id !== assetId) throw Error("账号不属于当前资产");
          accountEditor(details, asset, refresh, alive);
        }
      } catch (e) { if (alive()) d.querySelector(".ra-error").textContent = e.message; else if (current()) msg(e.message); }
      finally {
        actionBusy = false;
        if (b.isConnected) b.disabled = false;
        if (alive()) for (const button of d.querySelectorAll("[data-remote-action]")) button.disabled = false;
      }
    };
    draw();
  }
  async function remoteHostKey(assetId, protocol, refresh, alive) {
    const probe = await api("/assets/" + encodeURIComponent(assetId) + "/host-key/probe", "POST", { protocol });
    if (!alive()) return;
    const d = dialog("通过可信渠道核实主机指纹", `<p>目标 ${esc(protocol)}。请与目标主机控制台或管理人员独立核对，不能仅凭本页探测就认为可信。</p><pre>${esc(probe.algorithm)}\n${esc(probe.fingerprint)}</pre>` + check("我已通过可信渠道核对指纹一致", "confirm", false), "核实后批准", async (f) => {
      if (!f.has("confirm")) throw Error("必须先独立核对主机指纹");
      await reauth();
      if (!alive() || !d.isConnected) return;
      await api("/assets/" + encodeURIComponent(assetId) + "/host-key/approve", "POST", { protocol, algorithm: probe.algorithm, fingerprint: probe.fingerprint, confirm: true });
      if (alive() && d.isConnected) await refresh();
    });
  }
  function grantSelf(assetId, account, protocol, readiness, refresh, parentCurrent) {
    if (S.user?.role !== "admin" || !readiness.canGrantSelf || readiness.assetId !== assetId) throw Error("不能为当前身份自行授权");
    const mount = S.renderEpoch;
    let pendingIntent;
    const alive = () => S.mounted && mount === S.renderEpoch && S.user?.role === "admin" && parentCurrent();
    const protocols = readiness.protocols.filter((p) => p.endpoint && p.accounts?.some((a) => a.id === account.id)).map((p) => p.protocol);
    const d = dialog("明确授权给当前登录用户", `<p>用户：<strong>${esc(S.user.displayName)}</strong> · ${esc(S.user.id || S.user.username || "当前登录管理员")}<br>资产：${esc(readiness.assetName)}<br>账号：${esc(account.name)} / ${esc(account.username)}</p><p class="ra-warning">这是新增账号使用权限，不会因为管理员身份自动授予。保存资产或账号也不会执行此操作。</p><div class="ra-checks">` +
      protocols.map((p) => check(remoteProtocolLabels[p], "grant-" + p, false)).join("") + '</div>' +
      input("授权有效小时数（1–720，最长 30 天）", "hours", "8", "number") +
      input("SFTP 可读根目录（逗号分隔，必须显式填写，例如 /srv/team）", "readRoots") +
      check("允许 SFTP 写入（默认只读）", "allowFileWrite", false) + input("SFTP 可写根目录（明确限定写入范围）", "writeRoots") +
      check("允许 RDP 剪贴板", "allowClipboard", false) + check("允许 RDP 磁盘映射", "allowDrives", false) +
      check("允许 RDP 交互输入凭据（交互账号必须勾选）", "allowInteractive", false) +
      check("我确认将上述账号和协议权限授予我自己", "confirm", false), "验证身份并授予本人", async (f) => {
        if (!alive()) return;
        const selected = protocols.filter((p) => f.has("grant-" + p)), hours = Number(f.get("hours"));
        const roots = (key) => String(f.get(key) || "").split(",").map((value) => value.trim()).filter(Boolean);
        if (!f.has("confirm") || !selected.length) throw Error("请明确选择协议并确认授予当前用户");
        if (!Number.isFinite(hours) || hours < 1 || hours > 720) throw Error("有效期必须为 1–720 小时");
        if (selected.includes("sftp") && !roots("readRoots").length) throw Error("SFTP 必须明确填写可读根目录，不会默认授权整个文件系统");
        if (f.has("allowFileWrite") && (!selected.includes("sftp") || !roots("writeRoots").length)) throw Error("允许写入时必须选择 SFTP 并填写可写根目录");
        if (selected.includes("rdp") && account.authType === "interactive" && !f.has("allowInteractive")) throw Error("交互式 RDP 账号必须明确允许交互输入凭据");
        await reauth();
        if (!alive() || !d.isConnected) return;
        const intent = {
          confirm: true, protocols: selected,
          readRoots: selected.includes("sftp") ? roots("readRoots") : [], writeRoots: selected.includes("sftp") && f.has("allowFileWrite") ? roots("writeRoots") : [],
          allowFileWrite: selected.includes("sftp") && f.has("allowFileWrite"), allowClipboard: selected.includes("rdp") && f.has("allowClipboard"),
          allowDrives: selected.includes("rdp") && f.has("allowDrives"), allowInteractive: selected.includes("rdp") && f.has("allowInteractive"),
        };
        const fingerprint = JSON.stringify({ ...intent, hours });
        // Preserve the exact mutation across a lost response; edited intent gets a new key.
        if (pendingIntent?.fingerprint !== fingerprint) pendingIntent = { fingerprint, payload: { ...intent, idempotencyKey: uid(), expiresAt: new Date(Date.now() + hours * 3600000).toISOString() } };
        await api("/accounts/" + encodeURIComponent(account.id) + "/grant-self", "POST", pendingIntent.payload);
        if (alive() && d.isConnected) {
          try { await refresh(); } catch (e) { msg("授权已保存，但连接条件回读失败：" + e.message + "。请刷新面板核对，不要重复新增授权。"); }
        }
      });
    return d;
  }
  async function accounts(assetId) {
    requireAssetManage(assetId);
    if (!can("remoteAccount.manage")) throw Error("没有远程账号管理权限，请在“我的接入”查看个人授权");
    const epoch = S.renderEpoch, viewEpoch = S.viewEpoch;
    const rows = await api("/assets/" + assetId + "/accounts");
    if (!S.mounted || epoch !== S.renderEpoch || viewEpoch !== S.viewEpoch) return;
    S.accountRows = rows;
    const a = S.assets.find((x) => x.id === assetId);
    const d = dialog(
      (a?.name || assetId) + " · 远程账号",
      table(
        ["名称 / 用户名", "协议", "凭据", "操作"],
        rows.map(
          (x) =>
            `<tr><td>${esc(x.name)}<small>${esc(x.username)}</small></td><td>${esc(x.protocols.join(", "))}</td><td>${x.credential_configured ? "已设置 · 版本 " + x.credential_version : "未设置"}</td><td>${can("remoteAccount.manage") ? button("编辑", "account-edit", x.id) + button("更新凭据", "credential", x.id) + button("测试认证", "account-test", x.id) : ""}</td></tr>`,
        ),
      ) +
        (can("remoteAccount.manage")
          ? button("＋ 添加远程账号", "account-new", assetId)
          : ""),
      "关闭",
      async () => {},
    );
    d.querySelector("[data-close]").hidden = true;
  }
  function accountEditor(x, asset, continuation, parentCurrent = () => true, requestedProtocol) {
    const assetId = typeof asset === "string" ? asset : asset?.id || x?.asset_id;
    const target = typeof asset === "object" && asset ? asset : S.assets.find((a) => a.id === assetId);
    if (!target || !assetManage(target) || !can("remoteAccount.manage")) throw Error("当前资产不能管理远程账号");
    const mount = S.renderEpoch;
    const current = () => S.mounted && S.user && mount === S.renderEpoch && parentCurrent();
    const available = ["ssh", "sftp", "rdp"].filter((p) => target.endpoints.some((endpoint) => endpoint.protocol === p) || x?.protocols?.includes(p));
    if (!available.length) throw Error("请先为此服务器配置 SSH / SFTP / RDP 协议端点");
    const defaults = requestedProtocol ? [requestedProtocol] : target.os_family === "windows" ? ["rdp"] : target.os_family === "linux" ? ["ssh", "sftp"] : [];
    let savedId = x?.id;
    const d = dialog(x ? "编辑远程账号" : "添加远程账号", `<p>服务器：<strong>${esc(target.name)}</strong> · ${esc(target.os_family)}</p><p class="muted">填写目标操作系统上的真实账号，不是平台登录账号。添加账号不会自动创建系统用户，也不会自动授权任何人。</p>` +
      input("账号名称", "name", x?.name || "") + input("目标机用户名（Windows 可填 域\\用户名；仅 RDP 交互认证可留空）", "username", x?.username || "") +
      (x ? `<p>认证类型：<strong>${esc(x.auth_type)}</strong>（创建后不可更改）</p><small>${x.credential_configured ? "凭据已保存，不回显原值" : "尚未保存凭据"}</small>` : select("认证方式", "authType", [["password", "密码"], ["private_key", "SSH 私钥"], ["interactive", "RDP 交互输入（不保存凭据）"]], "password")) +
      '<fieldset><legend>允许协议（仅列已配置端点；仍需独立使用授权）</legend><div class="ra-checks">' + available.map((p) => check(remoteProtocolLabels[p], "protocol-" + p, (x?.protocols || defaults).includes(p))).join("") + '</div></fieldset>' +
      '<div class="ra-checks">' + check("启用账号", "enabled", x?.enabled ?? true) + check("归档账号（停止新连接）", "archived", x?.archived ?? false) + '</div>' +
      (!x ? check("保存账号后继续设置凭据（先验证平台身份）", "setCredential", true) : "") +
      '<p class="muted">Windows 的 SFTP 必须独立启用 OpenSSH 并配置 SFTP 端点；RDP 不提供网页文件协议。交互认证可在本人电脑输入另一个目标机身份，并非绑定特定系统用户。保存后返回这台服务器的连接配置。</p>', "保存账号", async (f) => {
        const authType = x?.auth_type || f.get("authType"), protocols = available.filter((p) => f.has("protocol-" + p));
        const name = String(f.get("name") || "").trim(), username = String(f.get("username") || "").trim();
        if (!name || (authType !== "interactive" && !username) || !protocols.length) throw Error("请填写名称、目标机用户名并选择至少一个协议（仅交互认证可不填用户名）");
        if (authType === "interactive" && protocols.some((p) => p !== "rdp")) throw Error("交互认证仅用于 RDP；SSH / SFTP 请使用密码或私钥");
        if (authType === "private_key" && protocols.includes("rdp")) throw Error("RDP 不支持 SSH 私钥，请使用独立密码或交互账号");
        if (!current()) return;
        const saved = await api(savedId ? "/accounts/" + encodeURIComponent(savedId) : "/assets/" + encodeURIComponent(assetId) + "/accounts", savedId ? "PATCH" : "POST", {
          name, username, authType, protocols, enabled: f.has("enabled"), archived: f.has("archived"),
        });
        savedId = saved.id || savedId;
        if (!current() || !d.isConnected) return;
        if (continuation) await continuation();
        if (!current() || !d.isConnected) return;
        if (!x && f.has("setCredential") && authType !== "interactive") {
          try { await credential(savedId, continuation || (() => assetRemote(assetId)), current); }
          catch (e) { if (current()) msg("账号已保存，凭据尚未设置：" + e.message + "。可从连接面板继续设置，不需要重复创建账号。"); }
        } else if (!continuation) {
          d.close(); await assetRemote(assetId);
        }
      });
    return d;
  }
  async function credential(id, continuation, parentCurrent = () => true) {
    const mount = S.renderEpoch, current = () => S.mounted && S.user && mount === S.renderEpoch && parentCurrent();
    await reauth();
    if (!current()) return;
    const x = await api("/accounts/" + encodeURIComponent(id));
    if (!current()) return;
    if (x.auth_type === "interactive") throw Error("交互式 RDP 账号不保存平台凭据，请在启动时本人输入");
    const d = dialog(
      "更新凭据：" + x.name,
      select(
        "操作",
        "action",
        [
          ["set", "设置 / 轮换保存的凭据"],
          ["clear", "清除平台保存的凭据"],
        ],
        "set",
      ) +
        (x.auth_type === "private_key"
          ? '<label>私钥<textarea name="privateKey" autocomplete="off"></textarea></label>' +
            input("私钥口令", "passphrase", "", "password")
          : input("远程账号密码", "password", "", "password")) +
        '<p class="muted">不会回显原凭据，也不会修改目标操作系统上的密码。</p>',
      "保存",
      async (f, form) => {
        if (!current()) return;
        await api("/accounts/" + id + "/credential", "POST", {
          action: f.get("action"),
          secret: {
            password: f.get("password") || "",
            privateKey: f.get("privateKey") || "",
            passphrase: f.get("passphrase") || "",
          },
        });
        form.reset();
        if (!current() || !d.isConnected) return;
        msg("凭据版本已更新；这不代表目标机认证已通过");
        if (continuation) await continuation();
      },
    );
    return d;
  }
  async function grantWizard() {
    const [subjects, assets] = await Promise.all([
      api("/grant-subjects"),
      api("/assets"),
    ]);
    if (!assets.length) throw Error("请先添加资产和远程账号");
    const choices = [
      ...subjects.users.map((u) => [
        "user:" + u.id,
        u.display_name + " / " + u.username,
      ]),
      ...subjects.groups.map((g) => ["group:" + g.id, "用户组 · " + g.name]),
    ];
    const actions = [
      "credential.temporary",
      "remoteAccount.use",
      "asset.view",
      "remoteAccount.view",
      "ssh.connect",
      "ssh.resume",
      "ssh.close",
      "sftp.list",
      "sftp.download",
      "sftp.upload",
      "sftp.mkdir",
      "sftp.rename",
      "sftp.delete",
      "rdp.launch",
      "rdp.clipboard",
      "rdp.driveRedirect",
    ];
    const d = dialog(
      "账号分配 · 批量授权",
      select("选择用户或用户组", "subject", choices, choices[0]?.[0]) +
        input("搜索全部资产", "assetSearch") +
        '<div class="ra-bar"><button type="button" id="ra-grant-search">搜索</button><button type="button" id="ra-grant-prev" disabled>上一页</button><button type="button" id="ra-grant-next">下一页</button></div>' +
        select(
          "选择资产",
          "assetId",
          assets.map((a) => [a.id, a.name]),
          assets[0].id,
        ) +
        '<label>选择远程账号（可多选）<select name="accounts" multiple required size="4"></select></label><div class="ra-checks">' +
        ["ssh", "sftp", "rdp"].map((p) => check(p, p, p === "ssh")).join("") +
        '</div><label>允许的具体动作</label><div class="ra-checks">' +
        actions
          .map((p) =>
            check(
              p,
              p,
              [
                "remoteAccount.use",
                "asset.view",
                "remoteAccount.view",
                "ssh.connect",
                "ssh.resume",
                "ssh.close",
              ].includes(p),
            ),
          )
          .join("") +
        "</div>" +
        input(
          "生效时间",
          "startsAt",
          new Date(Date.now() - 60000).toISOString(),
        ) +
        input(
          "到期时间",
          "expiresAt",
          new Date(Date.now() + 7 * 86400000).toISOString(),
        ) +
        input("可读根目录（逗号分隔）", "readRoots") +
        input("可写根目录（逗号分隔）", "writeRoots") +
        input("单文件字节上限", "maxFileBytes", 1073741824, "number") +
        input("任务总字节上限", "maxTotalBytes", 10737418240, "number") +
        input("最多条目数", "maxFiles", 10000, "number") +
        input("最多目录深度", "maxDepth", 32, "number") +
        input("最多并行任务", "maxConcurrent", 3, "number") +
        check("允许明确确认后的同名覆盖", "allowOverwrite", false) +
        check("允许 mstsc 交互式输入其他凭据", "allowInteractive", false) +
        '<p id="ra-grant-summary" class="muted"></p>',
      "确认分配",
      async (f, form) => {
        const ids = f.getAll("accounts");
        if (!ids.length) throw Error("请选择账号");
        const [kind, subject] = f.get("subject").split(":"),
          limits = {
            readRoots: f
              .get("readRoots")
              .split(",")
              .map((x) => x.trim())
              .filter(Boolean),
            writeRoots: f
              .get("writeRoots")
              .split(",")
              .map((x) => x.trim())
              .filter(Boolean),
            allowOverwrite: f.has("allowOverwrite"),
            allowInteractive: f.has("allowInteractive"),
          };
        for (const k of [
          "maxFileBytes",
          "maxTotalBytes",
          "maxFiles",
          "maxDepth",
          "maxConcurrent",
        ])
          limits[k] = Number(f.get(k));
        const payload = {
          userId: kind === "user" ? subject : "",
          groupId: kind === "group" ? subject : "",
          assetId: f.get("assetId"),
          actions: actions.filter((x) => f.has(x)),
          protocols: ["ssh", "sftp", "rdp"].filter((x) => f.has(x)),
          limits,
          startsAt: new Date(f.get("startsAt")).toISOString(),
          expiresAt: new Date(f.get("expiresAt")).toISOString(),
        };
        let count = 0;
        for (const accountId of ids) {
          try {
            await api("/grants", "POST", { ...payload, accountId });
            count++;
          } catch (e) {
            throw Error(
              "已成功分配 " + count + " 个账号，剩余停止：" + e.message,
            );
          }
        }
        msg("已分配 " + count + " 个账号");
        await show("grants");
      },
    );
    async function load() {
      if (!d.querySelector("[name=assetId]").value) {
        d.querySelector("[name=accounts]").innerHTML = "";
        summary();
        return;
      }
      const rows = await api(
        "/assets/" + d.querySelector("[name=assetId]").value + "/accounts",
      );
      d.querySelector("[name=accounts]").innerHTML = rows
        .filter((x) => x.enabled && !x.archived)
        .map(
          (x) =>
            '<option value="' +
            esc(x.id) +
            '">' +
            esc(
              x.name + " / " + x.username + " [" + x.protocols.join(",") + "]",
            ) +
            "</option>",
        )
        .join("");
      summary();
    }
    function summary() {
      const f = new FormData(d.querySelector("form"));
      d.querySelector("#ra-grant-summary").textContent =
        "授权摘要：选中 " +
        f.getAll("accounts").length +
        " 个账号；动作 " +
        actions.filter((x) => f.has(x)).join(", ") +
        "；到期 " +
        f.get("expiresAt");
    }
    d.querySelector("[name=assetId]").onchange = () =>
      load().catch((e) => msg(e.message));
    let assetOffset = 0,
      assetSearch = "";
    d.querySelector("#ra-grant-next").disabled = assets.length < 100;
    async function pageAssets(change) {
      if (change === 0) {
        assetSearch = d.querySelector("[name=assetSearch]").value.trim();
        assetOffset = 0;
      } else assetOffset = Math.max(0, assetOffset + change);
      try {
        const rows = await api(
          "/assets?offset=" +
            assetOffset +
            "&q=" +
            encodeURIComponent(assetSearch),
        );
        d.querySelector("[name=assetId]").innerHTML = rows
          .map(
            (a) =>
              '<option value="' + esc(a.id) + '">' + esc(a.name) + "</option>",
          )
          .join("");
        d.querySelector("#ra-grant-prev").disabled = assetOffset === 0;
        d.querySelector("#ra-grant-next").disabled = rows.length < 100;
        await load();
      } catch (e) {
        d.querySelector(".ra-error").textContent = e.message;
      }
    }
    d.querySelector("#ra-grant-search").onclick = () => pageAssets(0);
    d.querySelector("#ra-grant-prev").onclick = () => pageAssets(-100);
    d.querySelector("#ra-grant-next").onclick = () => pageAssets(100);
    d.querySelector("form").addEventListener("change", summary);
    await load();
  }
  async function grantEditor(g) {
    const defaults = g
      ? {
          userId: g.user_id || "",
          groupId: g.group_id || "",
          assetId: g.asset_id,
          accountId: g.account_id,
          actions: g.actions,
          protocols: g.protocols,
          limits: g.limits,
          startsAt: g.starts_at,
          expiresAt: g.expires_at,
        }
      : {
          userId: S.user.id,
          groupId: "",
          assetId: "",
          accountId: "",
          actions: [
            "remoteAccount.use",
            "asset.view",
            "remoteAccount.view",
            "ssh.connect",
            "ssh.resume",
            "ssh.close",
            "sftp.list",
            "sftp.download",
          ],
          protocols: ["ssh", "sftp"],
          limits: {
            readRoots: [],
            writeRoots: [],
            maxFileBytes: 1073741824,
            maxTotalBytes: 10737418240,
            maxFiles: 10000,
            maxDepth: 32,
            maxConcurrent: 3,
            allowOverwrite: false,
            allowInteractive: false,
          },
          startsAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 7 * 86400000).toISOString(),
        };
    jsonEditor(
      "分配准确的资产、账号、动作和有效期",
      defaults,
      g ? "/grants/" + g.id : "/grants",
      g ? "PATCH" : "POST",
    );
  }
  async function rdp(accountId, parentCurrent = () => true, onLaunch) {
    const mount = S.renderEpoch, viewEpoch = S.viewEpoch;
    const current = () => S.mounted && S.user && mount === S.renderEpoch && viewEpoch === S.viewEpoch && parentCurrent();
    const a = S.access.find((x) => x.account_id === accountId);
    if (!a || !allowed(a, "rdp.launch")) throw Error("当前账号没有明确的 RDP 启动授权");
    const devices = await api("/my/connectors");
    if (!current()) return;
    const capabilityReady = (device) => {
      const caps = device.capabilities;
      return Boolean(typeof device.version === "string" && device.version.trim() && caps &&
        ["ok", "credentialApi", "mstsc", "rdpsign"].every((key) => caps[key] === true) &&
        caps.signing?.ok === true && caps.signing?.configured === true);
    };
    const bound = devices.flatMap((d) =>
      (d.browser_bindings || [])
        .filter(
          (b) => !d.revoked && Date.now() - Date.parse(d.last_seen) < 20000 && d.approved_origin === location.origin,
        )
        .map((b) => ({ device: d, value: d.id + "|" + b.id })),
    );
    const valid = bound.filter(({ device }) => capabilityReady(device)).map(({ device, value }) => [value, device.name]);
    const excluded = bound.length - valid.length;
    if (!valid.length)
      throw Error(
        excluded ? "已绑定的在线 Windows 设备尚未明确通过连接器自检或 RDP 签名配置。请在本人连接器完成 Credential API、mstsc、rdpsign 自检与签名配置后刷新；未知能力不作为可连接。" : "当前浏览器没有在线、同源且有效绑定的 Windows 连接器。请到“我的 Windows 设备”配对。",
      );
    let pendingLaunch;
    const d = dialog(
      "在自己的 Windows 电脑打开 RDP",
      `<p>${esc(a.asset_name)} / ${esc(a.account_name)} · 目标与凭据由后端授权确定。</p>` +
        (excluded ? `<p class="ra-warning">已排除 ${excluded} 项尚未明确通过连接器自检或 RDP 签名配置的设备绑定。请在本人连接器完成自检与签名配置后刷新；未知状态不作为就绪。</p>` : "") +
        select("你的电脑（必须本人明确选择）", "device", [["", "请选择你要发起 RDP 的 Windows 电脑"], ...valid], "") +
        '<div class="ra-checks">' +
        check(
          "剪贴板（需授权）",
          "redirectClipboard",
          false,
        ) +
        check("磁盘映射（需授权）", "redirectDrives", false) +
        check("全屏", "fullscreen", true) +
        check("多显示器", "multiMonitor", false) +
        "</div>" +
        select(
          "磁盘范围",
          "driveMode",
          [
            ["all", "全部本地磁盘"],
            ["custom", "指定盘符"],
          ],
          "all",
        ) +
        input("自定义盘符", "driveList", "C:\\;D:\\") +
        '<p class="muted">提交后还需要在选定电脑的连接器页面确认。授权 60 秒过期。</p>',
      "发起授权",
      async (f) => {
        if (!current()) return;
        const selectedDevice = f.get("device");
        if (!valid.some(([id]) => id === selectedDevice)) throw Error("请选择你自己的目标 Windows 电脑，不会自动使用第一台在线设备");
        const [connectorId, browserBindingId] = selectedDevice.split("|");
        const options = {
          driveMode: f.get("driveMode"),
          driveList: f.get("driveList"),
        };
        for (const k of [
          "redirectClipboard",
          "redirectDrives",
          "fullscreen",
          "multiMonitor",
        ])
          options[k] = f.has(k);
        const intent = {
          assetId: a.asset_id,
          accountId,
          connectorId,
          browserBindingId,
          options,
        };
        const fingerprint = JSON.stringify(intent);
        if (pendingLaunch?.fingerprint !== fingerprint) pendingLaunch = { fingerprint, payload: { ...intent, idempotencyKey: uid() } };
        const t = await api("/rdp/launches", "POST", pendingLaunch.payload);
        if (!current() || !d.isConnected) return;
        msg("任务 " + t.id + " 已排队，请在你的连接器页面确认");
        onLaunch?.();
        await show("connectors");
      },
    );
  }
  async function click(event) {
    const b = event.target.closest("[data-ra]");
    if (!b || b.disabled || !S.mounted) return;
    event.preventDefault();
    const epoch = S.renderEpoch;
    const action = b.dataset.ra,
      id = b.dataset.id,
      t = S.terms.get(id);
    try {
      switch (action) {
        case "asset-telemetry":
          await assetTelemetry(id);
          break;
        case "agent-enrollment":
          agentEnrollment(id);
          break;
        case "agents-prev":
        case "agents-next":
          S.assetOffset = Math.max(0, S.assetOffset + (action === "agents-prev" ? -100 : 100));
          await show("agents");
          break;
        case "server-onboard":
          await serverOnboarding();
          break;
        case "reload":
          await render();
          break;
        case "tab":
          S.fileEmbedded = false;
          await show(id);
          break;
        case "terminal-files":
          const panel = root.querySelector("#ra-terminal-files");
          S.fileEmbedded = !S.fileEmbedded;
          panel.hidden = !S.fileEmbedded;
          if (S.fileEmbedded) {
            const active = S.terms.get(S.active);
            if (!active) throw Error("先选择一个 SSH 会话");
            const info = await api("/ssh/sessions/" + active.id);
            S.files = { account: info.accountId, path: "", offset: 0 };
            await filesView(panel);
          }
          break;
        case "password":
          passwordDialog();
          break;
        case "logout":
          await logout();
          break;
        case "asset-new":
          assetEditor();
          break;
        case "asset-detail":
          await assetDetails(id);
          break;
        case "asset-remote":
          b.closest?.("dialog")?.close();
          await assetRemote(id);
          break;
        case "assets-export":
          b.disabled = true;
          await exportAssets();
          break;
        case "import-new":
          importEditor("csv");
          break;
        case "discovery-new":
          importEditor("local_discovery");
          break;
        case "import-template":
          downloadImportTemplate();
          break;
        case "import-detail":
          b.disabled = true;
          await importDetails(id);
          break;
        case "organization-new":
          organizationEditor();
          break;
        case "organization-edit":
          const organization = S.organizations.find((item) => item.id === id);
          if (!organization) throw Error("组织记录已变化，请重新读取");
          organizationEditor(organization);
          break;
        case "organizations-prev":
          S.organizationOffset = Math.max(0, S.organizationOffset - 100);
          await show("organizations");
          break;
        case "organizations-next":
          S.organizationOffset += 100;
          await show("organizations");
          break;
        case "asset-group-new":
          assetGroupEditor();
          break;
        case "asset-group-edit":
          const group = S.assetGroups.find((item) => item.id === id);
          if (!group) throw Error("资产组记录已变化，请重新读取");
          assetGroupEditor(group);
          break;
        case "asset-groups-prev":
          S.assetGroupOffset = Math.max(0, S.assetGroupOffset - 100);
          await show("asset-groups");
          break;
        case "asset-groups-next":
          S.assetGroupOffset += 100;
          await show("asset-groups");
          break;
        case "assets-prev":
          S.assetOffset = Math.max(0, S.assetOffset - 100);
          await show("assets");
          break;
        case "assets-next":
          S.assetOffset += 100;
          await show("assets");
          break;
        case "asset-edit":
          requireAssetManage(id);
          assetEditor(S.assets.find((x) => x.id === id));
          break;
        case "ownership-history":
          await ownershipHistory(id);
          break;
        case "person-new":
          personEditor();
          break;
        case "person-edit":
          personEditor(S.people.find((person) => person.id === id));
          break;
        case "people-prev":
          S.peopleOffset = Math.max(0, S.peopleOffset - 100);
          await show("people");
          break;
        case "people-next":
          S.peopleOffset += 100;
          await show("people");
          break;
        case "accounts":
          await accounts(id);
          break;
        case "account-new":
          requireAssetManage(id);
          accountEditor(null, id);
          break;
        case "account-edit":
          accountEditor(S.accountRows.find((x) => x.id === id));
          break;
        case "credential":
          await credential(id);
          break;
        case "asset-test":
          requireAssetManage(id);
          dialog(
            "测试端点",
            select(
              "协议",
              "protocol",
              [
                ["ssh", "SSH"],
                ["sftp", "SFTP"],
                ["rdp", "RDP"],
              ],
              "ssh",
            ),
            "测试",
            async (f) =>
              msg(
                JSON.stringify(
                  await api(
                    "/assets/" + id + "/test",
                    "POST",
                    Object.fromEntries(f),
                  ),
                ),
              ),
          );
          break;
        case "account-test":
          dialog(
            "测试真实认证",
            select(
              "协议",
              "protocol",
              [
                ["ssh", "SSH"],
                ["sftp", "SFTP"],
              ],
              "ssh",
            ),
            "测试",
            async (f) =>
              msg(
                JSON.stringify(
                  await api(
                    "/accounts/" + id + "/test",
                    "POST",
                    Object.fromEntries(f),
                  ),
                ),
              ),
          );
          break;
        case "hostkey":
          requireAssetManage(id);
          dialog(
            "读取 SSH 主机指纹",
            select(
              "协议",
              "protocol",
              [
                ["ssh", "SSH"],
                ["sftp", "SFTP"],
              ],
              "ssh",
            ),
            "读取指纹",
            async (f) => {
              const protocol = f.get("protocol"),
                probe = await api("/assets/" + id + "/host-key/probe", "POST", {
                  protocol,
                });
              setTimeout(
                () =>
                  dialog(
                    "通过可信渠道核实主机指纹",
                    `<p>读取到的密钥尚未受信任，请与目标主机管理人员或控制台比对：</p><pre>${esc(probe.algorithm)}\n${esc(probe.fingerprint)}</pre>`,
                    "确认已核实并批准",
                    async () => {
                      await reauth();
                      await api("/assets/" + id + "/host-key/approve", "POST", {
                        protocol,
                        algorithm: probe.algorithm,
                        fingerprint: probe.fingerprint,
                        confirm: true,
                      });
                      msg("指纹已批准");
                    },
                  ),
                0,
              );
            },
          );
          break;
        case "user-new":
          await reauth();
          dialog(
            "添加平台用户",
            input("用户名", "username") +
              input("显示名称", "displayName") +
              input("初始密码", "initialPassword", "", "password") +
              select(
                "角色",
                "role",
                [
                  ["operator", "操作员"],
                  ["asset_manager", "资产管理员"],
                  ["auditor", "审计员"],
                  ["admin", "平台管理员"],
                ],
                "operator",
              ),
            "创建",
            async (f, form) => {
              await api("/users", "POST", Object.fromEntries(f));
              form.reset();
              await show("users");
            },
          );
          break;
        case "user-edit":
          await reauth();
          const u = S.records.find((x) => x.id === id);
          dialog(
            "编辑平台用户",
            select(
              "角色",
              "role",
              [
                ["operator", "操作员"],
                ["asset_manager", "资产管理员"],
                ["auditor", "审计员"],
                ["admin", "平台管理员"],
              ],
              u.role,
            ) +
              check("启用账号", "enabled", u.enabled) +
              input(
                "重置初始密码（留空不修改）",
                "initialPassword",
                "",
                "password",
              ),
            "保存并撤销旧登录",
            async (f) => {
              await api("/users/" + id, "PATCH", {
                role: f.get("role"),
                enabled: f.has("enabled"),
                initialPassword: f.get("initialPassword"),
              });
              await show("users");
            },
          );
          break;
        case "group-new":
          jsonEditor("创建用户组", { name: "", members: [] }, "/groups");
          break;
        case "group-edit":
          const g = S.records.find((x) => x.id === id);
          jsonEditor(
            "修改用户组",
            { name: g.name, members: g.members || [] },
            "/groups/" + id,
            "PATCH",
          );
          break;
        case "grant-new":
          await grantWizard();
          break;
        case "grant-edit":
          await grantEditor(S.records.find((x) => x.id === id));
          break;
        case "grant-revoke":
          if (confirm("撤销该授权？活动会话将由网关重新验证并终止。")) {
            await api("/grants/" + id, "DELETE");
            await show("grants");
          }
          break;
        case "ssh-temporary":
          await reauth();
          const temporaryAccount = S.access.find((x) => x.account_id === id);
          dialog(
            "仅用于本次 SSH 的临时凭据",
            input("密码（密码认证时填写）", "password", "", "password") +
              '<label>私钥（私钥认证时填写）<textarea name="privateKey" autocomplete="off"></textarea></label>' +
              input("私钥口令", "passphrase", "", "password"),
            "授权连接",
            async (f, form) => {
              const x = await api("/ssh/sessions", "POST", {
                assetId: temporaryAccount.asset_id,
                accountId: id,
                cols: 100,
                rows: 28,
                temporaryCredential: Object.fromEntries(f),
              });
              form.reset();
              await addTerminal(
                x.id,
                temporaryAccount.asset_name + " / " + temporaryAccount.username,
              );
            },
          );
          break;
        case "ssh":
          const a = S.access.find((x) => x.account_id === id);
          b.disabled = true;
          const session = await api("/ssh/sessions", "POST", {
            assetId: a.asset_id,
            accountId: id,
            cols: 100,
            rows: 28,
          });
          await addTerminal(session.id, a.asset_name + " / " + a.username);
          break;
        case "layout":
          S.layout = id;
          for (const key of S.terms.keys()) S.visible.add(key);
          await show("terminal");
          break;
        case "single":
          S.visible = new Set(S.active ? [S.active] : []);
          drawTerms();
          break;
        case "term-rename":
          renameTerm(id);
          break;
        case "term-close":
          if (confirm("结束该远程 SSH 会话？")) await closeTerminal(id);
          break;
        case "close-others":
        case "close-all":
          if (confirm("结束所选远程 SSH 会话？")) {
            const kept = S.active;
            for (const k of [...S.terms.keys()])
              if (action === "close-all" || k !== kept) await closeTerminal(k);
          }
          break;
        case "reconnect":
          await attach(t);
          break;
        case "popout":
          t.child = window.open(
            "/remote-workspace.html?sessionId=" + encodeURIComponent(id),
            "infra-" + id,
            "popup,width=1200,height=800",
          );
          if (!t.child) throw Error("浏览器阻止了新窗口，请允许此站点弹窗");
          break;
        case "term-search":
          dialog(
            "搜索本地终端缓冲",
            input("查找文本", "query"),
            "查找下一处",
            async (f) => {
              if (!t.search.findNext(f.get("query")))
                throw Error("当前缓冲中没有匹配");
            },
          );
          break;
        case "term-copy":
          await navigator.clipboard.writeText(t.term.getSelection());
          msg("选中文本已复制");
          break;
        case "font-up":
        case "font-down":
          t.term.options.fontSize = Math.max(
            10,
            Math.min(
              24,
              t.term.options.fontSize + (action === "font-up" ? 1 : -1),
            ),
          );
          t.fit.fit();
          break;
        case "term-clear":
          t.term.clear();
          msg("仅清理本地滚动回看，未向远程执行命令");
          break;
        case "files":
          S.files = { account: id, path: "", offset: 0 };
          await show("files");
          break;
        case "files-reset":
          S.files = null;
          await show("files");
          break;
        case "files-up":
          S.files.path = S.files.path.split("/").slice(0, -1).join("/") || "/";
          S.files.offset = 0;
          await show("files");
          break;
        case "file-open":
          S.files.path = join(S.files.path, S.files.list[Number(id)].name);
          S.files.offset = 0;
          await show("files");
          break;
        case "files-next":
          S.files.offset += 200;
          await show("files");
          break;
        case "files-prev":
          S.files.offset = Math.max(0, S.files.offset - 200);
          await show("files");
          break;
        case "files-refresh":
          await show("files");
          break;
        case "file-select-all":
        case "file-select-none":
          for (const box of root.querySelectorAll("[name=ra-selected]"))
            if (!box.disabled && !box.closest("tr").hidden)
              box.checked = action === "file-select-all";
          break;
        case "mkdir":
          dialog(
            "创建远程目录",
            input("目录名称", "name"),
            "创建",
            async (f) => {
              await api("/sftp/directories", "POST", {
                accountId: S.files.account,
                path: join(S.files.path, f.get("name")),
              });
              await show("files");
            },
          );
          break;
        case "rename-file":
          const file = S.files.list[Number(id)];
          dialog(
            "重命名远程文件 / 目录",
            input("新名称", "name", file.name),
            "重命名",
            async (f) => {
              await api("/sftp/rename", "POST", {
                accountId: S.files.account,
                path: join(S.files.path, file.name),
                destination: join(S.files.path, f.get("name")),
              });
              await show("files");
            },
          );
          break;
        case "delete-file":
          const item = S.files.list[Number(id)];
          if (
            confirm(
              "永久删除 " +
                item.name +
                (item.directory ? " 及其所有内容" : "") +
                "？",
            )
          ) {
            await api("/sftp/delete", "POST", {
              accountId: S.files.account,
              path: join(S.files.path, item.name),
              recursive: item.directory,
              confirm: true,
            });
            await show("files");
          }
          break;
        case "upload-files":
          await pickFiles();
          break;
        case "upload-folder":
          await pickFiles(true);
          break;
        case "download":
          await download(
            [...root.querySelectorAll("[name=ra-selected]:checked")].map((x) =>
              Number(x.value),
            ),
          );
          break;
        case "download-file":
          await download([Number(id)], true);
          break;
        case "task":
          const task = await api("/transfers/" + id);
          dialog(
            "传输明细",
            table(
              ["路径", "状态", "已确认", "错误 / 操作"],
              task.items.map(
                (i) =>
                  `<tr><td>${esc(i.relative_path)}</td><td>${esc(i.state)}</td><td>${size(i.offset_bytes)} / ${size(i.size)}</td><td>${esc(i.error_code)}${task.direction === "upload" && !["completed", "skipped", "cancelled"].includes(i.state) ? button("取消条目", "cancel-item", id + "|" + i.id) : ""}</td></tr>`,
              ),
            ),
            "关闭",
            async () => {},
          );
          break;
        case "resume":
          await resume(id);
          break;
        case "cancel-item":
          const [taskId, itemId] = id.split("|");
          S.uploadControllers?.get(taskId)?.abort();
          await api("/transfers/" + taskId + "/control", "POST", {
            action: "cancel_item",
            itemId,
          });
          msg("该条目已取消；已提交文件不受影响");
          b.disabled = true;
          break;
        case "pause-task":
          S.uploadControllers?.get(id)?.abort();
          await api("/transfers/" + id + "/control", "POST", {
            action: "pause",
          });
          await show("transfers");
          break;
        case "retry-task":
          dialog(
            "选择失败条目的冲突策略",
            select(
              "策略",
              "conflict",
              [
                ["ask", "继续报冲突"],
                ["skip", "跳过同名"],
                ["rename", "自动重命名"],
                ["overwrite", "原子覆盖"],
              ],
              "rename",
            ) + check("明确确认允许覆盖", "confirm", false),
            "重试提交",
            async (f) => {
              await api("/transfers/" + id + "/control", "POST", {
                action: "retry",
                conflict: f.get("conflict"),
                confirm: f.has("confirm"),
              });
              const r = await api("/transfers/" + id + "/commit", "POST", {});
              msg(r.state);
              await show("transfers");
            },
          );
          break;
        case "hide-task":
          await api("/transfers/" + id + "/hide", "POST", {});
          await show("transfers");
          break;
        case "cancel-task":
          S.uploadControllers?.get(id)?.abort();
          await api("/transfers/" + id + "/cancel", "POST", {});
          await show("transfers");
          break;
        case "pair":
          await reauth();
          const pairing = await api(
            "/connectors/pairing-challenges",
            "POST",
            {},
          );
          dialog(
            "在自己的 Windows 连接器中输入此码",
            "<p>有效期 120 秒。仅在本人 Windows 电脑的连接器页面输入，不要发给其他人。</p><pre>" +
              esc(pairing.challenge) +
              "</pre>",
            "关闭",
            async () => {},
          );
          break;
        case "connector-revoke":
          if (confirm("撤销该设备及其未使用的启动授权？")) {
            await reauth();
            await api("/connectors/" + id + "/revoke", "POST", {});
            await show("connectors");
          }
          break;
        case "rdp":
          await rdp(id);
          break;
        case "session-terminate":
          if (confirm("立即终止此用户的 SSH 会话？")) {
            await api("/admin/sessions/" + id, "DELETE");
            await show("sessions");
          }
          break;
      }
    } catch (e) {
      if (epoch === S.renderEpoch && S.mounted) msg(e.message);
    } finally {
      if (b.isConnected) b.disabled = false;
    }
  }
  function leave() {
    window.InfraOnboarding?.leave();
    S.mounted = false;
    ++S.renderEpoch;
    ++S.viewEpoch;
    clearInterval(refreshTimer);
    for (const controller of S.uploadControllers?.values() || []) controller.abort();
    for (const controller of S.downloadControllers?.values() || []) controller.abort();
    for (const t of S.terms.values()) t.panel.remove();
    if (root) {
      root.onclick = null;
      root.classList.remove("ra");
      for (const d of root.querySelectorAll("dialog")) { d.close(); d.remove(); }
    }
  }
  window.addEventListener("beforeunload", (e) => {
    if ([...S.terms.values()].some((t) => t.lease && !t.stopped)) {
      e.preventDefault();
      e.returnValue = "";
    }
  });
  window.InfraRemote = { render, leave };
  if (document.getElementById("ra-root")) render();
})();
