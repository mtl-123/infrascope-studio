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
    const r = await fetch(
      (gateway ? "/gateways/" + encodeURIComponent(gateway) : "") + base + url,
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
    if ((v.gatewayId || gateway) && v.id) {
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
    return `<label>${label}<input name="${name}" type="${type}" value="${esc(value)}" ${type === "password" ? 'autocomplete="new-password"' : ""}></label>`;
  }
  function select(label, name, options, value) {
    return `<label>${label}<select name="${name}">${options.map(([k, v]) => `<option value="${esc(k)}" ${k === value ? "selected" : ""}>${esc(v)}</option>`).join("")}</select></label>`;
  }
  function check(label, name, value) {
    return `<label><input type="checkbox" name="${name}" ${value ? "checked" : ""}> ${label}</label>`;
  }
  function dialog(title, body, submit, action) {
    const d = document.createElement("dialog");
    d.innerHTML = `<h3>${esc(title)}</h3><form>${body}<p class="ra-error" role="alert"></p><div class="ra-bar"><button class="primary" type="submit">${esc(submit)}</button><button type="button" data-close>取消</button></div></form>`;
    root.append(d);
    d.querySelector("[data-close]").onclick = () => d.close();
    d.onclose = () => d.remove();
    d.querySelector("form").onsubmit = async (e) => {
      e.preventDefault();
      const b = d.querySelector("[type=submit]");
      b.disabled = true;
      try {
        await action(new FormData(e.target), e.target, d);
        d.close();
      } catch (e) {
        d.querySelector(".ra-error").textContent = e.message;
      } finally {
        b.disabled = false;
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
  async function render() {
    root =
      document.getElementById("io-content") ||
      document.getElementById("ra-root");
    root.classList.add("ra");
    root.innerHTML =
      '<div class="page-heading"><div><small>INFRASTRUCTURE / REMOTE ACCESS</small><h2>远程接入工作台</h2><p>账号级授权 · LinuxTab · SFTP · 用户电脑 RDP</p></div></div><div id="ra-message" role="status" aria-live="polite"></div><div id="ra-body"></div>';
    root.onclick = click;
    view = root.querySelector("#ra-body");
    S.mounted = true;
    try {
      S.user = await api("/auth/me");
      S.csrf = S.user.csrf;
      if (S.user.mustChangePassword) {
        passwordDialog();
        view.innerHTML = card("请先更改初始密码。");
        return;
      }
      shell();
      const session = new URLSearchParams(location.search).get("sessionId");
      if (session && !S.terms.has(session)) {
        const data = await api("/ssh/sessions/" + encodeURIComponent(session));
        await addTerminal(data.id, "接续会话", true);
        S.tab = "terminal";
      }
      await show(S.tab);
    } catch (e) {
      if (e.status === 401) login();
      else
        view.innerHTML = card(
          "<h3>远程网关尚不可用</h3><p>" +
            esc(e.message) +
            "</p><p>本模块需要启用同一项目中的 Go 服务与 PostgreSQL。现有监控演示数据不会被自动导入为远程连接目标。</p>" +
            button("重新检查", "reload"),
        );
    }
    clearInterval(refreshTimer);
    refreshTimer = setInterval(() => {
      if (S.mounted && ["transfers", "connectors"].includes(S.tab))
        show(S.tab).catch((e) => msg(e.message));
    }, 5000);
  }
  function shell() {
    const tabs = [
      ["access", "我的接入"],
      ["terminal", "LinuxTab"],
      ["files", "SFTP 文件"],
      ["transfers", "传输任务"],
      ["assets", "资产与账号"],
      ["connectors", "我的 Windows 设备"],
    ];
    if (["admin", "asset_manager"].includes(S.user.role))
      tabs.push(["grants", "账号分配"]);
    if (S.user.role === "admin")
      tabs.push(
        ["users", "平台用户"],
        ["groups", "用户组"],
        ["sessions", "会话管理"],
      );
    if (["admin", "auditor"].includes(S.user.role))
      tabs.push(["audit", "审计"], ["health", "网关状态"]);
    view.innerHTML = `<div class="ra-bar"><strong>${esc(S.user.displayName)}</strong><small>${esc(S.user.role)} · ${esc(S.user.gatewayId)}</small>${button("修改密码", "password")}${button("退出", "logout")}</div><div class="ra-tabs">${tabs.map(([k, v]) => button(v, "tab", k)).join("")}</div><div id="ra-view"></div>`;
  }
  function login() {
    view.innerHTML = card(
      '<form id="ra-login" class="ra-login"><small>REMOTE ACCESS</small><h3>登录远程接入平台</h3>' +
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
    dialog(
      "修改平台密码",
      input("当前密码", "currentPassword", "", "password") +
        input("新密码（至少 12 字节）", "newPassword", "", "password"),
      "更新并重新登录",
      async (f) => {
        await api("/auth/password", "POST", Object.fromEntries(f));
        S.user = null;
        for (const t of S.terms.values()) t.ws?.close();
        S.terms.clear();
        login();
      },
    );
  }
  async function show(tab) {
    if (!S.user) return;
    if (tab === "files" && S.tab === "terminal" && S.fileEmbedded) {
      await filesView(root.querySelector("#ra-terminal-files"));
      return;
    }
    S.tab = tab;
    const target = root.querySelector("#ra-view");
    if (!target) return;
    for (const t of S.terms.values()) t.panel.remove();
    for (const b of root.querySelectorAll("[data-ra=tab]"))
      b.classList.toggle("selected", b.dataset.id === tab);
    target.innerHTML = '<p class="muted">正在读取服务器记录…</p>';
    if (tab === "terminal") {
      terminalView(target);
      return;
    }
    if (tab === "access") {
      S.access = await api("/my/access");
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
          "尚无有效的账号授权。管理员也需要获得明确的远程账号使用授权。",
        );
      return;
    }
    if (tab === "assets") {
      S.assets = await api(
        "/assets?offset=" +
          S.assetOffset +
          "&q=" +
          encodeURIComponent(S.assetQuery),
      );
      target.innerHTML =
        '<form id="ra-asset-search"><label>搜索全部有权访问的资产<input name="query" maxlength="200" value="' +
        esc(S.assetQuery) +
        '" placeholder="名称 / linux / virtual / 标签 / 分组"></label><button type="submit">搜索</button></form>' +
        `<div class="ra-bar">${can("asset.manage") ? button("＋ 添加资产", "asset-new") : ""}</div>` +
        card(
          table(
            ["资产 / 分组", "系统 / 类型", "协议端点", "操作"],
            S.assets.map(
              (a) =>
                `<tr><td><strong>${esc(a.name)}</strong><small>${esc(a.group_name)}</small></td><td>${esc(a.os_family)} · ${esc(a.kind)}<small>${a.archived ? "已归档" : a.enabled ? "已启用" : "停用"}</small></td><td>${a.endpoints.map((e) => `<div><code>${esc(e.protocol)} ${esc(e.host)}:${e.port}</code></div>`).join("")}</td><td>${button("账号", "accounts", a.id)}${can("asset.manage") ? button("编辑", "asset-edit", a.id) + button("主机指纹", "hostkey", a.id) + button("测试端点", "asset-test", a.id) : ""}</td></tr>`,
            ),
          ),
        ) +
        `<div class="ra-bar">${button("上一页", "assets-prev", "", S.assetOffset ? "" : "disabled")}<span>第 ${Math.floor(S.assetOffset / 100) + 1} 页 · 本页 ${S.assets.length} 项</span>${button("下一页", "assets-next", "", S.assets.length === 100 ? "" : "disabled")}</div>`;
      target.querySelector("#ra-asset-search").onsubmit = async (event) => {
        event.preventDefault();
        S.assetQuery = new FormData(event.target).get("query").trim();
        S.assetOffset = 0;
        try {
          await show("assets");
        } catch (e) {
          msg(e.message);
        }
      };
      return;
    }
    if (tab === "files") {
      await filesView(target);
      return;
    }
    if (tab === "transfers") {
      const list = await api("/transfers");
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
      target.innerHTML =
        card(
          "<h3>每位用户自己的 Windows 连接器</h3><p>在你的 Windows 电脑运行本项目 windows-connector，配置批准的平台 HTTPS 地址。每次新的浏览器登录需要重新配对，以绑定当前会话。</p>" +
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
    allowed = (a, p) => a.grants.some((g) => g.actions.includes(p));
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
    if (!S.access.length) S.access = await api("/my/access");
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
          await startUpload(all);
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
    if (folder) {
      if (!window.showDirectoryPicker)
        throw Error(
          "当前浏览器不支持保留空目录的目录选择器。请拖放文件夹，或使用支持 File System Access 的桌面浏览器。",
        );
      const h = await showDirectoryPicker({ mode: "read" }),
        all = [];
      msg("正在扫描目录，尚未上传…");
      await walkHandle(h, "", all);
      await startUpload(all);
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
  async function startUpload(all) {
    if (!all.length) throw Error("未选择文件");
    const conflict = root.querySelector("#ra-conflict")?.value || "ask";
    if (
      conflict === "overwrite" &&
      !confirm("覆盖策略会在上传和校验完成后原子替换同名文件，是否确认？")
    )
      return;
    const f = { ...S.files };
    const task = await api("/transfers", "POST", {
      accountId: f.account,
      direction: "upload",
      target: f.path,
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
      for (let start = 0; start < manifest.length; start += 500)
        await api("/transfers/" + task.id + "/items", "POST", {
          items: manifest.slice(start, start + 500),
          final: start + 500 >= manifest.length,
        });
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
    const task = await api("/transfers/" + id),
      controller = new AbortController();
    S.uploadControllers ??= new Map();
    S.uploadControllers.set(id, controller);
    try {
      for (const item of task.items) {
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
          verified += chunk.size;
        }
        if (verified !== offset)
          throw Error("服务端续传分块记录不完整：" + item.relative_path);
        do {
          const blob = local.file.slice(offset, offset + 4 * 1024 * 1024);
          const res = await api(
            url,
            "PUT",
            blob,
            {
              "Upload-Offset": String(offset),
              "Upload-SHA256": await hash(blob),
            },
            controller.signal,
          );
          offset = res.offset;
          msg(
            `上传 ${item.relative_path}：已确认 ${size(offset)} / ${size(item.size)}`,
          );
          if (item.size === 0) break;
        } while (offset < item.size);
      }
      const result = await api("/transfers/" + id + "/commit", "POST", {});
      msg("任务 " + id + "：" + result.state);
      if (S.tab === "transfers") await show("transfers");
    } finally {
      S.uploadControllers.delete(id);
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
    const f = S.files,
      paths = indices.map((i) => f.list[i].name);
    if (!paths.length) throw Error("请选择文件或目录");
    let handle = null;
    if (window.showSaveFilePicker)
      handle = await showSaveFilePicker({
        suggestedName: single ? paths[0] : "infrascope-files.zip",
      });
    const t = await api("/transfers", "POST", {
      accountId: f.account,
      direction: "download",
      target: f.path,
      conflict: "ask",
      paths,
      confirmOverwrite: false,
    });
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
    let writer;
    try {
      writer = await handle.createWritable();
      const r = await fetch(url, { credentials: "same-origin" });
      if (!r.ok) {
        const v = await r.json();
        throw Error(v.error);
      }
      const reader = r.body.getReader();
      let done = 0;
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        await writer.write(part.value);
        done += part.value.length;
        msg("本地写入中：" + size(done));
      }
      const state = await api("/transfers/" + t.id);
      if (state.state !== "completed")
        throw Error("网关传输未完整完成：" + state.state);
      await writer.close();
      writer = null;
      msg("文件已完成写入，请核对远端文件内容。");
    } catch (e) {
      await writer?.abort();
      msg("下载未完成：" + e.message);
    }
    await show("transfers");
  }
  function assetEditor(a) {
    const value = a
      ? {
          name: a.name,
          kind: a.kind,
          osFamily: a.os_family,
          groupName: a.group_name,
          tags: a.tags,
          description: a.description,
          metadata: a.metadata,
          enabled: a.enabled,
          archived: a.archived,
          inventoryId: a.inventory_id || "",
          endpoints: a.endpoints.map(({ protocol, host, port, gatewayId }) => ({
            protocol,
            host,
            port,
            gatewayId,
          })),
        }
      : {
          name: "",
          kind: "physical",
          osFamily: "linux",
          groupName: "",
          tags: [],
          description: "",
          metadata: {},
          enabled: true,
          archived: false,
          inventoryId: "",
          endpoints: [
            {
              protocol: "ssh",
              host: "",
              port: 22,
              gatewayId: S.user.gatewayId,
            },
            {
              protocol: "sftp",
              host: "",
              port: 22,
              gatewayId: S.user.gatewayId,
            },
          ],
        };
    jsonEditor(
      a ? "编辑资产" : "添加资产（请填写真实授权端点）",
      value,
      a ? "/assets/" + a.id : "/assets",
      a ? "PATCH" : "POST",
    );
  }
  async function accounts(assetId) {
    const rows = await api("/assets/" + assetId + "/accounts");
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
  function accountEditor(x, asset) {
    jsonEditor(
      x ? "编辑远程账号" : "添加远程账号",
      x
        ? {
            name: x.name,
            username: x.username,
            authType: x.auth_type,
            protocols: x.protocols,
            enabled: x.enabled,
            archived: x.archived,
          }
        : {
            name: "",
            username: "",
            authType: "password",
            protocols: ["ssh", "sftp"],
            enabled: true,
            archived: false,
          },
      x ? "/accounts/" + x.id : "/assets/" + asset + "/accounts",
      x ? "PATCH" : "POST",
    );
  }
  async function credential(id) {
    await reauth();
    const x = await api("/accounts/" + id);
    dialog(
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
        await api("/accounts/" + id + "/credential", "POST", {
          action: f.get("action"),
          secret: {
            password: f.get("password") || "",
            privateKey: f.get("privateKey") || "",
            passphrase: f.get("passphrase") || "",
          },
        });
        form.reset();
        msg("凭据版本已更新");
      },
    );
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
  async function rdp(accountId) {
    const a = S.access.find((x) => x.account_id === accountId),
      devices = await api("/my/connectors");
    const valid = devices.flatMap((d) =>
      (d.browser_bindings || [])
        .filter(
          (b) => !d.revoked && Date.now() - Date.parse(d.last_seen) < 20000,
        )
        .map((b) => [d.id + "|" + b.id, d.name]),
    );
    if (!valid.length)
      throw Error(
        "当前浏览器没有在线且有效绑定的 Windows 连接器。请到“我的 Windows 设备”配对。",
      );
    dialog(
      "在自己的 Windows 电脑打开 RDP",
      `<p>${esc(a.asset_name)} / ${esc(a.account_name)} · 目标与凭据由后端授权确定。</p>` +
        select("你的电脑", "device", valid, valid[0][0]) +
        '<div class="ra-checks">' +
        check(
          "剪贴板（需授权）",
          "redirectClipboard",
          allowed(a, "rdp.clipboard"),
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
        const [connectorId, browserBindingId] = f.get("device").split("|");
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
        const t = await api("/rdp/launches", "POST", {
          assetId: a.asset_id,
          accountId,
          connectorId,
          browserBindingId,
          options,
          idempotencyKey: uid(),
        });
        msg("任务 " + t.id + " 已排队，请在你的连接器页面确认");
        await show("connectors");
      },
    );
  }
  async function click(event) {
    const b = event.target.closest("[data-ra]");
    if (!b) return;
    event.preventDefault();
    const action = b.dataset.ra,
      id = b.dataset.id,
      t = S.terms.get(id);
    try {
      switch (action) {
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
          await api("/auth/logout", "POST", {});
          for (const t of S.terms.values()) {
            t.stopped = true;
            t.ws?.close();
            clearInterval(t.heartbeat);
            t.term.dispose();
          }
          S.terms.clear();
          S.access = [];
          S.user = null;
          login();
          break;
        case "asset-new":
          assetEditor();
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
          assetEditor(S.assets.find((x) => x.id === id));
          break;
        case "accounts":
          await accounts(id);
          break;
        case "account-new":
          accountEditor(null, id);
          break;
        case "account-edit":
          accountEditor(S.accountRows.find((x) => x.id === id));
          break;
        case "credential":
          await credential(id);
          break;
        case "asset-test":
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
      msg(e.message);
    } finally {
      if (b.isConnected) b.disabled = false;
    }
  }
  function leave() {
    S.mounted = false;
    clearInterval(refreshTimer);
    for (const t of S.terms.values()) t.panel.remove();
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
