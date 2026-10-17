const $ = (id) => document.getElementById(id),
  key = "rdp-access-profile-v1",
  fields = {
    address: "rdpAddress",
    port: "rdpPort",
    username: "rdpUsername",
    redirectClipboard: "redirectClipboard",
    redirectDrives: "redirectDrives",
    driveMode: "driveMode",
    driveList: "driveList",
    fullscreen: "fullscreen",
    multiMonitor: "multiMonitor",
  };
let launcherAvailable = false,
  launcherToken = null,
  mode = "controlled",
  timer,
  checking = false;
function toast(s) {
  $("toast").textContent = s;
  clearTimeout(timer);
  timer = setTimeout(() => ($("toast").textContent = ""), 2800);
}
function state(type, message) {
  launcherAvailable = type === "ready";
  $("headerStatus").textContent = {
    checking: "正在检查本机连接器",
    ready: "本机连接器在线",
    warning: "需要首次初始化",
    error: "本机连接器不可用",
  }[type];
  $("launcherState").textContent =
    message ||
    {
      checking: "正在检测一键直连",
      ready: "一键直连已就绪",
      warning: "需要启用受信任 RDP 签名",
      error: "连接器检测失败",
    }[type];
  for (const id of ["statusDot", "connectorIndicator"])
    $(id).className = "dot " + type;
  $("setupSigningButton").hidden = type !== "warning";
  $("launchMstscButton").disabled = !launcherAvailable;
}
function save() {
  if (mode !== "standalone") return;
  const v = {};
  for (const [k, id] of Object.entries(fields))
    v[k] = $(id).type === "checkbox" ? $(id).checked : $(id).value;
  try {
    localStorage.setItem(key, JSON.stringify(v));
  } catch {}
}
function restore() {
  try {
    const v = JSON.parse(localStorage.getItem(key));
    if (!v || typeof v !== "object") return;
    for (const k of ["address", "username"])
      if (typeof v[k] === "string") $(fields[k]).value = v[k];
    $("rdpPort").value = v.port || "3389";
    $("driveList").value = v.driveList || "C:\\;D:\\";
    $("driveMode").value = v.driveMode === "custom" ? "custom" : "all";
    for (const k of ["redirectClipboard", "redirectDrives", "fullscreen"])
      $(k).checked = v[k] !== false;
    $("multiMonitor").checked = !!v.multiMonitor;
  } catch {
    try {
      localStorage.removeItem(key);
    } catch {}
  }
}
function summary() {
  const host = $("rdpAddress").value.trim(),
    port = $("rdpPort").value || "3389";
  $("rdpTargetSummary").textContent = host
    ? `${host.includes(":") && !host.startsWith("[") ? "[" + host + "]" : host}:${port}`
    : "尚未选择目标";
}
function drives() {
  const off = !$("redirectDrives").checked;
  $("driveControls").classList.toggle("disabled", off);
  $("driveMode").disabled = off;
  $("driveList").disabled = off;
  $("driveListField").hidden = $("driveMode").value !== "custom";
}
function split() {
  const value = $("rdpAddress").value.trim(),
    match =
      value.match(/^([^:]+):(\d{1,5})$/) ||
      value.match(/^\[([^\]]+)\]:(\d{1,5})$/);
  if (match) {
    $("rdpAddress").value = match[1];
    $("rdpPort").value = match[2];
  }
  summary();
  save();
}
async function request(url, body) {
  const r = await fetch(url, {
    method: body === undefined ? "GET" : "POST",
    cache: "no-store",
    headers: {
      "X-Pulse-Token": launcherToken || "",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let v;
  try {
    v = await r.json();
  } catch {
    throw Error(`本机连接器返回了无效响应（HTTP ${r.status}）`);
  }
  if (!r.ok) throw Error(v.error || `请求失败（HTTP ${r.status}）`);
  return v;
}
async function check() {
  state("checking");
  try {
    const t = await request("/api/local-token");
    mode = t.mode || "controlled";
    $("rdpForm").hidden = mode !== "standalone";
    $("controlledPanel").hidden = mode !== "controlled";
    if (mode === "standalone") {
      restore();
      drives();
      summary();
    }
    if (!t.available || !t.token)
      throw Error("当前环境没有可用的 Windows mstsc 连接器");
    launcherToken = t.token;
    const s = await request("/api/rdp/signing-status");
    state(s.configured ? "ready" : "warning");
    await refresh();
  } catch (e) {
    launcherToken = null;
    state("error", e.message);
  }
}
$("showPassword").onclick = () => {
  const shown = $("rdpPassword").type === "password";
  $("rdpPassword").type = shown ? "text" : "password";
  $("showPassword").textContent = shown ? "隐藏" : "显示";
  $("showPassword").setAttribute("aria-pressed", String(shown));
};
for (const [k, id] of Object.entries(fields)) {
  $(id).addEventListener("input", () => {
    $("rdpValidation").textContent = "";
    if (k === "address" || k === "port") summary();
    if (["address", "port", "username"].includes(k)) save();
  });
  $(id).addEventListener("change", () => {
    drives();
    save();
  });
}
$("rdpPassword").oninput = () => ($("rdpValidation").textContent = "");
$("rdpAddress").onblur = split;
$("rdpAddress").onpaste = () => requestAnimationFrame(split);
$("setupSigningButton").onclick = async () => {
  if (
    !confirm(
      "将创建当前用户 RDP 签名证书、安装公钥信任，并通过 UAC 请求写入机器发布者策略。是否继续？",
    )
  )
    return;
  const b = $("setupSigningButton");
  b.disabled = true;
  try {
    await request("/api/rdp/setup-signing", {});
    toast("签名配置完成");
    await check();
  } catch (e) {
    state("warning", e.message);
    toast("初始化未完成，请检查 UAC 及策略状态");
  } finally {
    b.disabled = false;
  }
};
$("rdpForm").onsubmit = async (e) => {
  e.preventDefault();
  if (!launcherAvailable) return;
  const c = {};
  for (const [k, id] of Object.entries(fields))
    c[k] = $(id).type === "checkbox" ? $(id).checked : $(id).value;
  c.address = c.address.trim();
  c.username = c.username.trim();
  c.port = Number(c.port);
  c.password = $("rdpPassword").value;
  try {
    if (!c.address || /\s/.test(c.address))
      throw Error("请输入有效的 IP 地址或主机名");
    if (!Number.isInteger(c.port) || c.port < 1 || c.port > 65535)
      throw Error("端口必须在 1 到 65535 之间");
    if (/[\r\n]/.test(c.username)) throw Error("用户名格式无效");
    if (c.password && !c.username) throw Error("填写密码时必须同时填写用户名");
    if (c.redirectDrives && c.driveMode === "custom") {
      const ds = c.driveList
        .split(/[,;]/)
        .map((v) => v.trim())
        .filter(Boolean);
      if (!ds.length) throw Error("请至少填写一个本地盘符，例如 C:\\");
      for (const d of ds)
        if (!/^[A-Za-z]:\\?$/.test(d)) throw Error("盘符格式无效：" + d);
    }
    save();
    $("launchMstscButton").disabled = true;
    $("launchMstscButton").textContent = "正在启动…";
    const r = await request("/api/rdp/connect", c);
    toast(`mstsc 已启动，进程 ${r.pid}；请在远程桌面窗口完成连接`);
  } catch (e) {
    $("rdpValidation").textContent = e.message;
  } finally {
    $("launchMstscButton").disabled = !launcherAvailable;
    $("launchMstscButton").textContent = "连接远程桌面";
    c.password = "";
  }
};
$("pairForm").onsubmit = async (e) => {
  e.preventDefault();
  try {
    await request("/api/pair", {
      challenge: $("pairChallenge").value.trim(),
      name: $("pairName").value.trim(),
    });
    $("pairChallenge").value = "";
    toast("此 Windows 用户已配对");
    await refresh();
  } catch (e) {
    toast(e.message);
  }
};
async function refresh() {
  if (!launcherToken || mode !== "controlled" || checking) return;
  checking = true;
  try {
    const s = await request("/api/status");
    $("pairedState").textContent =
      s.error ||
      `${s.platform || "尚未配置批准的平台地址"} · ${s.device?.name || "未配对"}`;
    const box = $("pendingTasks");
    box.replaceChildren();
    for (const t of s.pending) {
      const el = document.createElement("div");
      el.className = "task";
      const title = document.createElement("strong");
      title.textContent = `${t.asset_name || t.asset_id} · ${t.account_name || t.account_id}`;
      el.append(title);
      const detail = document.createElement("p");
      detail.textContent = `目标 ${t.host}:${t.port} / ${t.username}；到期 ${new Date(t.expires_at).toLocaleTimeString()}；剪贴板：${t.options?.redirectClipboard ? "允许" : "禁用"}；磁盘：${t.options?.redirectDrives ? "允许" : "禁用"}`;
      el.append(detail);
      const b = document.createElement("button");
      b.textContent = "确认在此电脑启动";
      b.disabled = !launcherAvailable;
      b.onclick = async () => {
        b.disabled = true;
        try {
          const r = await request("/api/rdp/connect", {
            launchId: t.id,
            confirmed: true,
          });
          toast(`mstsc 已启动，进程 ${r.pid}`);
          await refresh();
        } catch (e) {
          toast(e.message);
          b.disabled = false;
        }
      };
      el.append(b);
      box.append(el);
    }
    if (!s.pending.length) box.textContent = "暂无待确认的授权任务。";
    $("recentTasks").textContent = s.launches
      .map(
        (x) =>
          `${x.id.slice(0, 8)} · ${x.state} · ${x.cleanup || "清理状态等待反馈"}`,
      )
      .join("\n");
  } catch (e) {
    $("pairedState").textContent = e.message;
  } finally {
    checking = false;
  }
}
drives();
summary();
check();
setInterval(refresh, 3000);
