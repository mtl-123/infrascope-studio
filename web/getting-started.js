/* InfraScope guided Linux enrollment. Uses the existing authenticated asset APIs. */
(function (global) {
  'use strict';
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const archive = 'infrascope-telemetry-0.1.0-linux-x86_64-gnu.tar.gz';
  const directory = archive.replace(/\.tar\.gz$/, '');
  const quote = value => "'" + String(value).replace(/'/g, "'\\''") + "'";
  const loopback = host => /^(localhost|127(?:\.\d{1,3}){3}|\[?::1\]?)$/i.test(host);
  function connection(origin, mode) {
    const url = new URL(origin);
    if (url.protocol !== 'https:') return '客户端需要 HTTPS。请使用平台的 HTTPS 入口重新打开引导。';
    if (mode === 'remote' && loopback(url.hostname)) return '当前使用本机地址，其他 Linux 服务器无法连接。请先配置可路由的 HTTPS 平台域名、监听地址和匹配证书，再从该域名打开此引导。不要在远端填写 127.0.0.1。';
    return '';
  }
  function config(origin, ca) {
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password) throw Error('平台地址必须是 HTTPS origin');
    return `server_url = ${JSON.stringify(origin)}\nstate_dir = "./host-state"\n${ca ? 'ca_cert = "./server-ca.pem"\n' : ''}allow_insecure_loopback = false\ninterval_seconds = 5\nrequest_timeout_seconds = 15\nmax_queue_bytes = 67108864\nmax_queue_files = 10000\n`;
  }
  function installCommands(origin, ca, sha256) {
    const base = quote(origin + '/downloads/' + archive);
    return `# 将下载的压缩包${ca ? '和 server-ca.pem' : ''}复制到 Linux 同一目录，再执行\n${sha256 ? `printf '%s  %s\\n' ${quote(sha256)} ${quote(archive)} | sha256sum -c -\n` : ''}tar -xzf ${archive}\n${ca ? `cp server-ca.pem ${directory}/server-ca.pem\n` : ''}cd ${directory}\nchmod +x ./infrascope-agent\ncat > host.toml <<'INFRASCOPE_CONFIG'\n${config(origin, ca)}INFRASCOPE_CONFIG\n./infrascope-agent sample --config ./host.toml\n\n# 公共受信 HTTPS 也可以用 curl 下载；自签名环境请先传入可信证书\n# 下载地址：${base}`;
  }
  const enrollCommands = `read -rsp '粘贴网页注册令牌: ' INFRASCOPE_ENROLLMENT_TOKEN; echo\nexport INFRASCOPE_ENROLLMENT_TOKEN\n./infrascope-agent enroll --config ./host.toml\nresult=$?\nunset INFRASCOPE_ENROLLMENT_TOKEN\nif [ "$result" -eq 0 ]; then\n  # 上报成功后持续运行（Ctrl+C 停止）\n  ./infrascope-agent once --config ./host.toml &&\n    ./infrascope-agent run --config ./host.toml\nelse\n  printf '%s\\n' '注册失败，请检查终端错误后重试。' >&2\nfi`;
  function evaluate(result, agentId, since, now = Date.now()) {
    const agents = result.agents.filter(a => a.kind === 'host' && a.os?.toLowerCase() === 'linux');
    const agent = agents.find(a => a.id === agentId);
    if (!agent) return { state: 'waiting', text: '等待 Linux 客户端注册；注册后请选择本次客户端。' };
    if (agent.revoked || !agent.enabled) return { state: 'blocked', text: '客户端已撤销或暂停，请在 Agent 策略核对配置。' };
    const sample = result.samples.find(s => s.agentId === agent.id && s.kind === 'host' && Date.parse(s.receivedAt) >= since);
    if (!sample) return { state: 'registered', text: '客户端已注册，尚未收到本次检查开始后的样本。请执行 once 或 run。' };
    const age = now - Date.parse(sample.observedAt), receivedAge = now - Date.parse(sample.receivedAt);
    if (!Number.isFinite(age) || !Number.isFinite(receivedAge) || age < -60000 || age > Math.max(30, agent.intervalSeconds * 3) * 1000 || receivedAge < -60000)
      return { state: 'stale', text: '已入库，但样本过期或时钟异常。请检查系统时间与采集进程。', sample, agent };
    if (sample.health?.status !== 'ok') return { state: 'partial', text: '样本已入库，但采集健康状态不是 ok，请查看指标详情中的错误。', sample, agent };
    return { state: 'ready', text: '已收到这台 Linux 客户端的新鲜样本，采集状态为 ok。', sample, agent };
  }
  const panel = (title, body) => `<section class="box guide-card"><h3>${title}</h3>${body}</section>`;
  const button = (label, action, extra = '') => `<button type="button" data-guide="${action}" ${extra}>${label}</button>`;
  const code = (text, id) => `<div class="guide-code"><pre id="${id}"><code>${esc(text)}</code></pre>${button('复制命令', 'copy', `data-copy="${id}"`)}</div>`;
  const field = (label, name, value = '') => `<label>${label}<input name="${name}" value="${esc(value)}"></label>`;
  let active = null;
  function leave() { active?.dispose(); active = null; }
  function renderHelp(target) {
    leave();
    target.classList.remove('ra'); target.onclick = null;
    target.innerHTML = `<div class="page-heading"><div><small>GETTING STARTED</small><h2>帮助与使用手册</h2><p>从第一台主机开始，按任务找到下一步。</p></div></div>
      <section class="box guide-hero"><span class="guide-kicker">推荐从这里开始 · LINUX</span><h3>接入第一台 Linux 主机</h3><p>登记主机与责任人 → 检查平台地址 → 下载并注册 → 等待真实指标。无需先配置 SSH 或远程账号。</p><button class="primary" data-page="getting-started">开始逐步接入</button><small>支持 x86_64 GNU / glibc ≥ 2.34。当前不支持 ARM64 和 Alpine。</small></section>
      <label class="guide-search">查找教程<input type="search" id="guide-help-search" placeholder="例如：令牌、Linux、密码、Docker"></label>
      <div class="guide-help-grid">
      ${panel('第一次使用', `<details open><summary>平台登录与主机账号有什么区别？</summary><p>平台账号用于管理资产和采集。Linux 系统账号用于 SSH/SFTP。安装主机 Agent 不需要配置 SSH 密码，也不需要“我的接入”授权。</p><p>本地管理员账号由部署者提供。当前开发环境的随机凭据保存在服务器仓库 .local-dev/admin.json，请向部署者获取，页面不会公开密码。</p></details><details><summary>先添加人员还是资产？</summary><p>逐步接入允许同页新增责任联系人和 Linux 资产。也可在“组织与人员”添加联系人，再到“设备与使用人”添加资产。人员联系人不等于可登录的平台用户。</p><button data-page="directory">组织与人员</button><button data-page="devices">设备与使用人</button></details>`) }
      ${panel('Linux Agent', `<details open><summary>从哪里生成注册令牌？</summary><p>使用“逐步接入”，或打开“Agent 策略”，在对应资产点击“注册客户端”，类型选 host。令牌有效期 10 分钟，仅交给目标机器。每台机器使用独立身份和状态目录。</p><button data-page="getting-started">逐步接入 Linux</button><button data-page="agents">Agent 策略</button></details><details><summary>注册后如何启动和查看数据？</summary>${code('./infrascope-agent once --config ./host.toml\n./infrascope-agent run --config ./host.toml', 'help-linux-run')}<p>在“Agent 策略”点击“查看指标与 Agent”。run 为前台运行，Ctrl+C 停止，退出终端会结束；开机自启需按发布包 deploy/DEPLOYMENT.md 单独配置并验证。</p></details><details><summary>首次没有网卡速率正常吗？</summary><p>首次采样缺少差分基线，速率为空。持续运行后才产生速率；无样本不显示为 0 或健康。</p></details>`) }
      ${panel('连接失败排查', `<details open><summary>远端 Linux 无法访问 127.0.0.1</summary><p>127.0.0.1 指向运行客户端的机器。当前本机开发入口不能供其他服务器使用。部署者需要配置 REMOTE_LISTEN、REMOTE_PUBLIC_ORIGIN、匹配域名的 HTTPS 证书和必要的网络来源，然后从可访问的域名打开引导。</p></details><details><summary>证书、令牌或上报失败</summary><p>证书错误：将可信公钥证书配置为 ca_cert，核对域名与有效期。不要关闭证书校验。令牌过期：重新生成；已注册的客户端保留原 state_dir，不用每次重新注册。上报失败：检查资产是否启用、责任人是否有效、客户端是否撤销、Linux 系统时间是否正确。</p></details><details><summary>提示“尚无有效的账号授权”</summary><p>这是远程接入模块的提示。采集指标请到 Agent 策略；需要 SSH/SFTP/RDP 时，再按远程操作教程配置独立授权。</p></details>`) }
      ${panel('其他任务', `<details><summary>Docker 与 PVE 怎么接入？</summary><p>分别使用 infrascope-docker-collector 和 infrascope-pve-collector，生成对应 docker / pve 类型令牌。每种采集器使用独立 state_dir。Docker 需要受控 Engine API 访问；PVE 需要可信 HTTPS 与最小权限 API token。PVE 实机、Windows Docker HTTPS 仍待验收。发布包 docs/COLLECTORS.md 有配置说明。</p></details><details><summary>如何连接 SSH / SFTP / Windows RDP？</summary><p>在“设备与使用人”找到服务器，点击“连接 / 文件”，按面板补齐端点、远程系统账号、凭据和本人授权。SSH 首次独立核对指纹，SFTP 配置授权目录。RDP 还需要本人 Windows 连接器配对和本机确认。</p><button data-page="devices">打开设备列表</button></details><details><summary>Windows 采集客户端怎么用？</summary><p>使用 Windows x86_64 包，配置 host.toml，生成 host 令牌后依次执行 enroll、once、run。注册与后续运行必须使用同一 Windows 用户，身份由 DPAPI 保护。不能将状态目录直接交给 LocalSystem。</p></details><details><summary>哪些功能还没完成？</summary><p>主机采集、统一资产及远程控制面有真实接口；部分监控、日志、告警和 SRE 页面仍为演示。远程目标登录、自启、PVE 和生产容量需各自验收，不因页面能打开就表示完成。</p></details>`) }
      </div><p id="guide-help-empty" hidden>没有匹配教程，请换一个关键词。</p>`;
    target.querySelector('#guide-help-search').oninput = event => {
      const query = event.target.value.trim().toLowerCase(); let count = 0;
      for (const card of target.querySelectorAll('.guide-help-grid .guide-card')) {
        card.hidden = !card.textContent.toLowerCase().includes(query); if (!card.hidden) count++;
      }
      target.querySelector('#guide-help-empty').hidden = count > 0;
    };
    target.onclick = async event => {
      const b = event.target.closest('[data-guide="copy"]'); if (!b) return;
      try { await navigator.clipboard.writeText(target.querySelector('#' + b.dataset.copy).textContent); b.textContent = '已复制'; }
      catch { b.textContent = '复制失败，请选中命令复制'; }
    };
  }
  async function mount(target, ctx) {
    leave();
    if (!ctx.user.permissions?.includes('asset.manage')) { target.innerHTML = panel('需要资产管理权限', '<p>请让管理员为你开放资产管理权限或代为登记主机，再到 Agent 策略查看已授权数据。</p>'); return; }
    const state = { step: 1, asset: null, person: null, mode: 'remote', assets: [], people: [], manifest: null, token: null, checkedAt: 0, busy: false, stopped: false, selectedAgent: '', uncertain: false, contactName: '', name: '', kind: 'physical' };
    let timer;
    const downloadURLs = new Set();
    const current = () => !state.stopped && ctx.current();
    const dispose = () => { state.stopped = true; state.token = null; clearTimeout(timer); for (const url of downloadURLs) URL.revokeObjectURL(url); downloadURLs.clear(); target.onclick = target.onsubmit = target.onchange = null; const token = target.querySelector('[data-guide-token]'); if (token) token.textContent = ''; };
    active = { dispose };
    const error = text => { if (current()) target.querySelector('[data-guide-error]').textContent = text; };
    const stepTitles = ['登记 Linux 主机', '检查连接与下载', '注册并运行', '确认真实上报'];
    function paint() {
      if (!current()) return;
      clearTimeout(timer);
      target.innerHTML = `<div class="guide-wizard"><ol class="guide-steps" aria-label="接入进度">${stepTitles.map((title, i) => `<li ${i + 1 === state.step ? 'aria-current="step"' : ''}><span>${i + 1 < state.step ? '✓' : i + 1}</span>${title}</li>`).join('')}</ol><div class="guide-section" tabindex="-1"><h3>${state.step}. ${stepTitles[state.step - 1]}</h3><p class="ra-error" data-guide-error role="alert"></p><div data-guide-body></div></div></div>`;
      const body = target.querySelector('[data-guide-body]');
      if (state.step === 1) {
        const assets = state.assets.filter(a => a.os_family === 'linux' && a.enabled && !a.archived && a.canManage);
        body.innerHTML = `<p>只登记采集对象与责任人，保存后可继续获取客户端。已有主机请直接选择，避免重复登记。</p>
          <form id="guide-asset-form"><label>选择已有 Linux 资产<select name="existing"><option value="">新建一台 Linux 资产</option>${assets.map(a => `<option value="${esc(a.id)}" ${state.asset?.id === a.id ? 'selected' : ''}>${esc(a.name)} · ${esc(a.id)}</option>`).join('')}</select></label><div class="guide-new-fields"><div class="guide-fields">${field('资产名称', 'name', state.name)}<label>物理 / 虚拟类型<select name="kind"><option value="physical" ${state.kind === 'physical' ? 'selected' : ''}>物理设备</option><option value="virtual" ${state.kind === 'virtual' ? 'selected' : ''}>虚拟机</option></select></label></div>
          <label>责任人<select name="person"><option value="">${ctx.user.role === 'admin' ? '新增联系人（填写下方姓名）' : '请选择已有联系人'}</option>${state.people.map(p => `<option value="${esc(p.id)}" ${state.person?.id === p.id ? 'selected' : ''}>${esc(p.display_name)} · ${esc(p.department || '未填部门')}</option>`).join('')}</select></label>${ctx.user.role === 'admin' ? `<div class="guide-contact-field">${field('新联系人的真实姓名', 'contactName', state.contactName)}</div>` : '<p>联系人只能由管理员新增。</p>'}<p class="muted">新资产默认类别为服务器、系统为 Linux，启用并分配给所选责任人。不创建远程账号或网络授权。</p></div><label class="guide-confirm"><input type="checkbox" name="confirm" required>确认使用所选资产；新建时确认保存联系人及资产。若中途取消，已保存记录会保留。</label><button class="primary" type="submit">保存并继续</button></form><p class="muted">这里显示前 100 条可管理记录。找不到时可先在设备列表搜索或登记，再重新进入。</p><button data-page="devices">设备与使用人</button>`;
      }
      if (state.step === 1 && state.asset) {
        const select = body.querySelector('[name="existing"]');
        if (select) select.value = state.asset.id;
        body.querySelector('.guide-new-fields').hidden = true;
      }
      if (state.step === 2) {
        const manifest = state.manifest, ca = !!manifest?.ca;
        body.innerHTML = `<p>当前资产：<strong>${esc(state.asset.name)}</strong></p><p>平台 HTTPS 地址：<code>${esc(location.origin)}</code></p><label>客户端装在哪里？<select name="mode"><option value="remote" ${state.mode === 'remote' ? 'selected' : ''}>另一台 Linux 服务器</option><option value="local" ${state.mode === 'local' ? 'selected' : ''}>平台所在的同一个 Linux / WSL 环境</option></select></label><div data-guide-connection></div><div class="guide-downloads"><h4>Linux x86_64 GNU 下载</h4><p>请先在目标执行 <code>uname -m</code> 和 <code>ldd --version</code>。需要 x86_64 与 glibc ≥ 2.34；ARM64、Alpine 和旧版 CentOS 不适用。</p>${manifest?.linux ? `<a class="guide-link" href="/downloads/${archive}" download>下载 Linux 客户端 0.1.0</a><p class="guide-hash">SHA256：<code>${esc(manifest.sha256)}</code></p>` : '<p class="ra-warning">当前部署未提供下载包，请让部署者运行 npm run prepare:onboarding 后重试；不可用时不会提供空下载。</p>'}${ca ? '<a class="guide-link" href="/downloads/server-ca.pem" download>下载当前平台公钥证书</a><p>将证书与下载包一同传到目标 Linux。仅包含公钥，不包含服务端私钥。</p>' : '<p>客户端默认使用系统信任的 CA；若平台使用内部 CA，请向部署者取得可信证书，并在 host.toml 配置 ca_cert。</p>'}</div>${button("下载此主机的 host.toml", "config")}<p class="muted">配置只含平台地址、采集参数与状态目录，不包含注册令牌。</p><h4>在目标 Linux 检查 HTTPS</h4>${code(`curl --fail --show-error --connect-timeout 10 ${ca ? '--cacert ./server-ca.pem ' : ''}${quote(location.origin + '/')} -o /dev/null`, 'guide-curl')}<p>这条命令要在目标 Linux 执行。网页不能代替目标机器验证网络与 TLS；连接失败时先处理地址、证书或网络配置。</p><label class="guide-confirm"><input type="checkbox" name="reachable">我已在目标 Linux 验证以上 HTTPS 请求成功，且架构符合要求</label><div class="ra-bar">${button('返回资产', 'back')}${button('已验证，继续安装', 'connection-next', 'class="primary"')}</div>`;
        updateConnection();
      }
      if (state.step === 3) {
        const ca = !!state.manifest?.ca;
        body.innerHTML = `<p>资产：<strong>${esc(state.asset.name)}</strong> · 平台：<code>${esc(location.origin)}</code></p><h4>① 解压并生成主机配置</h4><p>使用独立目录；下列命令会写入当前包目录的 host.toml。已有配置时先备份。</p>${code(installCommands(location.origin, ca, state.manifest?.sha256), 'guide-install')}<h4>② 生成一次性注册令牌</h4><p>只在首次注册时使用；已注册的机器保留 host-state，直接运行即可。重新生成不会撤销前一个仍有效的令牌。</p>${button('生成 10 分钟注册令牌', 'token', 'class="primary"')}<div data-guide-token aria-live="polite"></div><h4>③ 在同一终端注册并上报</h4>${code(enrollCommands, 'guide-enroll')}<p>令牌在命令提示时输入，不写入命令参数或历史。run 保持前台采集，Ctrl+C 停止；首次网卡速率为空属正常。</p><div class="ra-bar">${button('返回连接检查（清除令牌显示）', 'back')}${button('我已运行，检查上报', 'check-next', 'class="primary"')}</div>`;
        renderToken();
      }
      if (state.step === 4) {
        body.innerHTML = `<p>当前资产：<strong>${esc(state.asset.name)}</strong>。只检查此资产的 Linux host 客户端与本次检查之后入库的样本。</p><label>确认本次客户端<select name="agent"><option value="">等待注册 / 请选择目标客户端</option></select></label><p>按 Linux 的 <code>hostname</code> 和客户端 <code>status --config ./host.toml</code> 输出核对身份；已有客户端不会自动判定为本次接入成功。</p><div data-guide-result role="status" aria-live="polite">正在读取真实数据…</div><div class="ra-bar">${button('立即刷新', 'refresh')}${button('查看真实指标与配置', 'details')}${button('返回命令', 'back')}</div><p class="muted">页面停留期间每 5 秒检查，离开后停止。收到一个正常样本只证明本次采集链路，不代表长期稳定或开机自启已完成。</p><details><summary>没有数据时怎么检查？</summary><p>检查 run 终端的错误；确认令牌有效、配置地址正确、证书受信任、系统时间同步、资产启用且责任人有效。注册成功但无样本时执行 once。完整错误与采集健康信息见“查看真实指标与配置”。</p></details>`;
        poll();
      }
    }
    function updateConnection() {
      const reason = connection(location.origin, state.mode);
      target.querySelector('[data-guide-connection]').innerHTML = reason ? `<p class="ra-warning">${esc(reason)}</p><button data-page="help">查看部署与排查说明</button>` : '<p>请下载文件并在目标主机验证 HTTPS。选择同一环境仅适用于平台所在 Linux；另一台机器不能使用此选项绕过本机地址限制。</p>';
      target.querySelector('[data-guide="connection-next"]').disabled = !!reason || !state.manifest?.linux;
    }
    function renderToken() {
      clearTimeout(timer);
      const tokenArea = target.querySelector('[data-guide-token]'); if (!tokenArea) return;
      const token = state.token;
      if (!token) { tokenArea.textContent = '尚未生成令牌；刷新或离开页面后不会恢复显示。'; return; }
      if (Date.parse(token.expiresAt) <= Date.now()) { state.token = null; tokenArea.textContent = '令牌已过期，请重新生成。'; return; }
      tokenArea.innerHTML = `<p>仅交给目标 Linux。有效期至 ${esc(new Date(token.expiresAt).toLocaleString())}</p><pre class="guide-token">${esc(token.token)}</pre><p>离开、返回或刷新会清除显示，不会撤销服务端令牌。</p>`;
      timer = setTimeout(renderToken, Math.min(1000, Math.max(1, Date.parse(token.expiresAt) - Date.now())));
    }
    async function poll() {
      if (!current() || state.step !== 4 || state.polling) return;
      state.polling = true;
      clearTimeout(timer);
      try {
        const result = await ctx.api('/api/v1/assets/' + encodeURIComponent(state.asset.id) + '/telemetry?limit=100');
        if (!current() || state.step !== 4) return;
        const select = target.querySelector('[name="agent"]');
        select.innerHTML = '<option value="">请选择本次 Linux 客户端</option>' + result.agents.filter(a => a.kind === 'host' && a.os?.toLowerCase() === 'linux').map(a => `<option value="${esc(a.id)}" ${state.selectedAgent === a.id ? 'selected' : ''}>${esc(a.hostname)} · ${esc(a.id)}${a.revoked ? '（已撤销）' : ''}</option>`).join('');
        const status = evaluate(result, state.selectedAgent, state.checkedAt);
        target.querySelector('[data-guide-result]').innerHTML = `<div class="guide-result ${status.state === 'ready' ? 'guide-ready' : ''}"><strong>${esc(status.text)}</strong>${status.sample ? `<p>Agent：${esc(status.agent.id)}<br>采样：${esc(status.sample.observedAt)}<br>入库：${esc(status.sample.receivedAt)}</p>` : ''}</div>`;
        error('');
      } catch (e) {
        if (current() && state.step === 4) { error('读取失败：' + e.message); target.querySelector('[data-guide-result]').textContent = '本次读取失败，当前无法确认采集状态。'; }
      } finally {
        state.polling = false;
        if (current() && state.step === 4) timer = setTimeout(() => { if (document.visibilityState !== 'hidden') poll(); else timer = setTimeout(poll, 5000); }, 5000);
      }
    }
    target.onchange = event => {
      if (!current()) return;
      if (event.target.name === 'mode') { state.mode = event.target.value; target.querySelector('[name="reachable"]').checked = false; updateConnection(); }
      if (event.target.name === 'existing') target.querySelector('.guide-new-fields').hidden = !!event.target.value;
      if (event.target.name === 'person') { state.person = state.people.find(p => p.id === event.target.value) || null; const f = target.querySelector('.guide-contact-field'); if (f) f.hidden = !!event.target.value; }
      if (event.target.name === 'agent') { state.selectedAgent = event.target.value; poll(); }
    };
    target.onsubmit = async event => {
      if (event.target.id !== 'guide-asset-form') return;
      event.preventDefault(); if (!current() || state.busy) return;
      const form = new FormData(event.target), submit = event.target.querySelector('[type="submit"]');
      state.name = String(form.get('name') || '').trim(); state.contactName = String(form.get('contactName') || '').trim(); state.kind = String(form.get('kind'));
      state.busy = true; submit.disabled = true;
      try {
        if (!form.has('confirm')) throw Error('请确认资产与责任信息后保存。');
        if (state.uncertain && !form.get('existing')) throw Error('上次保存响应未确认，请先到组织与人员及设备列表核对是否已创建，再重新进入选择已有记录。');
        const existing = String(form.get('existing') || '');
        if (existing) {
          const asset = await ctx.api('/api/v1/assets/' + encodeURIComponent(existing));
          if (!current()) return;
          if (asset.os_family !== 'linux' || !asset.enabled || asset.archived || !asset.canManage || asset.ownershipLegacy || !['assigned', 'pending'].includes(asset.ownership?.state)) throw Error('该资产需要启用、Linux 系统和有效责任信息，请先在设备列表补齐。');
          state.asset = asset;
        } else {
          if (!state.name || new TextEncoder().encode(state.name).length > 180) throw Error('请填写资产名称（最多 180 字节）。');
          const personId = String(form.get('person') || '');
          if (personId) state.person = state.people.find(p => p.id === personId);
          else if (!state.person) {
            if (ctx.user.role !== 'admin') throw Error('请选择有效责任人；新增联系人需要管理员。');
            if (!state.contactName || new TextEncoder().encode(state.contactName).length > 180) throw Error('请填写真实联系人姓名（最多 180 字节）。');
            let person;
            try { person = await ctx.api('/people', 'POST', { displayName: state.contactName, department: '', email: '', contactType: 'internal', enabled: true }); }
            catch (e) { if (!e.status || e.status >= 500) state.uncertain = true; throw e; }
            if (!current()) return;
            state.person = { id: person.id, display_name: state.contactName, enabled: true }; state.people.push(state.person);
          }
          if (!state.person?.enabled) throw Error('请选择有效且启用的责任联系人。');
          const category = 'server';
          let created;
          try { created = await ctx.api('/api/v1/assets', 'POST', { name: state.name, kind: state.kind, osFamily: 'linux', category, enabled: true, archived: false, endpoints: [], tags: [], ownership: { state: 'assigned', userId: state.person.id, notificationIds: [], backupIds: [] } }); }
          catch (e) { if (!e.status || e.status >= 500) state.uncertain = true; throw e; }
          if (!current()) return;
          state.asset = { id: created.id, name: state.name, os_family: 'linux', enabled: true, archived: false, canManage: true }; state.assets.unshift(state.asset);
        }
        state.uncertain = false; state.step = 2; paint(); target.querySelector('.guide-section').focus();
      } catch (e) { error(e.message + (state.person ? ' 已保存或选定的联系人会保留；不会重复创建。' : '')); }
      finally { state.busy = false; if (current() && submit.isConnected) submit.disabled = false; }
    };
    target.onclick = async event => {
      const b = event.target.closest('[data-guide]'); if (!b || b.disabled || !current() || state.busy) return;
      const action = b.dataset.guide; b.disabled = true;
      try {
        if (action === 'copy') { await navigator.clipboard.writeText(target.querySelector('#' + b.dataset.copy).textContent); if (current()) b.textContent = '已复制'; }
        if (action === 'config') {
          const url = URL.createObjectURL(new Blob([config(location.origin, !!state.manifest?.ca)], {type: 'text/plain;charset=utf-8'})); downloadURLs.add(url);
          const link = document.createElement('a'); link.href = url; link.download = 'host.toml'; link.click();
        }
        if (action === 'back') { state.token = null; state.step--; paint(); }
        if (action === 'connection-next') {
          const reason = connection(location.origin, state.mode); if (reason) throw Error(reason);
          if (!target.querySelector('[name="reachable"]').checked) throw Error('请先在目标 Linux 验证网络、TLS 与架构，然后勾选确认。');
          state.step = 3; paint();
        }
        if (action === 'token') {
          state.busy = true;
          const token = await ctx.api('/api/v1/agents/enrollments', 'POST', { assetId: state.asset.id, kind: 'host', expiresInSeconds: 600 });
          if (!current() || state.step !== 3) return;
          state.token = token; renderToken();
        }
        if (action === 'check-next') { state.token = null; state.checkedAt = Date.now(); state.step = 4; paint(); }
        if (action === 'refresh') await poll();
        if (action === 'details') await ctx.details(state.asset);
      } catch (e) { if (current()) error(action === 'copy' ? '复制失败，请手动选中命令复制。' : e.message); }
      finally { state.busy = false; if (current() && b.isConnected) b.disabled = false; }
    };
    target.innerHTML = '<p role="status">正在读取可管理的真实资产和责任联系人…</p>';
    try {
      const results = await Promise.all([ctx.api('/api/v1/assets?offset=0'), ctx.api('/people?offset=0'), fetch('/downloads/onboarding.json', { cache: 'no-store' }).then(r => r.ok ? r.json() : null).catch(() => null)]);
      if (!current()) return;
      state.assets = results[0]; state.people = results[1].filter(p => p.enabled); state.manifest = results[2]; paint();
    } catch (e) { if (current()) target.innerHTML = panel('无法读取接入资料', `<p role="alert">${esc(e.message)}</p><p>没有创建任何资产。请刷新重试或联系管理员检查权限。</p>`); }
  }
  const exported = { renderHelp, mount, leave, connection, config, installCommands, evaluate, quote, enrollCommands };
  if (typeof module !== 'undefined' && module.exports) module.exports = exported;
  else global.InfraOnboarding = exported;
})(typeof window !== 'undefined' ? window : globalThis);
