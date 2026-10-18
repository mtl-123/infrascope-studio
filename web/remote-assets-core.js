(function (scope) {
  "use strict";
  const bytes = (value) => new TextEncoder().encode(value).length;
  const submitDisabled = (submitting, ready = true) => submitting || !ready;
  function text(value, label, limit) {
    const result = String(value || "").trim();
    if (bytes(result) > limit) throw Error(`${label}不能超过 ${limit} 个 UTF-8 字节`);
    if (/[\x00\r\n]/.test(result)) throw Error(`${label}不能包含控制字符或换行`);
    return result;
  }
  function ownershipUnchanged(existing, value) {
    const previous = existing?.ownership;
    if (existing?.ownershipLegacy !== false || !previous || !value || previous.state !== value.state) return false;
    for (const field of ["userId", "claimantId", "operationsId", "businessId"]) {
      if ((previous[field] || "") !== (value[field] || "")) return false;
    }
    for (const field of ["notificationIds", "backupIds"]) {
      const before = previous[field] ?? [], after = value[field] ?? [];
      if (!Array.isArray(before) || !Array.isArray(after) || before.length !== after.length) return false;
      const sorted = [...before].sort(), next = [...after].sort();
      if (sorted.some((id, index) => id !== next[index])) return false;
    }
    return true;
  }
  function ownershipPayload(value, people) {
    if (!["assigned", "pending"].includes(value?.state)) throw Error("请明确选择责任状态，不能默认指派负责人");
    const result = { state: value.state };
    const known = new Map((people || []).map((person) => [person.id, person]));
    const personId = (id) => {
      const result = text(id, "人员 ID", 120);
      if (result && !known.get(result)?.enabled) throw Error("责任人员缺失、停用或尚未读取，请重新搜索并选择有效人员");
      return result;
    };
    for (const field of ["userId", "claimantId", "operationsId", "businessId"]) result[field] = personId(value[field]);
    for (const field of ["notificationIds", "backupIds"]) {
      if (value[field] != null && !Array.isArray(value[field])) throw Error("通知人与备用联系人必须为人员列表");
      const ids = (value[field] || []).map(personId);
      if (ids.length > 20 || ids.some((id) => !id) || new Set(ids).size !== ids.length) throw Error("通知人与备用联系人各最多 20 人，不能重复或为空");
      result[field] = ids;
    }
    if (value.state === "assigned" && !result.userId) throw Error("已分配资产必须明确选择使用人");
    if (value.state === "pending" && !result.claimantId) throw Error("待认领资产必须明确选择待认领负责人");
    if ((value.state === "assigned" && result.claimantId) || (value.state === "pending" && result.userId)) throw Error("使用人与待认领负责人不可混用，请按责任状态选择");
    return result;
  }
  function personPayload(fields, existing) {
    const displayName = text(fields.displayName, "姓名", 180);
    if (!displayName) throw Error("请填写人员姓名");
    const email = text(fields.email, "邮箱", 254);
    if (email && !/^[^\s@<>]+@[^\s@<>]+$/.test(email)) throw Error("请填写有效邮箱，或留空并明确尚无可投递邮箱");
    if (!["internal", "external"].includes(fields.contactType)) throw Error("请选择内部人员或外部联系人");
    return {
      ...(existing ? { version: existing.version } : {}),
      displayName, department: text(fields.department, "部门", 240), email,
      contactType: fields.contactType, enabled: fields.enabled === true,
    };
  }
  function importPreviewPayload(fields, people, source = "csv") {
    const claimantId = text(fields.claimantId, "待认领负责人 ID", 120);
    if (!claimantId || !(people || []).some((person) => person.id === claimantId && person.enabled)) throw Error("请明确选择已读取且启用的待认领负责人");
    const result = { claimantId, organizationId: text(fields.organizationId, "组织 ID", 120) };
    if (source === "csv") {
      if (typeof fields.csv !== "string" || !fields.csv.trim()) throw Error("请粘贴或读取 UTF-8 CSV 文件");
      if (bytes(fields.csv) > 512 * 1024) throw Error("CSV 不能超过 512 KiB（UTF-8）");
      result.csv = fields.csv;
    } else if (source !== "local_discovery") throw Error("不支持的候选来源");
    return result;
  }
  function importSelection(job, values, now = Date.now()) {
    if (!["preview", "partial"].includes(job?.state)) throw Error("该任务不能继续确认，请重新读取真实任务状态");
    if (!Number.isFinite(Date.parse(job.expiresAt)) || Date.parse(job.expiresAt) <= now) throw Error("预览已过期，请重新生成并核对候选");
    const rowNumbers = values.map(Number);
    if (!rowNumbers.length || new Set(rowNumbers).size !== rowNumbers.length) throw Error("请明确选择至少一个未创建的候选行，不能重复选择");
    const rows = new Map((job.rows || []).map((row) => [row.rowNumber, row]));
    for (const number of rowNumbers) {
      if (!Number.isSafeInteger(number) || !["ready", "failed"].includes(rows.get(number)?.state)) throw Error("选择包含不可确认行，请重新读取任务后核对");
    }
    return { confirm: true, rowNumbers };
  }
  function assetPayload(fields, existing, people) {
    const name = text(fields.name, "资产名称", 180);
    if (!name) throw Error("请填写资产名称，最多 180 个 UTF-8 字节");
    if (!["server", "nas", "pve", "switch", "printer", "scanner", "other"].includes(fields.category)) throw Error("请选择资产类别");
    if (!["physical", "virtual"].includes(fields.kind)) throw Error("请选择物理或虚拟类型");
    if (!["linux", "windows", "other"].includes(fields.osFamily)) throw Error("请选择操作系统");
    const endpoints = (fields.endpoints || []).filter((endpoint) => endpoint.enabled).map((endpoint) => {
      const host = String(endpoint.host || "").trim();
      const port = Number(endpoint.port);
      const gatewayId = String(endpoint.gatewayId || "").trim();
      if (!host || /[\s/\\@?#\x00]/.test(host)) throw Error(`${endpoint.protocol.toUpperCase()} 地址应为主机名或 IP，不包含协议头、路径或空白`);
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error(`${endpoint.protocol.toUpperCase()} 端口必须是 1–65535 的整数`);
      if (!gatewayId) throw Error(`${endpoint.protocol.toUpperCase()} 需要明确网关 ID`);
      return { protocol: endpoint.protocol, host, port, gatewayId };
    });
    const tags = [...new Set(String(fields.tags || "").split(/[,，]/).map((value) => value.trim()).filter(Boolean))];
    if (tags.length > 30 || tags.some((value) => bytes(value) > 80)) throw Error("标签最多 30 项，每项不超过 80 个 UTF-8 字节");
    const metadata = {};
    for (const field of ["provider", "vmName", "instanceId", "hypervisorLabel"]) {
      const value = text(fields[field], "虚拟化元数据", 200);
      if (value) metadata[field] = value;
    }
    return {
      ...(existing ? { version: existing.version } : {}),
      name, kind: fields.kind, osFamily: fields.osFamily, category: fields.category,
      environment: text(fields.environment, "环境", 120), site: text(fields.site, "地点", 120), business: text(fields.business, "业务", 120),
      ...(Object.prototype.hasOwnProperty.call(fields, "organizationId") && (!existing || text(fields.organizationId, "组织 ID", 120) !== (existing.organization_id || "")) ? { organizationId: text(fields.organizationId, "组织 ID", 120) } : {}),
      ...(ownershipUnchanged(existing, fields.ownership) ? {} : { ownership: ownershipPayload(fields.ownership, people) }),
      groupName: text(fields.groupName, "分组", 120), tags,
      description: String(fields.description || "").trim(), metadata,
      enabled: fields.enabled === true, archived: fields.archived === true,
      inventoryId: existing?.inventory_id || String(fields.inventoryId || "").trim(),
      endpoints,
    };
  }
  if (typeof module !== "undefined" && module.exports) module.exports = { assetPayload, personPayload, ownershipUnchanged, submitDisabled, importPreviewPayload, importSelection };
  else scope.InfraRemoteAssets = { assetPayload, personPayload, ownershipUnchanged, submitDisabled, importPreviewPayload, importSelection };
})(typeof window === "undefined" ? globalThis : window);
