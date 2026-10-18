(function (scope) {
  "use strict";
  function parseIntent(search) {
    const params = new URLSearchParams(search);
    if (!["assetId", "accountId", "protocol"].some((key) => params.has(key))) return null;
    for (const key of params.keys()) if (!["assetId", "accountId", "protocol", "userId"].includes(key)) throw Error("快捷连接链接包含未知字段");
    for (const key of ["assetId", "accountId", "protocol", "userId"]) if (params.getAll(key).length !== 1) throw Error("快捷连接链接字段不完整或重复");
    const assetId = params.get("assetId"), accountId = params.get("accountId"), protocol = params.get("protocol"), userId = params.get("userId");
    if (![assetId,accountId,userId].every(value => /^[A-Za-z0-9_-]{1,120}$/.test(value)) || !["ssh", "sftp"].includes(protocol)) throw Error("快捷连接引用或协议无效");
    return { assetId, accountId, protocol, userId };
  }
  function authorizedAccount(items, intent) {
    const action = intent.protocol === "ssh" ? "ssh.connect" : "sftp.list";
    const account = items.find((item) => item.asset_id === intent.assetId && item.account_id === intent.accountId);
    if (!account || !account.grants?.some((grant) => grant.protocols?.includes(intent.protocol) && grant.actions?.includes("remoteAccount.use") && grant.actions?.includes(action))) throw Error("快捷连接已失效或当前登录用户没有该资产账号权限");
    return account;
  }
  if (typeof module !== "undefined" && module.exports) module.exports = { parseIntent, authorizedAccount };
  else scope.InfraQuickLaunch = { parseIntent, authorizedAccount };
})(typeof window === "undefined" ? globalThis : window);
