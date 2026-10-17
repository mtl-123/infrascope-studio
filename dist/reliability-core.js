(function (global) {
'use strict';
function slo(input, target = 99.9, minimum = 100) {
  const valid = Number.isFinite(target) && target > 0 && target < 100 &&
    Number.isFinite(input.total) && Number.isFinite(input.bad) && input.total >= 0 && input.bad >= 0 && input.bad <= input.total;
  if (!valid || input.total < minimum || input.coverage < 0.99 || !Number.isFinite(input.coverage))
    return { known: false, reason: !valid ? '输入无效' : input.coverage < 0.99 ? '采集覆盖不足' : '有效样本不足' };
  const allowance = input.total * (1 - target / 100);
  return { known: true, availability: (1 - input.bad / input.total) * 100,
    allowance, remaining: (allowance - input.bad) / allowance * 100,
    remainingEvents: allowance - input.bad };
}
function burn(bad, total, target) {
  return Number.isFinite(bad) && Number.isFinite(total) && total > 0 && bad >= 0 && bad <= total && target > 0 && target < 100
    ? (bad / total) / (1 - target / 100) : null;
}
function evaluate(pair, target, quality = true, threshold = 14.4) {
  if (!quality || pair.long.total < 100 || pair.short.total < 100) return { state: 'unknown', long: null, short: null };
  const long = burn(pair.long.bad, pair.long.total, target), short = burn(pair.short.bad, pair.short.total, target);
  if (long === null || short === null) return { state: 'unknown', long, short };
  return { state: long >= threshold && short >= threshold ? 'firing' : 'normal', long, short };
}
function transition(state, action, evidenceFresh = false) {
  if (action === 'ack' && state === 'open') return 'investigating';
  if (action === 'verify' && state === 'investigating') return 'verifying';
  if (action === 'resolve' && state === 'verifying' && evidenceFresh) return 'resolved';
  if (action === 'reopen' && state === 'resolved') return 'open';
  return state;
}
function capacity(n, perHost, seconds, bytes = 24) {
  if (![n, perHost, seconds, bytes].every(Number.isFinite) || n < 0 || perHost < 0 || seconds <= 0 || bytes <= 0) return null;
  const perSecond = n * perHost / seconds;
  return { perSecond, perDay: perSecond * 86400, gibPerDay: perSecond * 86400 * bytes / (1024 ** 3) };
}
function scene(key) {
  const base = { key, time: '2026-10-18 01:40:00 CST', total: 1200000, coverage: 1, bad: 430,
    short: { bad: 4, total: 10000 }, long: { bad: 24, total: 60000 }, p95: 186,
    evidenceFresh: true, title: '服务运行平稳', quality: '数据可信', load: [22,25,21,28,25,30,26,24,28,31,29,26] };
  if (key === 'network') return { ...base, bad: 2400, short: { bad: 240, total: 10000 }, long: { bad: 1200, total: 60000 }, p95: 1240,
    title: '办公门户响应变慢', load: [22,25,21,28,25,31,39,64,89,94,92,93] };
  if (key === 'blind') return { ...base, coverage: 0.82, evidenceFresh: false, title: '采集链路出现盲区', quality: '覆盖不足', p95: null,
    short: { bad: 0, total: 0 }, long: { bad: 0, total: 0 }, load: [22,25,21,28,25,31,null,null,null,null,null,null] };
  return base;
}
const api = { slo, burn, evaluate, transition, capacity, scene };
if (typeof module !== 'undefined') module.exports = api; else global.InfraReliabilityCore = api;
})(typeof window !== 'undefined' ? window : globalThis);
