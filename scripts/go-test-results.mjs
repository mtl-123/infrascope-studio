export function summarizeGoTests(output, requiredTests = []) {
  const tests = new Map();
  const failures = [];
  for (const line of output.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      failures.push("Go test output contains a non-JSON line");
      continue;
    }
    if (event.Test && ["pass", "fail", "skip"].includes(event.Action)) {
      tests.set(`${event.Package}/${event.Test}`, {
        name: event.Test,
        result: event.Action,
      });
    }
    if (!event.Test && event.Action === "fail") {
      failures.push(`Package failed: ${event.Package}`);
    }
  }
  const results = [...tests.values()];
  for (const name of requiredTests) {
    if (!results.some((test) => test.name === name && test.result === "pass")) {
      failures.push(`Required test did not pass: ${name}`);
    }
  }
  if (!results.length) failures.push("No Go tests executed");
  const counts = { pass: 0, fail: 0, skip: 0 };
  for (const test of results) counts[test.result]++;
  return {
    ...counts,
    failures,
    ok: counts.pass > 0 && counts.fail === 0 && counts.skip === 0 && failures.length === 0,
  };
}
