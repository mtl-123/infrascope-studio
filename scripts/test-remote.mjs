import { PGlite } from "@electric-sql/pglite";
import { PGLiteSocketServer } from "@electric-sql/pglite-socket";
import { spawn } from "node:child_process";
const db = await PGlite.create(),
  server = new PGLiteSocketServer({
    db,
    host: "127.0.0.1",
    port: 55439,
    maxConnections: 20,
  });
await server.start();
const go = process.env.INFRA_GO || "go";
const child = spawn(
  go,
  ["test", "-race", "-count=1", "-v", "-timeout", "240s", "./..."],
  {
    cwd: new URL("../remote-access/", import.meta.url),
    env: {
      ...process.env,
      INFRA_TEST_DATABASE_URL:
        "postgres://postgres@127.0.0.1:55439/postgres?sslmode=disable&default_query_exec_mode=describe_exec&pool_max_conns=1",
    },
    stdio: "inherit",
  },
);
const code = await new Promise((resolve) => {
  child.on("exit", resolve);
  child.on("error", (e) => {
    process.stderr.write(e.message + "\n");
    resolve(1);
  });
});
await server.stop();
await db.close();
process.exitCode = code || 0;
