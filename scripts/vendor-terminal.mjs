import { mkdir, copyFile } from "node:fs/promises";
const mappings = {
  "@xterm/xterm/lib/xterm.js": "xterm.js",
  "@xterm/xterm/css/xterm.css": "xterm.css",
  "@xterm/addon-fit/lib/addon-fit.js": "addon-fit.js",
  "@xterm/addon-search/lib/addon-search.js": "addon-search.js",
  "@xterm/addon-serialize/lib/addon-serialize.js": "addon-serialize.js",
  "@xterm/xterm/LICENSE": "xterm-LICENSE",
  "@xterm/addon-fit/LICENSE": "fit-LICENSE",
  "@xterm/addon-search/LICENSE": "search-LICENSE",
};
await mkdir("dist/vendor/terminal", { recursive: true });
for (const [source, target] of Object.entries(mappings))
  await copyFile("node_modules/" + source, "dist/vendor/terminal/" + target);

await copyFile(
  "node_modules/@xterm/xterm/LICENSE",
  "dist/vendor/terminal/serialize-LICENSE",
);
