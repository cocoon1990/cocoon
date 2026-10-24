// پروسهٔ جدا: ROUTER یک OnceLock است، پس برای config متفاوت باید
// نمونهٔ Wasm تازه init شود.
import fs from "node:fs";

const dir = "/tmp/wasmtest";
const glue = await import(`${dir}/ghost_wasm.js`);
await glue.default({
  module_or_path: new Response(fs.readFileSync(`${dir}/ghost_wasm_bg.wasm`), { headers: { "Content-Type": "application/wasm" } }),
});

glue.init_router(fs.readFileSync(`${dir}/deny-config.json`, "utf8"));
const d = JSON.parse(glue.route_request("https://youtube.com/blocked/x", "", 0));

console.log(
  `backend=${JSON.stringify(d.backend)} is_denied=${d.is_denied} ` +
    `deny_exact_match=${d.backend === "deny"}`
);
