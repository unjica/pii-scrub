// Packs the package, installs the tarball into a temp project and checks ESM import, CJS require and types.
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname ?? new URL(".", import.meta.url).pathname, "..");
const run = (cmd, args, cwd) =>
  execFileSync(cmd, args, { cwd, stdio: ["ignore", "pipe", "inherit"] }).toString();
const dir = mkdtempSync(join(tmpdir(), "pii-scrub-smoke-"));
try {
  const out = JSON.parse(run("npm", ["pack", "--json", "--pack-destination", dir], root));
  const tarball = join(dir, out[0].filename);
  console.log(`packed ${out[0].filename}: ${out[0].files.length} files, ${out[0].size} bytes`);
  for (const f of out[0].files) console.log(`  ${f.path}`);
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "smoke", private: true }));
  run("npm", ["install", "--no-audit", "--no-fund", tarball], dir);
  const pkg = JSON.parse(
    run("node", ["-p", "JSON.stringify(require('@tacko/pii-scrub/package.json'))"], dir),
  );
  if (Object.keys(pkg.dependencies ?? {}).length) throw new Error("runtime dependencies found");
  writeFileSync(
    join(dir, "esm.mjs"),
    `import { scrubText, scrub, createScrubber } from "@tacko/pii-scrub";
if (scrubText("mail a@b.co") !== "mail [email]") throw new Error("esm text");
if (scrub({ password: "x" }).password !== "[password]") throw new Error("esm value");
if (typeof createScrubber !== "function") throw new Error("esm api");
console.log("ESM import OK");`,
  );
  writeFileSync(
    join(dir, "cjs.cjs"),
    `const { scrubText, scrubError } = require("@tacko/pii-scrub");
if (scrubText("mail a@b.co") !== "mail [email]") throw new Error("cjs text");
const e = scrubError(new Error("token=abc"));
if (!(e instanceof Error) || e.message !== "token=[redacted]") throw new Error("cjs error");
console.log("CJS require OK");`,
  );
  writeFileSync(
    join(dir, "types.mts"),
    `import { createScrubber, type ScrubOptions } from "@tacko/pii-scrub";
const o: ScrubOptions = { detectors: { ipv4: true } };
const s: string = createScrubber(o).text("x");
export { s };`,
  );
  writeFileSync(
    join(dir, "types.cts"),
    `import pii = require("@tacko/pii-scrub");
const s: string = pii.scrubText("x");
export { s };`,
  );
  process.stdout.write(run("node", ["esm.mjs"], dir));
  process.stdout.write(run("node", ["cjs.cjs"], dir));
  const tsc = join(root, "node_modules", "typescript", "bin", "tsc");
  writeFileSync(
    join(dir, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        strict: true,
        noEmit: true,
        module: "nodenext",
        moduleResolution: "nodenext",
        types: [],
      },
      files: ["types.mts", "types.cts"],
    }),
  );
  try {
    run("node", [tsc, "-p", "tsconfig.json"], dir);
  } catch (err) {
    console.error(err.stdout?.toString());
    throw err;
  }
  console.log("Type resolution OK (ESM + CJS, moduleResolution nodenext)");
} finally {
  rmSync(dir, { recursive: true, force: true });
}
