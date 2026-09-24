import { defineConfig } from "tsup";

export default defineConfig([
  {
    // Library: dual ESM + CJS with type declarations.
    entry: { index: "src/index.ts" },
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    clean: true,
    outDir: "dist",
    target: "node18",
    platform: "node",
  },
  {
    // CLI: CJS only (portable `#!/usr/bin/env node` bin for Jenkins/GitLab).
    entry: { "cli/darkmoon-ci": "cli/darkmoon-ci.ts" },
    format: ["cjs"],
    dts: false,
    sourcemap: false,
    clean: false,
    outDir: "dist",
    target: "node18",
    platform: "node",
    banner: { js: "#!/usr/bin/env node" },
  },
]);
