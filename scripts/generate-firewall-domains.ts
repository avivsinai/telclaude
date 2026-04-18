import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { renderFirewallAllowedDomainsShellScript } from "../src/sandbox/firewall-domains.js";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const outputPath = path.resolve(scriptDir, "../docker/allowed-domains.generated.sh");

await fs.writeFile(outputPath, renderFirewallAllowedDomainsShellScript(), "utf8");
