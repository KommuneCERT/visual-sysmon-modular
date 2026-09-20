import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Catalog } from "../../site/js/catalog.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const catalogData = JSON.parse(readFileSync(path.join(root, "site/data/catalog.json"), "utf8"));
export const newCatalog = (overlay = {}) => new Catalog(catalogData, overlay);
export const profileWith = rels => ({ slug: "t", name: "t", sysmon_version: "15", modules: rels });
