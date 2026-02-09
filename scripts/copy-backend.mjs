import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = path.join(root, "backend");
const dest = path.join(root, "src-tauri", "resources", "backend");

const skipDirs = new Set([".venv", "__pycache__"]);

function shouldCopy(srcPath) {
  const parts = path.normalize(srcPath).split(path.sep);
  return !parts.some((part) => skipDirs.has(part));
}

fs.rmSync(dest, { recursive: true, force: true });
fs.mkdirSync(dest, { recursive: true });

fs.cpSync(src, dest, {
  recursive: true,
  filter: (srcPath) => shouldCopy(srcPath),
});

console.log(`Copied backend to ${dest}`);
