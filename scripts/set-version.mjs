import fs from "fs";

const version = process.env.VERSION;

if (!version) {
  console.error("Missing VERSION env var.");
  process.exit(1);
}

function updateJson(filePath, updater) {
  if (!fs.existsSync(filePath)) return;
  const raw = fs.readFileSync(filePath, "utf8");
  const parsed = JSON.parse(raw);
  updater(parsed);
  fs.writeFileSync(filePath, JSON.stringify(parsed, null, 2));
}

updateJson("src-tauri/tauri.conf.json", (tauri) => {
  tauri.version = version;
});

updateJson("package.json", (pkg) => {
  pkg.version = version;
});

const cargoPath = "src-tauri/Cargo.toml";
if (fs.existsSync(cargoPath)) {
  const raw = fs.readFileSync(cargoPath, "utf8");
  const updated = raw.replace(
    /^(version\s*=\s*")[^"]+("\s*)$/m,
    `$1${version}$2`,
  );
  fs.writeFileSync(cargoPath, updated);
}

console.log(`Set version ${version}`);
