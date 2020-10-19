import fs from "fs";
import path from "path";

export function init(time = 60, age = 1800) {
  if (!fs.existsSync("./.tmp")) fs.mkdirSync("./.tmp");

  const _interval = () => {
    fs.readdirSync("./.tmp").map((el) => {
      let f = path.join("./.tmp", el);
      let stats = fs.statSync(f);

      if (Date.now() - stats.mtimeMs > age * 1000) return fs.unlinkSync(f);
    });
  };

  setInterval(_interval, time * 1000);
  _interval();
}

export function save(id: string, data: Buffer) {
  if (id.indexOf("../") !== -1) return false;
  fs.writeFileSync(path.join("./.tmp", id), data);
}

export function get(id: string) {
  if (id.indexOf("../") !== -1) return null;
  let f = path.join("./.tmp", id);
  if (fs.existsSync(f)) {
    return fs.readFileSync(f);
  } else return null;
}

export function has(id: string) {
  let f = path.join("./.tmp", id);
  return fs.existsSync(f);
}
