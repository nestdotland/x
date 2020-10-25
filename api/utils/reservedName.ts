export const RESERVED = new Set([
    // std package names and Deno default packages
    "_util",
    "archive",
    "async",
    "bytes",
    "datetime",
    "encoding",
    "examples",
    "flags",
    "fmt",
    "fs",
    "hash",
    "http",
    "io",
    "log",
    "mime",
    "node",
    "assert",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "dns",
    "events",
    "https",
    "http2",
    "module",
    "net",
    "os",
    "perf_hooks",
    "process",
    "querystring",
    "readline",
    "repl",
    "std",
    "stream",
    "string_decoder",
    "sys",
    "timers",
    "tls",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "worker_threads",
    "zlib",
    "path",
    "permissions",
    "signal",
    "testing",
    "textproto",
    "uuid",
    "ws",
    "version",
  
    // package names requested to be reserved
    "libre",
  ]);
  
  export default function isNameOkay (name: string) {
    return !RESERVED.has(name);
  }