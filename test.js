const Benchmark = require("benchmark");
const semver = require("semver");

const suite = new Benchmark.Suite();

const mod = "foobar@0.0.1-rc.1.semverCompliantMetaData/thing/thing.ts";
const reg = /^(?<name>[\-\w]+)@(?<version>(?:(?:[0-9]+)\.(?:[0-9]+)\.(?:[0-9]+)(?:-(?:[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)(?:\+(?:[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)(?<path>(?:.+)\/(?:[^/]+))$/;

// add tests
suite
  .add("RegEx version", function () {
    reg.exec(mod);
  })
  .add("String version", function () {
    let [[packageName, packageVersion], ...fileNameParts] = mod
      .split("/")
      .slice(1)
      .map((e, i) => (i === 0 ? e.split("@") : e));
    const name = "/" + fileNameParts.join("/");
    semver.valid(packageVersion);
  })
  .on("cycle", function (event) {
    console.log(String(event.target));
  })
  .on("complete", function () {
    console.log("Fastest is " + this.filter("fastest").map("name"));
  })
  .run({ async: true });
