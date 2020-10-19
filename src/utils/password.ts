import crypto from "crypto";
import constants from "./constants";

function split(hashed: string) {
  let splitHash = hashed.split("$").slice(1, -1);
  let meta = splitHash[0].split(":");
  let [salt, hash] = splitHash[1]
    .split(":")
    .map((el) => Buffer.from(el, "base64"));

  let algo = meta[0];
  let rounds = parseInt(meta[1]);

  return {
    algo,
    rounds,

    salt,
    hash,
  };
}

function join({
  salt,
  hash,
  algo,
  rounds,
}: {
  salt: Buffer;
  hash: Buffer;
  algo: string;
  rounds: number;
}) {
  let meta = `${algo}:${rounds}`;
  let data = `${salt.toString("base64")}:${hash.toString("base64")}`.replace(
    /=+/g,
    "",
  );
  return `$${meta}$${data}$`;
}

export function hash(password: string): Promise<string> {
  return new Promise((res, rej) => {
    let salt = crypto.randomBytes(constants.DEFAULT_SALT_LENGTH);
    let algo = constants.DEFAULT_HASH_ALGO;
    let rounds = constants.DEFAULT_ROUNDS;
    let keylen: number = constants.HASH_ALGOS[algo].keylen;

    if (crypto.getHashes().indexOf(algo) === -1)
      throw new Error("Invalid hashing algorithm");
    return crypto.pbkdf2(password, salt, rounds, keylen, algo, (err, hash) => {
      if (err) return rej(err);
      return res(
        join({
          algo,
          rounds,
          salt,
          hash,
        }),
      );
    });
  });
}

export function verify(password: string, hashed: string): Promise<boolean> {
  return new Promise((res, rej) => {
    let { algo, rounds, salt, hash } = split(hashed);
    if (!constants.HASH_ALGOS[algo])
      throw new Error("Invalid algorithm identifier");
    let keylen: number = constants.HASH_ALGOS[algo].keylen;

    if (crypto.getHashes().indexOf(algo) === -1)
      throw new Error("Invalid hashing algorithm");
    return crypto.pbkdf2(
      password,
      salt,
      rounds,
      keylen,
      algo,
      (err, computedHash) => {
        if (err) return rej(err);
        return res(crypto.timingSafeEqual(hash, computedHash));
      },
    );
  });
}
