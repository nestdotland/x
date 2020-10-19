import crypto from "crypto";
import token from "./token";
import constants from "./constants";
import { hash } from "./password";

function split (encrypted: string) {
  let splitEnc = encrypted.split("$").slice(1, -1);
  let algo: keyof typeof constants.ENCRYPTION_ALGOS = splitEnc[0] as any;
  if (!constants.ENCRYPTION_ALGOS[algo]) throw new Error("Invalid algorithm identifier");
  let [ iv, tag, encryptedToken, hashedToken ] = splitEnc[1].split(":").map(el => Buffer.from(el, "base64"));

  return {
    algo,

    iv,
    tag,
    encryptedToken,
    hashedToken,
  };
}

function join ({ algo, iv, tag, encryptedToken, hashedToken }: { algo: string, iv: Buffer, tag: Buffer, encryptedToken: Buffer, hashedToken: Buffer }) {
  let data = `${iv.toString("base64")}:${tag.toString("base64")}:${encryptedToken.toString("base64")}:${hashedToken.toString("base64")}`.replace(/=+/g, "");
  return `$${algo}$${data}$`;
}

function _pbkdf2Key (password: string, iv: Buffer): Promise<Buffer> {
  return new Promise((res, rej) => {
    let algo = constants.DEFAULT_HASH_ALGO;
    let rounds = constants.DEFAULT_ROUNDS;
    let keylen: number = constants.HASH_ALGOS[algo].keylen;

    if (crypto.getHashes().indexOf(algo) === -1) throw new Error("Invalid hashing algorithm");
    return crypto.pbkdf2(password, iv, rounds, keylen, algo, (err, hash) => {
      if (err) return rej(err);
      return res(hash);
    });
  });
}

async function _encrypt (token: string, key: string) {
  let algoSpecs = constants.ENCRYPTION_ALGOS[constants.DEFAULT_ENCRYPTION_ALGO];
  if (crypto.getCiphers().indexOf(algoSpecs.algoName) === -1) throw new Error("Invalid encryption algorithm");
  if (crypto.getHashes().indexOf(algoSpecs.hashName) === -1) throw new Error("Invalid hashing algorithm");
  let tokenBuffer = Buffer.from(token, "utf8");
  let iv = crypto.randomBytes(algoSpecs.ivLength);
  let derivedKey = (await _pbkdf2Key(key, iv)).slice(0, algoSpecs.keyLength);
  let hashedToken = crypto.createHash(algoSpecs.hashName).update(iv).update(tokenBuffer).digest().slice(0, algoSpecs.hashLength);
  if (derivedKey.length !== algoSpecs.keyLength) throw new Error("Hash not long enough");
  let cipher = crypto.createCipheriv(algoSpecs.algoName, derivedKey, iv);
  let outBuffers = [];
  outBuffers.push(cipher.update(tokenBuffer));
  outBuffers.push(cipher.final());
  let encryptedToken = Buffer.concat(outBuffers);
  let tag = crypto.createHash(algoSpecs.hashName).update(constants.DEFAULT_ENCRYPTION_ALGO).update(derivedKey).update(iv).update(encryptedToken).digest().slice(0, algoSpecs.tagLength);
  let outString = join({ algo: constants.DEFAULT_ENCRYPTION_ALGO, iv: iv, tag: tag, encryptedToken: encryptedToken, hashedToken: hashedToken });
  return outString;
}

async function _decrypt (encryptedToken: string, key: string): Promise<[ string, boolean ]> {
  let parsedToken = split(encryptedToken);
  let algoSpecs = constants.ENCRYPTION_ALGOS[parsedToken.algo];
  if (crypto.getCiphers().indexOf(algoSpecs.algoName) === -1) throw new Error("Invalid encryption algorithm");
  if (crypto.getHashes().indexOf(algoSpecs.hashName) === -1) throw new Error("Invalid hashing algorithm");
  let derivedKey = (await _pbkdf2Key(key, parsedToken.iv)).slice(0, algoSpecs.keyLength);
  if (derivedKey.length !== algoSpecs.keyLength) throw new Error("Hash not long enough");
  let decipher = crypto.createDecipheriv(algoSpecs.algoName, derivedKey, parsedToken.iv);
  let outBuffers = [];
  outBuffers.push(decipher.update(parsedToken.encryptedToken));
  outBuffers.push(decipher.final());
  let outString = Buffer.concat(outBuffers).toString("utf8");
  let tag = crypto.createHash(algoSpecs.hashName).update(parsedToken.algo).update(derivedKey).update(parsedToken.iv).update(parsedToken.encryptedToken).digest().slice(0, algoSpecs.tagLength);
  let isTagValid = crypto.timingSafeEqual(tag, parsedToken.tag);
  return [ outString, isTagValid ];
}

function _verify (encryptedToken: string, toCompare: string): boolean {
  let parsedToken = split(encryptedToken);
  let algoSpecs = constants.ENCRYPTION_ALGOS[parsedToken.algo];
  if (crypto.getHashes().indexOf(algoSpecs.hashName) === -1) throw new Error("Invalid hashing algorithm");
  let hashedToken = crypto.createHash(algoSpecs.hashName).update(parsedToken.iv).update(Buffer.from(toCompare, "utf8")).digest().slice(0, algoSpecs.hashLength);
  let isEqual = crypto.timingSafeEqual(hashedToken, parsedToken.hashedToken);
  return isEqual;
}

/**
 * @returns [ Unencrypted token, encrypted token string ]
 */
export async function generate (password: string): Promise<[ string, string ]> {
  let genToken = token();
  let encryptedToken = await _encrypt(genToken, password);
  return [ genToken, encryptedToken ];
}

export async function encrypt (token: string, password: string): Promise<string> {
  let encryptedToken = await _encrypt(token, password);
  return encryptedToken;
}

export async function decrypt (encryptedToken: string, password: string): Promise<string> {
  let [ decryptedToken, isTagValid ] = await _decrypt(encryptedToken, password);
  if (!isTagValid) return null;
  return decryptedToken;
}

export function verify (encryptedToken: string, toCompare: string) {
  return _verify(encryptedToken, toCompare);
}

export default {
  generate,
  encrypt,
  decrypt,
  verify,
};