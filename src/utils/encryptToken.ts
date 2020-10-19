import crypto from "crypto";
import token from "./token";
import { hash } from "./password";

const ENCRYPTION_ALGOS = {
  "chacha20-blake2b": {
    algoName: "chacha20",
    ivLength: 16,
    keyLength: 32,
    hashName: "blake2b512",
    hashLength: 64,
    tagLength: 16,
  },
  "aes128ctr-sha256": {
    algoName: "aes-128-ctr",
    ivLength: 16,
    keyLength: 16,
    hashName: "sha256",
    hashLength: 32,
    tagLength: 16,
  },
};

const DEFAULT_ALGO: keyof typeof ENCRYPTION_ALGOS = "chacha20-blake2b";

function split (encrypted: string) {
  let splitEnc = encrypted.split("$").slice(1, -1);
  let algo: keyof typeof ENCRYPTION_ALGOS = splitEnc[0] as any;
  if (!ENCRYPTION_ALGOS[algo]) throw new Error("Invalid algorithm identifier");
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

function _encrypt (token: string, key: string) {
  let algoSpecs = ENCRYPTION_ALGOS[DEFAULT_ALGO];
  if (crypto.getCiphers().indexOf(algoSpecs.algoName) === -1) throw new Error("Invalid encryption algorithm");
  if (crypto.getHashes().indexOf(algoSpecs.hashName) === -1) throw new Error("Invalid hashing algorithm");
  let tokenBuffer = Buffer.from(token, "utf8");
  let iv = crypto.randomBytes(algoSpecs.ivLength);
  let derivedKey = crypto.createHash(algoSpecs.hashName).update(key).digest().slice(0, algoSpecs.keyLength);
  let hashedToken = crypto.createHash(algoSpecs.hashName).update(iv).update(tokenBuffer).digest().slice(0, algoSpecs.hashLength);
  if (derivedKey.length !== algoSpecs.keyLength) throw new Error("Hash not long enough");
  let cipher = crypto.createCipheriv(algoSpecs.algoName, derivedKey, iv);
  let outBuffers = [];
  outBuffers.push(cipher.update(tokenBuffer));
  outBuffers.push(cipher.final());
  let encryptedToken = Buffer.concat(outBuffers);
  let tag = crypto.createHash(algoSpecs.hashName).update(DEFAULT_ALGO).update(derivedKey).update(iv).update(encryptedToken).digest().slice(0, algoSpecs.tagLength);
  let outString = join({ algo: DEFAULT_ALGO, iv: iv, tag: tag, encryptedToken: encryptedToken, hashedToken: hashedToken });
  return outString;
}

// empty type extending boolean, to provide better documentation through types
interface IsTagValid extends Boolean {}

function _decrypt (encryptedToken: string, key: string): [ RawToken, IsTagValid ] {
  let parsedToken = split(encryptedToken);
  let algoSpecs = ENCRYPTION_ALGOS[parsedToken.algo];
  if (crypto.getCiphers().indexOf(algoSpecs.algoName) === -1) throw new Error("Invalid encryption algorithm");
  if (crypto.getHashes().indexOf(algoSpecs.hashName) === -1) throw new Error("Invalid hashing algorithm");
  let derivedKey = crypto.createHash(algoSpecs.hashName).update(key).digest().slice(0, algoSpecs.keyLength);
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
  let algoSpecs = ENCRYPTION_ALGOS[parsedToken.algo];
  if (crypto.getHashes().indexOf(algoSpecs.hashName) === -1) throw new Error("Invalid hashing algorithm");
  let hashedToken = crypto.createHash(algoSpecs.hashName).update(parsedToken.iv).update(Buffer.from(toCompare, "utf8")).digest().slice(0, algoSpecs.hashLength);
  let isEqual = crypto.timingSafeEqual(hashedToken, parsedToken.hashedToken);
  return isEqual;
}

// empty types extending string, to provide better documentation through types
interface RawToken extends String {}
interface EncryptedToken extends String {}

export function generate (username: string, password: string): [ RawToken, EncryptedToken ] {
  let genToken = token();
  let key = `${username}:${password}`;
  let encryptedToken = _encrypt(genToken, key);
  return [ genToken, encryptedToken ];
}

export function decrypt (encryptedToken: EncryptedToken, username: string, password: string): RawToken {
  let key = `${username}:${password}`;
  let [ decryptedToken, isTagValid ] = _decrypt(encryptedToken as string, key);
  if (!isTagValid) return null;
  return decryptedToken;
}

export function verify (encryptedToken: EncryptedToken, toCompare: RawToken) {
  return _verify(encryptedToken as string, toCompare as string);
}

export default {
  generate,
  decrypt,
  verify,
};