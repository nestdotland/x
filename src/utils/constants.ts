export const ENCRYPTION_ALGOS = {
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

export const DEFAULT_ENCRYPTION_ALGO: keyof typeof ENCRYPTION_ALGOS =
  "chacha20-blake2b";

export const HASH_ALGOS = {
  sha256: {
    keylen: 32,
  },
  sha384: {
    keylen: 48,
  },
  sha512: {
    keylen: 64,
  },
  blake2b512: {
    keylen: 64,
  },
};

export const DEFAULT_SALT_LENGTH = 16;
export const DEFAULT_ROUNDS = 32000;
export const DEFAULT_HASH_ALGO: keyof typeof HASH_ALGOS = "blake2b512";

export default {
  ENCRYPTION_ALGOS,
  DEFAULT_ENCRYPTION_ALGO,
  HASH_ALGOS,
  DEFAULT_SALT_LENGTH,
  DEFAULT_ROUNDS,
  DEFAULT_HASH_ALGO,
};
