import { Router } from "express";
import normalize from "../utils/normalize";
import eToken from "../utils/encryptedToken";
import { hash, verify } from "../utils/password";
import { User, DbConnection } from "../utils/driver";

export default (database: DbConnection) => {
  const enableEncryptedTokens = process.env.ENABLE_ENCRYPTED_TOKENS && process.env.ENABLE_ENCRYPTED_TOKENS === "yes";

  const router = Router();

  router.post("/signup", async (req, res) => {
    let { username, password }: { username: string, password: string } = req.body;
    if (!username || !password) return res.sendStatus(400);
    if (typeof username !== "string" || typeof password !== "string") return res.sendStatus(400);

    if (username.length > 20 || username.length < 3) return res.sendStatus(400);

    let nzName = normalize(username);
    if (!nzName) return res.sendStatus(400);

    if (await database.repositories.User.findOne({ where: { normalizedName: nzName } })) return res.sendStatus(409);


    let user = new User();
    user.name = username;
    user.normalizedName = nzName;
    user.password = await hash(password);
    let tokenPair = await eToken.generate(password);
    user.apiKey = enableEncryptedTokens ? tokenPair[1] : tokenPair[0];
    user.packageNames = [];

    await database.repositories.User.insert(user);

    return res.status(201).send({
      success: true,
      name: username,
      apiKey: tokenPair[0],
    });
  });

  router.post("/newpassword", async (req, res) => {
    const { username, password, newPassword }: { username: string, password: string, newPassword: string } = req.body;
    if (!username || !password || !newPassword) return res.sendStatus(400);
    if (typeof username !== "string" || typeof password !== "string" || typeof newPassword !== "string") return res.sendStatus(400);

    if (username.length > 20) return res.sendStatus(400);

    let dbUser = await database.repositories.User.findOne({ where: { name: username } });
    if (!dbUser) return res.sendStatus(404);

    let passwordMatch = await verify(password, dbUser.password);
    if (!passwordMatch) return res.sendStatus(401);

    let newPasswordHash = await hash(newPassword);

    let rawToken = await eToken.decrypt(dbUser.apiKey, password);
    let encryptedToken = await eToken.encrypt(rawToken, newPassword);
    let dbToken = enableEncryptedTokens ? encryptedToken : rawToken;

    await database.repositories.User.update({ name: dbUser.name }, { password: newPasswordHash, apiKey: dbToken });

    return res.status(200).send({
      success: true,
      name: username,
    });
  });

  router.post("/getkey", async (req, res) => {
    const { username, password }: { username: string, password: string } = req.body;
    if (!username || !password) return res.sendStatus(400);

    if (username.length > 20) return res.sendStatus(400);

    let dbUser = await database.repositories.User.findOne({ where: { name: username } });
    if (!dbUser) return res.sendStatus(404);

    let passwordMatch = await verify(password, dbUser.password);
    if (!passwordMatch) return res.sendStatus(401);

    let token = dbUser.apiKey;
    if (token.startsWith("$")) token = await eToken.decrypt(token, password);

    return res.status(200).send({
      success: true,
      name: username,
      apiKey: token,
    });
  });

  router.post("/newkey", async (req, res) => {
    const { username, password }: { username: string, password: string } = req.body;
    if (!username || !password) return res.sendStatus(400);

    if (username.length > 20) return res.sendStatus(400);

    let dbUser = await database.repositories.User.findOne({ where: { name: username } });
    if (!dbUser) return res.sendStatus(404);

    let passwordMatch = await verify(password, dbUser.password);
    if (!passwordMatch) return res.sendStatus(401);

    let tokenPair = await eToken.generate(password);
    let dbToken = enableEncryptedTokens ? tokenPair[1] : tokenPair[0];

    await database.repositories.User.update({ name: dbUser.name }, { apiKey: dbToken });

    return res.status(200).send({
      success: true,
      name: username,
      apiKey: tokenPair[0],
    });
  });

  return router;
};