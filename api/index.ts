import { NowRequest, NowResponse } from "@vercel/node";

import { getNameData } from "./lib/file_name_util";

const packageFilesQuery = (name: string, version: string) =>
  `
  query {
    module(name: "${name}") {
      uploads(version: "${version}") {
        files
      }
    }
  }
`;

export default (req: NowRequest, res: NowResponse) => {
  const moduleData = getNameData(req.url ?? "");
  if (!moduleData) return res.status(400).send("Invalid package URL");

  res.status(200).send(`
    <style>
      * {
          font-family: monospace;
          font-size: 18px;
      }
    </style>
      <b>Module Name:</b> ${moduleData.name}
      <br />
      <br />
      <b>Module Data:</b> ${JSON.stringify(moduleData)}
      <br />
      <br />
      <b>Query to be used:</b>
      ${packageFilesQuery(moduleData.name, moduleData.version).replace(/ /g, "&nbsp;").replace(/\n/g, "<br />")}
  `);
};