import { NowRequest, NowResponse } from "@vercel/node";
import { getNameData } from "./utils/file_name_util";
import { sendError } from "./utils/send_error";

const MOCK_MALICIOUS = false;

const packageFilesQuery = (name: string, version: string) =>
  `
    query {
      module(name: "${name}") {
        uploads(version: "${version}") {
          files {
            txId
            manifestId
          }
        }
      }
    }
  `;

export default async (req: NowRequest, res: NowResponse) => {
  const moduleData = getNameData(req.url ?? "");
  const { ignoreMalicious = "no" } = req.query;
  if (!moduleData) return sendError(res, 400, "Invalid package URL");

  if (MOCK_MALICIOUS && ignoreMalicious !== "yes") {
    const warningMsg = `The module ${moduleData.name}@${moduleData.version} has been flagged for containing malware.`;
    res.setHeader("X-Deno-Warning", warningMsg);

    return sendError(res, 451, warningMsg);
  }

  res.status(200).send(`
    <style>
      * {
          font-family: monospace;
          font-size: 18px;
      }
    </style>
    <p>
      <b>Module Name:</b> ${moduleData.name}
      <br />
      <br />
      <b>Module Data:</b> ${JSON.stringify(moduleData)}
      <br />
      <br />
      <b>Query to be used:</b>
      ${packageFilesQuery(moduleData.name, moduleData.version)
        .replace(/ /g, "&nbsp;")
        .replace(/\n/g, "<br />")}
    </p>
  `);
};
