import { NowResponse } from "@vercel/node";

export function sendError(res: NowResponse, code: number, message: string) {
  return res.status(code).json({ code, message });
}