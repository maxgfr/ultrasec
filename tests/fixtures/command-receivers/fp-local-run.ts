import { KALI } from "./tp-member.js";

export async function run(api: string, repo: string) {
  return `${api}:${repo}:${KALI}`;
}

export async function main(req: any) {
  const api = req.query.api;
  return run(api, "repo");
}
