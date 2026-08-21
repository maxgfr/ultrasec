import { publishAll } from "../../lib/publish";

export default async function handler(req, res) {
  const { session_variables } = req.body;
  return res.json(await publishAll(session_variables));
}
