import { store } from "../../lib/publish";

async function endPoint(request, response) {
  return response.json(await store(request));
}

export default endPoint;
