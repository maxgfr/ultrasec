import { store } from "../../../lib/publish";

export async function GET() {
  return store("all");
}

export async function DELETE() {
  return store("none");
}

function helper() {
  return 1;
}
