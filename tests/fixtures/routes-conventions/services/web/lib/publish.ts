import { execSync } from "child_process";

export function publishAll(v) {
  return execSync("publish --for " + v);
}

export function store(v) {
  return v;
}
