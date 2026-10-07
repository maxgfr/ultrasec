import type { Response } from "express";

export function remember(res: Response, token: string): void {
  res.cookie("sid", token);
}
