import type { Finding } from "../types.js";

/** Valid evidence from an incomplete scanner report: retain it, but never count
 * the scanner as successful or cache it as a completed pass. */
export class PartialToolReportError extends Error {
  constructor(
    message: string,
    readonly findings: Finding[],
  ) {
    super(message);
    this.name = "PartialToolReportError";
  }
}
