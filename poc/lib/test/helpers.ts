import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
/** poc/ root (test/ is under poc/lib/test). */
export const POC_ROOT = join(here, "..", "..");

export function pocPath(...parts: string[]): string {
  return join(POC_ROOT, ...parts);
}

export function readPoc(...parts: string[]): Buffer {
  return readFileSync(pocPath(...parts));
}

export function readPocText(...parts: string[]): string {
  return readFileSync(pocPath(...parts), "utf8");
}
