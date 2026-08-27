import { createHash } from "node:crypto";

export function sha256(bytes) {
  return "sha256:" + createHash("sha256").update(bytes).digest("hex");
}
