import { createPublicKey, verify } from "node:crypto";
import process from "node:process";

function canonical(value) {
  if (value === null || typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value).replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => {
        const encodedKey = JSON.stringify(key)
          .replace(/\u2028/g, "\\u2028")
          .replace(/\u2029/g, "\\u2029");
        return `${encodedKey}:${canonical(value[key])}`;
      })
      .join(",")}}`;
  }
  throw new Error(`unsupported value type: ${typeof value}`);
}

function publicKeyFromRawHex(publicKeyHex) {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({
    key: Buffer.concat([prefix, Buffer.from(publicKeyHex, "hex")]),
    format: "der",
    type: "spki",
  });
}

let input = "";
for await (const chunk of process.stdin) {
  input += chunk;
}
const request = JSON.parse(input);
const vectors = (request.vectors || []).map((value) => canonical(value));
const signatures = (request.signatures || []).map((check) => ({
  name: check.name,
  valid: verify(
    null,
    Buffer.from(canonical(check.object), "utf8"),
    publicKeyFromRawHex(check.public_key),
    Buffer.from(check.signature, "hex"),
  ),
}));
process.stdout.write(JSON.stringify({ vectors, signatures }));
