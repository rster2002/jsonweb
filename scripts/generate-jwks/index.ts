const es256 = await crypto.subtle.generateKey(
  {
    name: "ECDSA",
    namedCurve: "P-256",
  },
  true,
  ["sign", "verify"],
);

const es256private = await crypto.subtle.exportKey("jwk", es256.privateKey);
const es256public = await crypto.subtle.exportKey("jwk", es256.publicKey);

await Bun.write("es256-public.jwks.json", JSON.stringify(es256public, null, 2));
await Bun.write("es256-private.jwks.json", JSON.stringify(es256private, null, 2));

const rs256 = await crypto.subtle.generateKey(
  {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: "SHA-256",
  },
  true,
  ["sign", "verify"],
);

const rs256private = await crypto.subtle.exportKey("jwk", rs256.privateKey);
const rs256public = await crypto.subtle.exportKey("jwk", rs256.publicKey);

await Bun.write("rs256-public.jwks.json", JSON.stringify(rs256public, null, 2));
await Bun.write("rs256-private.jwks.json", JSON.stringify(rs256private, null, 2));
