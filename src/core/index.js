// Public entry point for `encrypted-git-storage` / `encrypted-git-storage/core`.
// Everything here is backend- and environment-agnostic (browser, SW, Node):
// WebCrypto + fetch only.
export * from './crypto.js';        // encrypt, decrypt, isEncrypted, sha256hex
export * from './format.js';        // manifest shape + push helpers
export * from './pktline.js';       // git pkt-line framing (protocol v0)
export * from './packcat.js';       // merge append-only packs into one valid pack
export * from './store-client.js';  // makeStoreClient (gateway object endpoints)
export * from './manifest-io.js';   // loadManifest / encryptManifest
export * from './smart-http.js';    // handleInfoRefs / handleUploadPack / handleReceivePack
export * from './maintenance.js';   // compact / replacePacks / pruneOrphans
