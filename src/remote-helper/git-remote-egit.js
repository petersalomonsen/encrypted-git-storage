#!/usr/bin/env node
// git remote helper for the `egit::` transport.
//
//   git clone egit::<proxy-url>/<repoId>
//   git push  egit::<proxy-url>/<repoId> main
//
// git invokes this with argv = [remoteName, url] and speaks the remote-helper
// protocol on stdin/stdout (`git help remote-helpers`). We implement the
// "connect"/fetch/push capabilities by building/parsing packfiles, encrypting them
// with ../core/crypto.js, and PUT/GET-ing them via the gateway proxy.
//
// The AES key comes from EGIT_KEY (hex/base64) in the environment for now (Ariz
// exports the wallet-derived key). Reuse ../core with the service worker so both
// sides interoperate.
//
// TODO(next session): implement the remote-helper command loop:
//   capabilities -> "fetch\npush\n\n"
//   list         -> advertise refs from the decrypted manifest
//   fetch        -> download+decrypt packs, feed objects to git (fast-import or a
//                   temp pack), or use `git index-pack`
//   push         -> `git pack-objects --thin --revs`, encrypt, PUT, CAS the refs
// Mirror near-git-storage's git-remote-near for the pack plumbing.

import process from 'node:process';

async function main() {
    const [, , _remoteName, _url] = process.argv;
    // TODO: parse url -> { proxyUrl, repoId }; load EGIT_KEY.
    process.stderr.write('git-remote-egit: not implemented yet — see TODOs.\n');
    process.exit(1);
}

main();
