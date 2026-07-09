import { test, describe } from 'node:test';

// Remote-helper scenario (real `git` + git-remote-egit + MinIO). Marked todo until
// src/remote-helper/git-remote-egit.js exists (see CLAUDE.md build order).
//
// When implementing, drive it like near-git-storage's CLI tests:
//   - put git-remote-egit on PATH, set EGIT_KEY + proxy URL
//   - in a tmp repo: git init, commit, `git push egit::<proxy>/<repoId> main`
//   - `git clone egit::<proxy>/<repoId>` into another tmp dir; assert file matches
//   - read <repoId>/packs/0 from MinIO and assert it is ciphertext

describe('remote-helper (git-remote-egit) over encrypted object store', () => {
    test.todo('push → clone round-trips via git CLI');
    test.todo('stored packs are ciphertext (zero-knowledge)');
    test.todo('concurrent pushes: refs CAS prevents lost updates');
});
