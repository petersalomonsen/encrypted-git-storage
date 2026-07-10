import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { concatPacks, packObjectCount } from '../../src/core/packcat.js';
import { pktLine, pktLines, parsePktSection, concatBytes, FLUSH } from '../../src/core/pktline.js';

const execFileP = promisify(execFile);

describe('core/pktline', () => {
    test('frame → parse round-trips, flush separates, remainder preserved', () => {
        const framed = concatBytes(
            pktLines(['want abc\n', 'want def\n']),          // section + flush
            pktLine('done\n'),
            FLUSH,
            new Uint8Array([0x50, 0x41, 0x43, 0x4b]),        // trailing raw payload
        );
        const s1 = parsePktSection(framed);
        assert.deepEqual(s1.lines, ['want abc', 'want def']);
        const s2 = parsePktSection(framed, s1.next);
        assert.deepEqual(s2.lines, ['done']);
        assert.deepEqual([...framed.subarray(s2.next)], [0x50, 0x41, 0x43, 0x4b]);
    });

    test('empty flush-only input parses to zero lines', () => {
        const { lines, next } = parsePktSection(FLUSH);
        assert.deepEqual(lines, []);
        assert.equal(next, 4);
    });
});

describe('core/packcat merges packs into one valid pack', () => {
    let work, env;
    const git = (cwd, ...args) => execFileP('git', args, { cwd, env });
    const gitPack = (cwd, revs) => new Promise((resolve, reject) => {
        const child = spawn('git', ['pack-objects', '--revs', '--thin', '--stdout', '--delta-base-offset', '-q'], { cwd, env });
        const out = [];
        child.stdout.on('data', c => out.push(c));
        child.on('close', code => code === 0 ? resolve(new Uint8Array(Buffer.concat(out))) : reject(new Error(`pack-objects ${code}`)));
        child.stdin.end(revs);
    });

    before(async () => {
        work = await mkdtemp(join(tmpdir(), 'packcat-'));
        env = {
            ...process.env,
            GIT_AUTHOR_NAME: 'T', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 'T', GIT_COMMITTER_EMAIL: 't@t',
        };
    });
    after(() => rm(work, { recursive: true, force: true }));

    test('two incremental (thin) packs merge into a self-contained pack', async () => {
        const repo = join(work, 'src-repo');
        await mkdir(repo);
        await git(repo, 'init', '-b', 'main');
        // Sizable, delta-friendly content so the second pack really uses deltas.
        await writeFile(join(repo, 'data.txt'), 'line of text\n'.repeat(5000));
        await git(repo, 'add', '.');
        await git(repo, 'commit', '-m', 'one');
        const { stdout: shaARaw } = await git(repo, 'rev-parse', 'main');
        const shaA = shaARaw.trim();

        await writeFile(join(repo, 'data.txt'), 'line of text\n'.repeat(5000) + 'appended tail\n');
        await git(repo, 'commit', '-am', 'two');
        const { stdout: shaBRaw } = await git(repo, 'rev-parse', 'main');
        const shaB = shaBRaw.trim();

        const pack0 = await gitPack(repo, `${shaA}\n`);           // full
        const pack1 = await gitPack(repo, `${shaB}\n^${shaA}\n`); // thin increment
        const merged = await concatPacks([pack0, pack1]);
        assert.equal(packObjectCount(merged), packObjectCount(pack0) + packObjectCount(pack1));

        // The acid test: git itself must accept the merged pack as complete and
        // strictly valid in a BARE repo with no other objects (no --fix-thin).
        const scratch = join(work, 'scratch-repo');
        await git(work, 'init', '--bare', 'scratch-repo');
        await new Promise((resolve, reject) => {
            const child = spawn('git', ['index-pack', '--stdin', '--strict'], { cwd: scratch, env, stdio: ['pipe', 'ignore', 'inherit'] });
            child.on('close', code => code === 0 ? resolve() : reject(new Error(`index-pack --strict exited ${code}`)));
            child.stdin.end(merged);
        });

        // And both commits must be fully readable from it.
        await git(scratch, 'cat-file', '-e', shaA);
        await git(scratch, 'cat-file', '-e', shaB);
        const { stdout: type } = await git(scratch, 'cat-file', '-t', shaB);
        assert.equal(type.trim(), 'commit');
    });

    test('merging a single pack is the identity apart from the recomputed trailer', async () => {
        const repo = join(work, 'src-repo');
        const { stdout: sha } = await git(repo, 'rev-parse', 'main');
        const pack = await gitPack(repo, sha);
        const merged = await concatPacks([pack]);
        assert.deepEqual(merged, pack, 'identical including SHA-1 trailer');
    });

    test('rejects garbage', async () => {
        await assert.rejects(() => concatPacks([new Uint8Array(40)]), /bad pack magic/);
        await assert.rejects(() => concatPacks([new Uint8Array(5)]), /pack too small/);
    });
});
