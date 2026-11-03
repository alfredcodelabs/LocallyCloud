// Linux-only bounded access to two explicitly selected directory descriptors.
import { constants } from 'node:fs';
import { open, realpath, mkdir, opendir } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import * as M from '../../crates/core/src/views/architecture/model.js';
import * as R from '../../crates/core/src/views/architecture/engine.js';
const READ = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
export async function workspace(directory) {
  if (!path.isAbsolute(directory) || path.resolve(directory) !== await realpath(directory)) { throw new Error('Use an absolute workspace without symlinks'); }
  const root = await open(directory, READ | constants.O_DIRECTORY);
  let proposals;
  try {
    const stat = await root.stat();
    if (stat.uid !== process.getuid() || (stat.mode & 0o077)) { throw new Error('Workspace must be owned by the current user with mode 0700'); }
    const base = `/proc/self/fd/${root.fd}`;
    await mkdir(base + '/proposals', { mode: 0o700 }).catch(e => { if (e.code !== 'EEXIST') { throw e; } });
    proposals = await open(base + '/proposals', READ | constants.O_DIRECTORY);
    const proposalStat = await proposals.stat();
    if (proposalStat.uid !== process.getuid() || (proposalStat.mode & 0o077)) { throw new Error('Proposal directory must be private and user-owned'); }
    const out = `/proc/self/fd/${proposals.fd}`;
    let written = 0, proposing = false;
    return {
      async read() {
        const file = await open(base + '/review.json', READ);
        try {
          const stat = await file.stat();
          if (!stat.isFile() || stat.size > M.LIMIT.bytes) { throw new Error('Review must be a regular file up to 8 MiB'); }
          const buffer = Buffer.alloc(Math.min(M.LIMIT.bytes + 1, stat.size + 1)); let length = 0;
          while (length < buffer.length) {
            const { bytesRead } = await file.read(buffer, length, buffer.length - length, length);
            if (!bytesRead) { break; } length += bytesRead;
          }
          if (length > M.LIMIT.bytes) { throw new Error('Review exceeds 8 MiB'); }
          if (length !== stat.size) { throw new Error('Review changed while reading; retry'); }
          const model = M.importModel(M.parse(buffer.subarray(0, length).toString('utf8')));
          if (model.documentType !== 'review') { throw new Error('Save an explicit review JSON from the UI first'); }
          return model;
        } finally { await file.close(); }
      },
      async propose(model, command, expectedDigest) {
        if (proposing) { throw new Error('Another proposal is being written; retry after it completes'); }
        proposing = true;
        try {
          if (await R.digest(model) !== expectedDigest) { throw new Error('Stale context: read the review again'); }
          const proposal = await R.proposal(model, command);
          const json = JSON.stringify(proposal, null, 2);
          if (Buffer.byteLength(json) > 65536) { throw new Error('Proposal exceeds 64 KiB'); }
          // Bound directory traversal and writes even if many requests arrive concurrently.
          const entries = await opendir(out); let count = 0;
          for await (const ignored of entries) { if (++count >= 128) { throw new Error('Proposal directory limit reached; archive proposals explicitly'); } }
          if (++written > 128) { throw new Error('Session proposal limit reached'); }
          const name = randomUUID() + '.json';
          const file = await open(out + '/' + name, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
          try { await file.writeFile(json); await file.sync(); } finally { await file.close(); }
          return { proposalFile: 'proposals/' + name, proposal, committed: false, nextAction: 'Open this proposal in the human UI; inspect its diff before accepting.' };
        } finally { proposing = false; }
      },
      async close() { await proposals.close(); await root.close(); },
    };
  } catch (error) { await proposals?.close(); await root.close(); throw error; }
}
