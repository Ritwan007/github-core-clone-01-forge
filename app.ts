// A standalone GitHub-compatible git forge: git smart HTTP (upload-pack v2/v0, receive-pack v0),
// REST v3 under /api/v3, GraphQL v4 at /api/graphql and MCP at /mcp, all from one in-memory store.
// Node 22, standard library only, no git binary, no network beyond the trial's env.
//
// Determinism: every timestamp the forge emits comes from MAKEFUN_TRIAL_NOW (or a fixed constant
// when it is unset); there is no Date.now() and no Math.random() anywhere in a response. The
// viewer is the scenario's token owner (adaiversen); the bearer token is MAKEFUN_SHOP_TOKEN.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------------------------
// Identity and time
// ---------------------------------------------------------------------------------------------

/** The login the trial's bearer token names (wire.ts buildScenario: viewer users[0]). */
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
/** The stranger login, which owns nothing here (wire.ts buildScenario: users[2]). */
const STRANGER_LOGIN = 'olgabauer';
/** The default branch every repository is born with. */
const DEFAULT_BRANCH = 'main';
/** The identity every server-made commit and tag carries. */
const FORGE_IDENTITY = `${VIEWER_NAME} <${VIEWER_EMAIL}>`;
/** The token every API call must carry; empty only when the env did not set one. */
const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

/** The trial's only "now": MAKEFUN_TRIAL_NOW, else a fixed constant (never the wall clock). */
const TRIAL_NOW_RAW = process.env.MAKEFUN_TRIAL_NOW ?? '';
const TRIAL_NOW_MS = (() => {
  const parsed = Date.parse(TRIAL_NOW_RAW);
  return Number.isFinite(parsed) ? parsed : 1_700_000_000_000;
})();
const TRIAL_NOW_ISO = new Date(TRIAL_NOW_MS).toISOString();
const TRIAL_NOW_SEC = Math.floor(TRIAL_NOW_MS / 1000);

/** The all-zero object id. */
const ZERO_OID = '0'.repeat(40);
const SHA40 = /^[0-9a-f]{40}$/;
const JSON_TYPE = 'application/json; charset=utf-8';

/** A monotonically increasing request counter (request ids never enter a scored export). */
let requestCounter = 0;
/** A global database id counter, so every repo/issue/pull/comment id is unique and stable. */
let nextDbId = 1;

function nextId(): number {
  return nextDbId++;
}

function isOid(value: string): boolean {
  return SHA40.test(value);
}

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

function b64encode(data: Buffer | string): string {
  return Buffer.isBuffer(data) ? data.toString('base64') : Buffer.from(data, 'utf8').toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/\s+/g, ''), 'base64');
}

/** base64url without padding (opaque global ids and pagination cursors). */
function b64url(data: string): string {
  return Buffer.from(data, 'utf8').toString('base64url');
}

function unb64url(text: string): string {
  try {
    return Buffer.from(text, 'base64url').toString('utf8');
  } catch {
    return '';
  }
}

function sha1hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function cloneBuffer(data: Buffer): Buffer {
  return Buffer.from(data);
}

// ---------------------------------------------------------------------------------------------
// pkt-line codec (git smart HTTP framing)
// ---------------------------------------------------------------------------------------------

const PKT_LINE_MAX = 65520;

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  if (data.length + 4 > PKT_LINE_MAX) throw new Error('pkt-line payload too long');
  const header = Buffer.allocUnsafe(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}

function pktFlush(): Buffer {
  return Buffer.from('0000', 'ascii');
}

function pktDelim(): Buffer {
  return Buffer.from('0001', 'ascii');
}

/** Encode a sequence of data lines and control packets into one buffer. */
function pktLines(items: ReadonlyArray<string | Buffer | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(pktFlush());
    else if (item === 'delim') parts.push(pktDelim());
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

type Pkt =
  | { kind: 'data'; payload: Buffer }
  | { kind: 'flush' }
  | { kind: 'delim' }
  | { kind: 'response-end' };

/** Decode pkt-lines from a buffer; returns the packets and the offset where framing stopped. */
function decodePktLines(buffer: Buffer, start = 0): { packets: Pkt[]; offset: number } {
  const packets: Pkt[] = [];
  let offset = start;
  while (offset + 4 <= buffer.length) {
    const head = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const length = Number.parseInt(head, 16);
    if (length === 0) {
      packets.push({ kind: 'flush' });
      offset += 4;
      continue;
    }
    if (length === 1) {
      packets.push({ kind: 'delim' });
      offset += 4;
      continue;
    }
    if (length === 2) {
      packets.push({ kind: 'response-end' });
      offset += 4;
      continue;
    }
    if (length < 4 || length > PKT_LINE_MAX || offset + length > buffer.length) break;
    packets.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return { packets, offset };
}

// ---------------------------------------------------------------------------------------------
// Git object model (SHA-1, exactly as git computes it)
// ---------------------------------------------------------------------------------------------

type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObject {
  type: GitObjectType;
  data: Buffer;
}

const TYPE_CODE: Record<GitObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, GitObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: GitObjectType, data: Buffer): string {
  const hash = createHash('sha1');
  hash.update(Buffer.from(`${type} ${data.length}\u0000`, 'utf8'));
  hash.update(data);
  return hash.digest('hex');
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > data.length) throw new Error('malformed tree object');
    entries.push({
      mode: data.subarray(offset, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: { name: string; mode: string }, b: { name: string; mode: string }): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\u0000`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const headerText = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of headerText.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5);
    else if (line.startsWith('parent ')) parents.push(line.slice(7));
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(tree: string, parents: readonly string[], message: string, timestamp: number): Buffer {
  const who = `${FORGE_IDENTITY} ${timestamp} +0000`;
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

interface TagView {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const headers = new Map<string, string>();
  for (const line of (blank < 0 ? text : text.slice(0, blank)).split('\n')) {
    const space = line.indexOf(' ');
    if (space > 0) headers.set(line.slice(0, space), line.slice(space + 1));
  }
  return {
    object: headers.get('object') ?? '',
    type: headers.get('type') ?? '',
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message: blank < 0 ? '' : text.slice(blank + 2),
  };
}

/** Every object reachable from `roots` (commit -> tree + parents, tag -> target, tree -> entries). */
function collectReachable(roots: Iterable<string>, lookup: (oid: string) => GitObject | undefined): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const root of roots) if (isOid(root)) queue.push(root);
  while (queue.length > 0) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    const object = lookup(oid);
    if (!object) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      for (const parent of commit.parents) queue.push(parent);
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  return seen;
}

// ---------------------------------------------------------------------------------------------
// Packfile read/write (version 2, plain objects plus OFS/REF deltas on read)
// ---------------------------------------------------------------------------------------------

function writePackObjectHeader(type: GitObjectType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile from plain objects (no deltas); trailer is SHA-1 over everything before it. */
function writePack(objects: Iterable<GitObject>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const object of list) {
    parts.push(writePackObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function packChecksumOk(pack: Buffer): boolean {
  if (pack.length < 20) return false;
  return sha1hex(pack.subarray(0, pack.length - 20)) === pack.subarray(pack.length - 20).toString('hex');
}

function readVarintSize(buffer: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buffer[start]!;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let offset = start + 1;
  while (byte & 0x80) {
    byte = buffer[offset++]!;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, next: offset, first };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset++]!;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset++]!;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOffset += delta[offset++]! * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += delta[offset++]! * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      delta.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

interface RawPackEntry {
  offset: number;
  typeCode: number;
  size: number;
  data: Buffer;
  baseOffset?: number;
  baseOid?: string;
}

/** Parse a packfile into objects (deltas resolved); throws on any structural problem. */
function readPack(pack: Buffer, resolveBase?: (oid: string) => GitObject | undefined): Map<string, GitObject> {
  if (pack.length < 32) throw new Error('pack too short');
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const declaredCount = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  if (!packChecksumOk(pack)) throw new Error('pack checksum mismatch');
  const raw: RawPackEntry[] = [];
  const byOffset = new Map<number, RawPackEntry>();
  let offset = 12;
  for (let index = 0; index < declaredCount; index += 1) {
    const entryOffset = offset;
    const header = readVarintSize(pack, offset);
    offset = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: RawPackEntry = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      let byte = pack[offset]!;
      offset += 1;
      let value = byte & 0x7f;
      while (byte & 0x80) {
        byte = pack[offset++]!;
        value = ((value + 1) * 128) + (byte & 0x7f);
      }
      entry.baseOffset = entryOffset - value;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error(`unknown pack type code ${typeCode}`);
    }
    const inflated = inflateSync(pack.subarray(offset, trailerStart), { info: true }) as unknown as {
      buffer: Buffer;
      engine: { bytesWritten: number };
    };
    if (inflated.buffer.length !== header.size) throw new Error('pack entry size mismatch');
    entry.data = inflated.buffer;
    offset += inflated.engine.bytesWritten;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  if (offset !== trailerStart) throw new Error('pack trailing bytes');
  const objects = new Map<string, GitObject>();
  const resolved = new Map<number, { type: GitObjectType; data: Buffer; oid: string }>();
  const resolving = new Set<number>();
  const resolve = (entry: RawPackEntry): { type: GitObjectType; data: Buffer; oid: string } => {
    const done = resolved.get(entry.offset);
    if (done) return done;
    if (resolving.has(entry.offset)) throw new Error('delta cycle');
    resolving.add(entry.offset);
    let type: GitObjectType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset!);
      if (!baseEntry) throw new Error('ofs-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const external = resolveBase?.(entry.baseOid!);
      if (!external) {
        const baseEntry = [...resolved.values()].find((candidate) => candidate.oid === entry.baseOid);
        if (!baseEntry) throw new Error('ref-delta base missing');
        type = baseEntry.type;
        data = applyDelta(baseEntry.data, entry.data);
      } else {
        type = external.type;
        data = applyDelta(external.data, entry.data);
      }
    } else {
      type = CODE_TYPE[entry.typeCode]!;
      data = entry.data;
    }
    const oid = hashObject(type, data);
    const result = { type, data, oid };
    resolved.set(entry.offset, result);
    resolving.delete(entry.offset);
    return result;
  };
  for (const entry of raw) {
    const result = resolve(entry);
    if (!objects.has(result.oid)) objects.set(result.oid, { type: result.type, data: result.data });
  }
  return objects;
}

// ---------------------------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------------------------

interface IssueComment {
  id: number;
  body: string;
}

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: IssueComment[];
}

interface PullFile {
  filename: string;
  status: 'added' | 'removed' | 'modified';
  additions: number;
  deletions: number;
  changes: number;
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  mergeBase: string;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  commitMeta: Map<string, CommitView>;
  labels: Map<string, { name: string; color: string }>;
  issues: Map<number, Issue>;
  pulls: Map<number, Pull>;
  nextNumber: number;
  nextCommentId: number;
}

const reposByName = new Map<string, Repo>();

function globalId(kind: string, dbId: number): string {
  return b64url(`${kind}:${dbId}`);
}

function repoGlobalId(repo: Repo): string {
  return globalId('Repository', repo.id);
}

function issueGlobalId(repo: Repo, issue: Issue): string {
  return globalId('Issue', repo.id * 1_000_000 + issue.number);
}

function pullGlobalId(repo: Repo, pull: Pull): string {
  return globalId('PullRequest', repo.id * 1_000_000 + pull.number);
}

function commentGlobalId(repo: Repo, comment: IssueComment): string {
  return globalId('IssueComment', repo.id * 1_000_000 + comment.id);
}

/** Decode an opaque global id back into its kind and numeric part. */
function parseGlobalId(id: string): { kind: string; num: number } | null {
  const text = unb64url(id);
  const match = /^([A-Za-z]+):(\d+)$/.exec(text);
  if (!match) return null;
  return { kind: match[1]!, num: Number(match[2]) };
}

function createRepo(name: string, isPrivate: boolean, description: string): Repo {
  const repo: Repo = {
    id: nextId(),
    name,
    owner: VIEWER_LOGIN,
    description,
    isPrivate,
    defaultBranch: DEFAULT_BRANCH,
    refs: new Map(),
    objects: new Map(),
    commitMeta: new Map(),
    labels: new Map(),
    issues: new Map(),
    pulls: new Map(),
    nextNumber: 1,
    nextCommentId: 1,
  };
  reposByName.set(name, repo);
  return repo;
}

function lookupRepo(owner: string, name: string): Repo | null {
  if (owner !== VIEWER_LOGIN) return null;
  return reposByName.get(name) ?? null;
}

/** Store an object, returning its id; commits are parsed into the metadata cache. */
function storeObject(repo: Repo, type: GitObjectType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) {
    repo.objects.set(oid, { type, data });
    if (type === 'commit') repo.commitMeta.set(oid, parseCommit(data));
  }
  return oid;
}

function getObject(repo: Repo, oid: string): GitObject | undefined {
  return repo.objects.get(oid);
}

function commitView(repo: Repo, oid: string): CommitView | null {
  const cached = repo.commitMeta.get(oid);
  if (cached) return cached;
  const object = repo.objects.get(oid);
  if (!object || object.type !== 'commit') return null;
  const view = parseCommit(object.data);
  repo.commitMeta.set(oid, view);
  return view;
}

/** Create a commit object on `tree` with `parents` and store it. */
function makeCommit(repo: Repo, tree: string, parents: readonly string[], message: string): string {
  const data = buildCommit(tree, parents, message.endsWith('\n') ? message : `${message}\n`, TRIAL_NOW_SEC);
  return storeObject(repo, 'commit', data);
}

/** Flatten a tree into path -> {mode, oid}; missing trees yield an empty map. */
function flattenTree(repo: Repo, treeOid: string, prefix = ''): Map<string, { mode: string; oid: string }> {
  const out = new Map<string, { mode: string; oid: string }>();
  const object = repo.objects.get(treeOid);
  if (!object || object.type !== 'tree') return out;
  for (const entry of parseTree(object.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') {
      for (const [childPath, child] of flattenTree(repo, entry.oid, path)) out.set(childPath, child);
    } else {
      out.set(path, { mode: entry.mode, oid: entry.oid });
    }
  }
  return out;
}

/** Build (and store) the tree objects for a flat path map; returns the root tree id. */
function buildTreeFromMap(repo: Repo, files: Map<string, { mode: string; oid: string }>): string {
  interface Node {
    files: Map<string, { mode: string; oid: string }>;
    dirs: Map<string, Node>;
  }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, entry] of files) {
    const segments = path.split('/');
    let node = root;
    for (let index = 0; index < segments.length - 1; index += 1) {
      const name = segments[index]!;
      if (!node.dirs.has(name)) node.dirs.set(name, make());
      node = node.dirs.get(name)!;
    }
    node.files.set(segments[segments.length - 1]!, entry);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return storeObject(repo, 'tree', buildTree(entries));
  };
  return build(root);
}

/** The tree of a commit, or null. */
function commitTree(repo: Repo, commitOid: string): string | null {
  const view = commitView(repo, commitOid);
  return view ? view.tree : null;
}

/** Resolve a ref name or oid to a commit oid (branch, tag, full ref, or raw sha). */
function resolveRef(repo: Repo, ref: string): string | null {
  if (isOid(ref)) return repo.objects.has(ref) ? ref : null;
  if (repo.refs.has(ref)) return repo.refs.get(ref)!;
  if (repo.refs.has(`refs/heads/${ref}`)) return repo.refs.get(`refs/heads/${ref}`)!;
  if (repo.refs.has(`refs/tags/${ref}`)) return repo.refs.get(`refs/tags/${ref}`)!;
  return null;
}

/** True when `ancestor` is an ancestor of (or equal to) `oid`. */
function isAncestor(repo: Repo, ancestor: string, oid: string): boolean {
  if (ancestor === oid) return true;
  const seen = new Set<string>();
  const stack = [oid];
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (current === ancestor) return true;
    if (seen.has(current)) continue;
    seen.add(current);
    const view = commitView(repo, current);
    if (!view) continue;
    for (const parent of view.parents) stack.push(parent);
  }
  return false;
}

/** The merge-base of two commits: the first common ancestor found walking from `a`. */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancestorsOfB = new Set<string>();
  const stackB = [b];
  while (stackB.length > 0) {
    const current = stackB.pop()!;
    if (ancestorsOfB.has(current)) continue;
    ancestorsOfB.add(current);
    const view = commitView(repo, current);
    if (!view) continue;
    for (const parent of view.parents) stackB.push(parent);
  }
  const stackA = [a];
  const seen = new Set<string>();
  while (stackA.length > 0) {
    const current = stackA.pop()!;
    if (ancestorsOfB.has(current)) return current;
    if (seen.has(current)) continue;
    seen.add(current);
    const view = commitView(repo, current);
    if (!view) continue;
    for (const parent of view.parents) stackA.push(parent);
  }
  return null;
}

/** Commits reachable from `tip`, newest first (depth-first pre-order, parents in order). */
function listCommits(repo: Repo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (seen.has(current)) continue;
    seen.add(current);
    const view = commitView(repo, current);
    if (!view) continue;
    out.push(current);
    for (let index = view.parents.length - 1; index >= 0; index -= 1) stack.push(view.parents[index]!);
  }
  return out;
}

/** Count lines of a buffer (a trailing newline does not add an empty line). */
function lineCount(data: Buffer): number {
  if (data.length === 0) return 0;
  const text = data.toString('utf8');
  const parts = text.split('\n');
  if (parts.length > 0 && parts[parts.length - 1] === '') parts.pop();
  return parts.length;
}

/** A rough line diff: lines in `next` not in `prev` are additions, the reverse deletions. */
function lineDiff(prev: Buffer, next: Buffer): { additions: number; deletions: number } {
  const prevLines = new Map<string, number>();
  for (const line of prev.toString('utf8').split('\n')) prevLines.set(line, (prevLines.get(line) ?? 0) + 1);
  const nextLines = new Map<string, number>();
  for (const line of next.toString('utf8').split('\n')) nextLines.set(line, (nextLines.get(line) ?? 0) + 1);
  let additions = 0;
  let deletions = 0;
  for (const [line, count] of nextLines) {
    const inPrev = prevLines.get(line) ?? 0;
    if (count > inPrev) additions += count - inPrev;
  }
  for (const [line, count] of prevLines) {
    const inNext = nextLines.get(line) ?? 0;
    if (count > inNext) deletions += count - inNext;
  }
  return { additions, deletions };
}

/** Diff two trees (by root oid) into changed files with line counts. */
function diffTrees(repo: Repo, baseTree: string, headTree: string): PullFile[] {
  const base = flattenTree(repo, baseTree);
  const head = flattenTree(repo, headTree);
  const files: PullFile[] = [];
  const paths = new Set([...base.keys(), ...head.keys()]);
  for (const path of [...paths].sort()) {
    const b = base.get(path);
    const h = head.get(path);
    if (b && !h) {
      const data = repo.objects.get(b.oid)?.data ?? Buffer.alloc(0);
      const deletions = lineCount(data);
      files.push({ filename: path, status: 'removed', additions: 0, deletions, changes: deletions });
    } else if (!b && h) {
      const data = repo.objects.get(h.oid)?.data ?? Buffer.alloc(0);
      const additions = lineCount(data);
      files.push({ filename: path, status: 'added', additions, deletions: 0, changes: additions });
    } else if (b && h && b.oid !== h.oid) {
      const prev = repo.objects.get(b.oid)?.data ?? Buffer.alloc(0);
      const next = repo.objects.get(h.oid)?.data ?? Buffer.alloc(0);
      const { additions, deletions } = lineDiff(prev, next);
      files.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions });
    }
  }
  return files;
}

/** Three-way merge of trees; `conflict` when both sides changed the same path differently. */
function mergeTrees(
  repo: Repo,
  baseTree: string,
  headTree: string,
  tipTree: string,
): { tree: string; conflict: boolean } {
  const base = flattenTree(repo, baseTree);
  const head = flattenTree(repo, headTree);
  const tip = flattenTree(repo, tipTree);
  const merged = new Map<string, { mode: string; oid: string }>();
  let conflict = false;
  const paths = new Set([...base.keys(), ...head.keys(), ...tip.keys()]);
  for (const path of paths) {
    const b = base.get(path);
    const h = head.get(path);
    const t = tip.get(path);
    const same = (x: { oid: string } | undefined, y: { oid: string } | undefined): boolean =>
      (x?.oid ?? null) === (y?.oid ?? null);
    if (same(h, b)) {
      if (t) merged.set(path, t);
    } else if (same(t, b)) {
      if (h) merged.set(path, h);
    } else if (same(h, t)) {
      if (h) merged.set(path, h);
    } else {
      conflict = true;
    }
  }
  return { tree: buildTreeFromMap(repo, merged), conflict };
}

/** Whether a pull request's head can merge cleanly onto its base tip right now. */
function pullIsMergeable(repo: Repo, pull: Pull): boolean {
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  if (!baseTip || !headTip) return false;
  const base = mergeBase(repo, headTip, baseTip);
  if (base === null) return false;
  const baseTree = commitTree(repo, base);
  const headTree = commitTree(repo, headTip);
  const tipTree = commitTree(repo, baseTip);
  if (baseTree === null || headTree === null || tipTree === null) return false;
  return !mergeTrees(repo, baseTree, headTree, tipTree).conflict;
}

/** Squash-merge a pull request onto its base branch; returns the merge commit or null on conflict. */
function squashMerge(repo: Repo, pull: Pull): string | null {
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  if (!baseTip || !headTip) return null;
  const base = mergeBase(repo, headTip, baseTip);
  if (base === null) return null;
  const baseTree = commitTree(repo, base);
  const headTree = commitTree(repo, headTip);
  const tipTree = commitTree(repo, baseTip);
  if (baseTree === null || headTree === null || tipTree === null) return null;
  const { tree, conflict } = mergeTrees(repo, baseTree, headTree, tipTree);
  if (conflict) return null;
  const message = `Merge pull request #${pull.number} from ${pull.headRef}`;
  return makeCommit(repo, tree, [baseTip], message);
}

/** Peel an annotated tag (recursively) to its commit; other objects pass through. */
function peelTag(repo: Repo, oid: string): string {
  let current = oid;
  for (let depth = 0; depth < 8; depth += 1) {
    const object = repo.objects.get(current);
    if (!object || object.type !== 'tag') return current;
    current = parseTag(object.data).object;
  }
  return current;
}

/** The files a pull request changes (merge-base tree vs head tree). */
function pullFiles(repo: Repo, pull: Pull): PullFile[] {
  const baseTree = commitTree(repo, pull.mergeBase);
  const headTree = commitTree(repo, pull.headSha);
  if (baseTree === null || headTree === null) return [];
  return diffTrees(repo, baseTree, headTree);
}

// ---------------------------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------------------------

interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  method: string;
  path: string;
  segments: string[];
  query: URLSearchParams;
  body: Buffer;
  bodyJson: unknown;
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': `forge-${++requestCounter}`,
    ...headers,
  });
  res.end(text);
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > 64 * 1024 * 1024) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}

function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/** Whether the request carries the trial's bearer token. */
function authed(req: IncomingMessage): boolean {
  if (SHOP_TOKEN === '') return true;
  const header = req.headers.authorization ?? '';
  return header === `Bearer ${SHOP_TOKEN}`;
}

/** Parse the request body as JSON; empty body is {}; invalid JSON throws a 400 marker. */
function parseJsonBody(ctx: Ctx): Record<string, unknown> {
  if (ctx.body.length === 0) return {};
  try {
    const parsed: unknown = JSON.parse(ctx.body.toString('utf8'));
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    if (Array.isArray(parsed)) return { __array: parsed };
    return {};
  } catch {
    throw Object.assign(new Error('Invalid JSON body'), { status: 400 });
  }
}

function intQuery(query: URLSearchParams, name: string, fallback: number): number {
  const raw = query.get(name);
  if (raw === null) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/** Paginate a list; returns the page and a Link header value (or null when there is no next page). */
function paginate<T>(ctx: Ctx, items: readonly T[]): { page: T[]; link: string | null } {
  const perPage = Math.min(100, intQuery(ctx.query, 'per_page', 30));
  const page = intQuery(ctx.query, 'page', 1);
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  let link: string | null = null;
  if (start + perPage < items.length) {
    const host = ctx.req.headers.host ?? 'localhost';
    const params = new URLSearchParams(ctx.query);
    params.set('per_page', String(perPage));
    params.set('page', String(page + 1));
    const nextUrl = `http://${host}${ctx.path}?${params.toString()}`;
    const lastPage = Math.max(1, Math.ceil(items.length / perPage));
    params.set('page', String(lastPage));
    const lastUrl = `http://${host}${ctx.path}?${params.toString()}`;
    link = `<${nextUrl}>; rel="next", <${lastUrl}>; rel="last"`;
  }
  return { page: [...slice], link };
}

function pageHeaders(link: string | null): Record<string, string> {
  return link === null ? {} : { link };
}

// ---------------------------------------------------------------------------------------------
// REST JSON shapes
// ---------------------------------------------------------------------------------------------

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: repoGlobalId(repo),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    fork: false,
    created_at: TRIAL_NOW_ISO,
    updated_at: TRIAL_NOW_ISO,
    pushed_at: TRIAL_NOW_ISO,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    clone_url: `https://github.com/${repo.owner}/${repo.name}.git`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
  };
}

function labelJson(repo: Repo, name: string): Record<string, unknown> {
  const label = repo.labels.get(name);
  return {
    id: label ? nextDbId + 0 : 0,
    node_id: label ? globalId('Label', repo.id * 1_000_000 + name.length) : '',
    name,
    color: label?.color ?? 'ededed',
    description: '',
    default: false,
  };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: issueGlobalId(repo, issue),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => labelJson(repo, name)),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    assignee: null,
    created_at: TRIAL_NOW_ISO,
    updated_at: TRIAL_NOW_ISO,
    closed_at: issue.state === 'closed' ? TRIAL_NOW_ISO : null,
    comments: issue.comments.length,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function pullJson(repo: Repo, pull: Pull): Record<string, unknown> {
  return {
    id: pull.id,
    node_id: pullGlobalId(repo, pull),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.headRef, sha: pull.headSha, label: `${repo.owner}:${pull.headRef}` },
    base: { ref: pull.baseRef, sha: pull.baseSha, label: `${repo.owner}:${pull.baseRef}` },
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: TRIAL_NOW_ISO,
    updated_at: TRIAL_NOW_ISO,
    closed_at: pull.state === 'closed' ? TRIAL_NOW_ISO : null,
    draft: false,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
  };
}

function commentJson(repo: Repo, comment: IssueComment): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: commentGlobalId(repo, comment),
    body: comment.body,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: TRIAL_NOW_ISO,
    updated_at: TRIAL_NOW_ISO,
  };
}

function commitJson(repo: Repo, oid: string): Record<string, unknown> {
  const view = commitView(repo, oid);
  const message = view?.message ?? '';
  return {
    sha: oid,
    commit: {
      message,
      author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: TRIAL_NOW_ISO },
      committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: TRIAL_NOW_ISO },
    },
    parents: (view?.parents ?? []).map((parent) => ({ sha: parent })),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${oid}`,
  };
}

// ---------------------------------------------------------------------------------------------
// REST: repositories, branches, commits, contents
// ---------------------------------------------------------------------------------------------

function listUserRepos(ctx: Ctx): void {
  const all = [...reposByName.values()].sort((a, b) => a.id - b.id);
  const { page, link } = paginate(ctx, all.map((repo) => repoJson(repo)));
  sendJson(ctx.res, 200, page, pageHeaders(link));
}

function createUserRepo(ctx: Ctx): void {
  let body: Record<string, unknown>;
  try {
    body = parseJsonBody(ctx);
  } catch (err) {
    sendError(ctx.res, 400, 'Invalid JSON body');
    return;
  }
  const name = typeof body.name === 'string' ? body.name : '';
  if (name === '') {
    sendError(ctx.res, 422, 'name is required');
    return;
  }
  if (reposByName.has(name)) {
    sendError(ctx.res, 422, `Repository ${name} already exists`);
    return;
  }
  const isPrivate = body.private === true;
  const description = typeof body.description === 'string' ? body.description : '';
  const repo = createRepo(name, isPrivate, description);
  sendJson(ctx.res, 201, repoJson(repo));
}

function getRepo(ctx: Ctx, owner: string, name: string): void {
  const repo = lookupRepo(owner, name);
  if (!repo) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  sendJson(ctx.res, 200, repoJson(repo));
}

function patchRepo(ctx: Ctx, owner: string, name: string): void {
  const repo = lookupRepo(owner, name);
  if (!repo) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  let body: Record<string, unknown>;
  try {
    body = parseJsonBody(ctx);
  } catch {
    sendError(ctx.res, 400, 'Invalid JSON body');
    return;
  }
  if (typeof body.description === 'string') repo.description = body.description;
  if (typeof body.private === 'boolean') repo.isPrivate = body.private;
  sendJson(ctx.res, 200, repoJson(repo));
}

function deleteRepo(ctx: Ctx, owner: string, name: string): void {
  const repo = lookupRepo(owner, name);
  if (!repo) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  reposByName.delete(name);
  ctx.res.writeHead(204, { 'x-github-request-id': `forge-${++requestCounter}` });
  ctx.res.end();
}

function listBranches(ctx: Ctx, repo: Repo): void {
  const branches: Record<string, unknown>[] = [];
  for (const [ref, oid] of [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (!ref.startsWith('refs/heads/')) continue;
    branches.push({ name: ref.slice('refs/heads/'.length), commit: { sha: oid }, protected: false });
  }
  sendJson(ctx.res, 200, branches);
}

function getBranch(ctx: Ctx, repo: Repo, branch: string): void {
  const oid = repo.refs.get(`refs/heads/${branch}`);
  if (!oid) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  sendJson(ctx.res, 200, { name: branch, commit: { sha: oid }, protected: false });
}

function getRef(ctx: Ctx, repo: Repo, ref: string): void {
  const oid = repo.refs.get(ref);
  if (!oid) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  sendJson(ctx.res, 200, { ref, object: { sha: oid, type: 'commit' } });
}

function createRef(ctx: Ctx, repo: Repo): void {
  let body: Record<string, unknown>;
  try {
    body = parseJsonBody(ctx);
  } catch {
    sendError(ctx.res, 400, 'Invalid JSON body');
    return;
  }
  const ref = typeof body.ref === 'string' ? body.ref : '';
  const sha = typeof body.sha === 'string' ? body.sha : '';
  if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) {
    sendError(ctx.res, 422, 'Invalid ref or sha');
    return;
  }
  if (repo.refs.has(ref)) {
    sendError(ctx.res, 422, 'Reference already exists');
    return;
  }
  repo.refs.set(ref, sha);
  sendJson(ctx.res, 201, { ref, object: { sha, type: 'commit' } });
}

function listCommits(ctx: Ctx, repo: Repo): void {
  const shaParam = ctx.query.get('sha');
  const tip = shaParam !== null ? resolveRef(repo, shaParam) : repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
  if (!tip) {
    sendJson(ctx.res, 200, []);
    return;
  }
  const commits = listCommits(repo, tip).map((oid) => commitJson(repo, oid));
  sendJson(ctx.res, 200, commits);
}

/** The subtree object id for `dirPath` under a root tree ('' is the root itself). */
function subtreeOid(repo: Repo, rootTree: string, dirPath: string): string | null {
  if (dirPath === '') return rootTree;
  const segments = dirPath.split('/');
  let current = rootTree;
  for (const segment of segments) {
    const object = repo.objects.get(current);
    if (!object || object.type !== 'tree') return null;
    const entry = parseTree(object.data).find((candidate) => candidate.name === segment && candidate.mode === '40000');
    if (!entry) return null;
    current = entry.oid;
  }
  return current;
}

function dirListing(repo: Repo, treeOid: string, dirPath: string): Record<string, unknown>[] {
  const object = repo.objects.get(treeOid);
  if (!object || object.type !== 'tree') return [];
  const entries: Record<string, unknown>[] = [];
  for (const entry of parseTree(object.data)) {
    const path = dirPath === '' ? entry.name : `${dirPath}/${entry.name}`;
    entries.push({
      type: entry.mode === '40000' ? 'dir' : 'file',
      name: entry.name,
      path,
      sha: entry.oid,
      size: entry.mode === '40000' ? 0 : (repo.objects.get(entry.oid)?.data.length ?? 0),
    });
  }
  return entries;
}

function getContents(ctx: Ctx, repo: Repo, filePath: string): void {
  const refParam = ctx.query.get('ref');
  const tip = refParam !== null ? resolveRef(repo, refParam) : repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
  if (!tip) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  const tree = commitTree(repo, tip);
  if (tree === null) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  const flat = flattenTree(repo, tree);
  const file = flat.get(filePath);
  if (file) {
    const data = repo.objects.get(file.oid)?.data ?? Buffer.alloc(0);
    const name = filePath.split('/').pop() ?? filePath;
    sendJson(ctx.res, 200, {
      type: 'file',
      encoding: 'base64',
      size: data.length,
      name,
      path: filePath,
      content: data.toString('base64'),
      sha: file.oid,
    });
    return;
  }
  const sub = subtreeOid(repo, tree, filePath);
  if (sub !== null) {
    sendJson(ctx.res, 200, dirListing(repo, sub, filePath));
    return;
  }
  sendError(ctx.res, 404, 'Not Found');
}

/** Commit one file change on a branch; creates the branch from the default branch when new. */
function commitFile(
  repo: Repo,
  branch: string,
  filePath: string,
  content: Buffer,
  message: string,
  expectedSha?: string,
): { status: 200 | 201; commitSha: string; contentSha: string } | { status: 409 } {
  let tip = repo.refs.get(`refs/heads/${branch}`);
  let baseFiles = new Map<string, { mode: string; oid: string }>();
  let parents: string[] = [];
  if (tip) {
    const tree = commitTree(repo, tip);
    if (tree !== null) baseFiles = flattenTree(repo, tree);
    parents = [tip];
  } else {
    const defaultTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
    if (defaultTip) {
      const tree = commitTree(repo, defaultTip);
      if (tree !== null) baseFiles = flattenTree(repo, tree);
      parents = [defaultTip];
    }
  }
  const existing = baseFiles.get(filePath);
  if (expectedSha !== undefined) {
    if (!existing || existing.oid !== expectedSha) return { status: 409 };
  }
  const blobOid = storeObject(repo, 'blob', content);
  const next = new Map(baseFiles);
  next.set(filePath, { mode: '100644', oid: blobOid });
  const treeOid = buildTreeFromMap(repo, next);
  const commitSha = makeCommit(repo, treeOid, parents, message);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  return { status: existing ? 200 : 201, commitSha, contentSha: blobOid };
}

function putContents(ctx: Ctx, repo: Repo, filePath: string): void {
  let body: Record<string, unknown>;
  try {
    body = parseJsonBody(ctx);
  } catch {
    sendError(ctx.res, 400, 'Invalid JSON body');
    return;
  }
  const message = typeof body.message === 'string' ? body.message : 'Update file';
  const contentB64 = typeof body.content === 'string' ? body.content : '';
  const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
  const sha = typeof body.sha === 'string' ? body.sha : undefined;
  let content: Buffer;
  try {
    content = b64decode(contentB64);
  } catch {
    sendError(ctx.res, 422, 'content is not valid base64');
    return;
  }
  const result = commitFile(repo, branch, filePath, content, message, sha);
  if (result.status === 409) {
    sendError(ctx.res, 409, 'sha does not match the current file');
    return;
  }
  const name = filePath.split('/').pop() ?? filePath;
  sendJson(ctx.res, result.status, {
    content: {
      name,
      path: filePath,
      sha: result.contentSha,
      size: content.length,
      type: 'file',
      encoding: 'base64',
      content: contentB64,
    },
    commit: { sha: result.commitSha, message },
  });
}

function deleteContents(ctx: Ctx, repo: Repo, filePath: string): void {
  let body: Record<string, unknown>;
  try {
    body = parseJsonBody(ctx);
  } catch {
    sendError(ctx.res, 400, 'Invalid JSON body');
    return;
  }
  const message = typeof body.message === 'string' ? body.message : 'Delete file';
  const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
  const sha = typeof body.sha === 'string' ? body.sha : undefined;
  const tip = repo.refs.get(`refs/heads/${branch}`);
  if (!tip) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  const tree = commitTree(repo, tip);
  if (tree === null) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  const files = flattenTree(repo, tree);
  const existing = files.get(filePath);
  if (!existing) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  if (sha !== undefined && sha !== existing.oid) {
    sendError(ctx.res, 409, 'sha does not match the current file');
    return;
  }
  files.delete(filePath);
  const treeOid = buildTreeFromMap(repo, files);
  const commitSha = makeCommit(repo, treeOid, [tip], message);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  sendJson(ctx.res, 200, { commit: { sha: commitSha, message } });
}

// ---------------------------------------------------------------------------------------------
// REST: labels, issues, pull requests
// ---------------------------------------------------------------------------------------------

function createLabel(ctx: Ctx, repo: Repo): void {
  let body: Record<string, unknown>;
  try {
    body = parseJsonBody(ctx);
  } catch {
    sendError(ctx.res, 400, 'Invalid JSON body');
    return;
  }
  const name = typeof body.name === 'string' ? body.name : '';
  if (name === '') {
    sendError(ctx.res, 422, 'name is required');
    return;
  }
  const color = typeof body.color === 'string' ? body.color.replace(/^#/, '') : 'ededed';
  if (!repo.labels.has(name)) repo.labels.set(name, { name, color });
  sendJson(ctx.res, 201, labelJson(repo, name));
}

function createIssue(ctx: Ctx, repo: Repo): void {
  let body: Record<string, unknown>;
  try {
    body = parseJsonBody(ctx);
  } catch {
    sendError(ctx.res, 400, 'Invalid JSON body');
    return;
  }
  const title = typeof body.title === 'string' ? body.title : '';
  if (title === '') {
    sendError(ctx.res, 422, 'title is required');
    return;
  }
  const labels: string[] = [];
  if (Array.isArray(body.labels)) {
    for (const entry of body.labels) {
      if (typeof entry === 'string') labels.push(entry);
      else if (entry !== null && typeof entry === 'object' && typeof (entry as Record<string, unknown>).name === 'string') {
        labels.push((entry as Record<string, unknown>).name as string);
      }
    }
  }
  for (const name of labels) {
    if (!repo.labels.has(name)) {
      sendError(ctx.res, 422, `Label '${name}' does not exist`);
      return;
    }
  }
  const issue: Issue = {
    id: nextId(),
    number: repo.nextNumber++,
    title,
    body: typeof body.body === 'string' ? body.body : '',
    state: 'open',
    labels,
    comments: [],
  };
  repo.issues.set(issue.number, issue);
  sendJson(ctx.res, 201, issueJson(repo, issue));
}

function listIssues(ctx: Ctx, repo: Repo): void {
  const state = ctx.query.get('state') ?? 'open';
  const sort = ctx.query.get('sort') ?? 'created';
  const direction = ctx.query.get('direction') ?? (sort === 'created' ? 'desc' : 'desc');
  let items = [...repo.issues.values()];
  if (state === 'open') items = items.filter((issue) => issue.state === 'open');
  else if (state === 'closed') items = items.filter((issue) => issue.state === 'closed');
  if (sort === 'created') {
    items.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
  }
  const { page, link } = paginate(ctx, items.map((issue) => issueJson(repo, issue)));
  sendJson(ctx.res, 200, page, pageHeaders(link));
}

function getIssue(ctx: Ctx, repo: Repo, number: number): void {
  const issue = repo.issues.get(number);
  if (!issue) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  sendJson(ctx.res, 200, issueJson(repo, issue));
}

function patchIssue(ctx: Ctx, repo: Repo, number: number): void {
  const issue = repo.issues.get(number);
  if (!issue) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  let body: Record<string, unknown>;
  try {
    body = parseJsonBody(ctx);
  } catch {
    sendError(ctx.res, 400, 'Invalid JSON body');
    return;
  }
  if (typeof body.title === 'string') issue.title = body.title;
  if (typeof body.body === 'string') issue.body = body.body;
  if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
  sendJson(ctx.res, 200, issueJson(repo, issue));
}

function listComments(ctx: Ctx, repo: Repo, number: number): void {
  const issue = repo.issues.get(number);
  if (!issue) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  sendJson(ctx.res, 200, issue.comments.map((comment) => commentJson(repo, comment)));
}

function createComment(ctx: Ctx, repo: Repo, number: number): void {
  const issue = repo.issues.get(number);
  if (!issue) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  let body: Record<string, unknown>;
  try {
    body = parseJsonBody(ctx);
  } catch {
    sendError(ctx.res, 400, 'Invalid JSON body');
    return;
  }
  const commentBody = typeof body.body === 'string' ? body.body : '';
  if (commentBody === '') {
    sendError(ctx.res, 422, 'body is required');
    return;
  }
  const comment: IssueComment = { id: repo.nextCommentId++, body: commentBody };
  issue.comments.push(comment);
  sendJson(ctx.res, 201, commentJson(repo, comment));
}

function createPull(ctx: Ctx, repo: Repo): void {
  let body: Record<string, unknown>;
  try {
    body = parseJsonBody(ctx);
  } catch {
    sendError(ctx.res, 400, 'Invalid JSON body');
    return;
  }
  const title = typeof body.title === 'string' ? body.title : '';
  const head = typeof body.head === 'string' ? body.head : '';
  const base = typeof body.base === 'string' ? body.base : '';
  if (title === '' || head === '' || base === '') {
    sendError(ctx.res, 422, 'title, head and base are required');
    return;
  }
  const headSha = resolveRef(repo, head);
  const baseSha = resolveRef(repo, base);
  if (!headSha || !baseSha) {
    sendError(ctx.res, 422, 'head or base branch not found');
    return;
  }
  const baseOf = mergeBase(repo, headSha, baseSha);
  if (baseOf === null) {
    sendError(ctx.res, 422, 'No common ancestor between head and base');
    return;
  }
  const pull: Pull = {
    id: nextId(),
    number: repo.nextNumber++,
    title,
    body: typeof body.body === 'string' ? body.body : '',
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    headRef: head,
    baseRef: base,
    headSha,
    baseSha,
    mergeBase: baseOf,
  };
  repo.pulls.set(pull.number, pull);
  sendJson(ctx.res, 201, pullJson(repo, pull));
}

function listPulls(ctx: Ctx, repo: Repo): void {
  const state = ctx.query.get('state') ?? 'open';
  let items = [...repo.pulls.values()];
  if (state === 'open') items = items.filter((pull) => pull.state === 'open');
  else if (state === 'closed') items = items.filter((pull) => pull.state === 'closed');
  items.sort((a, b) => b.number - a.number);
  const { page, link } = paginate(ctx, items.map((pull) => pullJson(repo, pull)));
  sendJson(ctx.res, 200, page, pageHeaders(link));
}

function getPull(ctx: Ctx, repo: Repo, number: number): void {
  const pull = repo.pulls.get(number);
  if (!pull) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  sendJson(ctx.res, 200, pullJson(repo, pull));
}

function listPullFiles(ctx: Ctx, repo: Repo, number: number): void {
  const pull = repo.pulls.get(number);
  if (!pull) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  sendJson(ctx.res, 200, pullFiles(repo, pull));
}

function mergePull(ctx: Ctx, repo: Repo, number: number): void {
  const pull = repo.pulls.get(number);
  if (!pull) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  if (pull.state !== 'open') {
    sendError(ctx.res, 405, 'Pull request is already closed');
    return;
  }
  let body: Record<string, unknown> = {};
  try {
    body = parseJsonBody(ctx);
  } catch {
    sendError(ctx.res, 400, 'Invalid JSON body');
    return;
  }
  const method = typeof body.merge_method === 'string' ? body.merge_method : 'squash';
  if (method !== 'squash' && method !== 'merge' && method !== 'rebase') {
    sendError(ctx.res, 422, `Unknown merge method '${method}'`);
    return;
  }
  const sha = squashMerge(repo, pull);
  if (sha === null) {
    sendError(ctx.res, 405, 'Merge conflict');
    return;
  }
  repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = TRIAL_NOW_ISO;
  pull.mergeCommitSha = sha;
  sendJson(ctx.res, 200, { sha, merged: true, message: 'Pull request successfully merged' });
}

// ---------------------------------------------------------------------------------------------
// REST router
// ---------------------------------------------------------------------------------------------

function routeRest(ctx: Ctx): void {
  // segments keep the leading '' from path.split('/'): ['', 'api', 'v3', ...rest]
  const segments = ctx.segments.slice(3);
  const method = ctx.method;

  if (segments.length === 0 || segments[0] === '') {
    if (method === 'GET') {
      sendJson(ctx.res, 200, {
        current_user_url: '/api/v3/user',
        repository_url: '/api/v3/repos/{owner}/{repo}',
        user_repositories_url: '/api/v3/user/repos',
        meta_url: '/api/v3/meta',
      });
      return;
    }
    sendError(ctx.res, 404, 'Not Found');
    return;
  }

  if (segments[0] === 'meta' && segments.length === 1) {
    if (method === 'GET') {
      sendJson(ctx.res, 200, { installed_version: '1.0.0', forge: 'github-core-clone-01' });
      return;
    }
    sendError(ctx.res, 404, 'Not Found');
    return;
  }

  if (segments[0] === 'user') {
    if (segments.length === 1 && method === 'GET') {
      sendJson(ctx.res, 200, {
        login: VIEWER_LOGIN,
        id: VIEWER_ID,
        node_id: globalId('User', VIEWER_ID),
        name: VIEWER_NAME,
        email: VIEWER_EMAIL,
        type: 'User',
      });
      return;
    }
    if (segments.length === 2 && segments[1] === 'repos') {
      if (method === 'GET') {
        listUserRepos(ctx);
        return;
      }
      if (method === 'POST') {
        createUserRepo(ctx);
        return;
      }
    }
    sendError(ctx.res, 404, 'Not Found');
    return;
  }

  if (segments[0] === 'repos' && segments.length >= 3) {
    const owner = decodeSegment(segments[1]!);
    const name = decodeSegment(segments[2]!);
    const repo = lookupRepo(owner, name);
    const rest = segments.slice(3);
    if (rest.length === 0) {
      if (method === 'GET') {
        getRepo(ctx, owner, name);
        return;
      }
      if (method === 'PATCH') {
        patchRepo(ctx, owner, name);
        return;
      }
      if (method === 'DELETE') {
        deleteRepo(ctx, owner, name);
        return;
      }
      sendError(ctx.res, 404, 'Not Found');
      return;
    }
    if (!repo) {
      sendError(ctx.res, 404, 'Not Found');
      return;
    }
    if (rest[0] === 'branches') {
      if (rest.length === 1 && method === 'GET') {
        listBranches(ctx, repo);
        return;
      }
      if (rest.length === 2 && method === 'GET') {
        getBranch(ctx, repo, decodeSegment(rest[1]!));
        return;
      }
      sendError(ctx.res, 404, 'Not Found');
      return;
    }
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (rest.length === 2 && method === 'POST') {
        createRef(ctx, repo);
        return;
      }
      if (rest.length === 4 && rest[2] === 'heads' && method === 'GET') {
        getRef(ctx, repo, `refs/heads/${decodeSegment(rest[3]!)}`);
        return;
      }
      sendError(ctx.res, 404, 'Not Found');
      return;
    }
    if (rest[0] === 'commits') {
      if (rest.length === 1 && method === 'GET') {
        listCommits(ctx, repo);
        return;
      }
      sendError(ctx.res, 404, 'Not Found');
      return;
    }
    if (rest[0] === 'contents') {
      const filePath = rest.slice(1).map(decodeSegment).join('/');
      if (method === 'GET') {
        getContents(ctx, repo, filePath);
        return;
      }
      if (method === 'PUT') {
        putContents(ctx, repo, filePath);
        return;
      }
      if (method === 'DELETE') {
        deleteContents(ctx, repo, filePath);
        return;
      }
      sendError(ctx.res, 404, 'Not Found');
      return;
    }
    if (rest[0] === 'labels') {
      if (rest.length === 1 && method === 'POST') {
        createLabel(ctx, repo);
        return;
      }
      sendError(ctx.res, 404, 'Not Found');
      return;
    }
    if (rest[0] === 'issues') {
      if (rest.length === 1 && method === 'GET') {
        listIssues(ctx, repo);
        return;
      }
      if (rest.length === 1 && method === 'POST') {
        createIssue(ctx, repo);
        return;
      }
      const number = Number.parseInt(rest[1] ?? '', 10);
      if (Number.isFinite(number) && rest.length === 2) {
        if (method === 'GET') {
          getIssue(ctx, repo, number);
          return;
        }
        if (method === 'PATCH') {
          patchIssue(ctx, repo, number);
          return;
        }
      }
      if (Number.isFinite(number) && rest.length === 3 && rest[2] === 'comments') {
        if (method === 'GET') {
          listComments(ctx, repo, number);
          return;
        }
        if (method === 'POST') {
          createComment(ctx, repo, number);
          return;
        }
      }
      sendError(ctx.res, 404, 'Not Found');
      return;
    }
    if (rest[0] === 'pulls') {
      if (rest.length === 1 && method === 'GET') {
        listPulls(ctx, repo);
        return;
      }
      if (rest.length === 1 && method === 'POST') {
        createPull(ctx, repo);
        return;
      }
      const number = Number.parseInt(rest[1] ?? '', 10);
      if (Number.isFinite(number) && rest.length === 2 && method === 'GET') {
        getPull(ctx, repo, number);
        return;
      }
      if (Number.isFinite(number) && rest.length === 3 && rest[2] === 'files' && method === 'GET') {
        listPullFiles(ctx, repo, number);
        return;
      }
      if (Number.isFinite(number) && rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
        mergePull(ctx, repo, number);
        return;
      }
      sendError(ctx.res, 404, 'Not Found');
      return;
    }
    sendError(ctx.res, 404, 'Not Found');
    return;
  }

  sendError(ctx.res, 404, 'Not Found');
}

// ---------------------------------------------------------------------------------------------
// Git smart HTTP
// ---------------------------------------------------------------------------------------------

const UPLOAD_PACK_CAPS_V0 =
  'multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed symref=HEAD:refs/heads/main object-format=sha1 agent=github-core-clone-01-forge/1.0.0';
const RECEIVE_PACK_CAPS_V0 =
  'report-status side-band-64k delete-refs ofs-delta quiet atomic symref=HEAD:refs/heads/main object-format=sha1 agent=github-core-clone-01-forge/1.0.0';

function sendRaw(res: ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': `forge-${++requestCounter}`,
  });
  res.end(body);
}

/** All refs of a repo, HEAD first, then sorted; values are commit oids. */
function advertisedRefs(repo: Repo): Array<{ name: string; oid: string; peeled?: string }> {
  const refs: Array<{ name: string; oid: string; peeled?: string }> = [];
  const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (tip) refs.push({ name: 'HEAD', oid: tip });
  const names = [...repo.refs.keys()].sort();
  for (const name of names) {
    const oid = repo.refs.get(name)!;
    const entry: { name: string; oid: string; peeled?: string } = { name, oid };
    const object = repo.objects.get(oid);
    if (object?.type === 'tag') entry.peeled = peelTag(repo, oid);
    refs.push(entry);
  }
  return refs;
}

function advertisementV0(repo: Repo, service: string, capabilities: string): Buffer {
  const refs = advertisedRefs(repo);
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), pktFlush()];
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\u0000${capabilities}\n`));
  } else {
    refs.forEach((ref, index) => {
      const caps = index === 0 ? `\u0000${capabilities}` : '';
      parts.push(pktLine(`${ref.oid} ${ref.name}${caps}\n`));
    });
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

function advertisementV2(): Buffer {
  return pktLines([
    'version 2\n',
    'agent=github-core-clone-01-forge/1.0.0\n',
    'ls-refs=unborn\n',
    'fetch=shallow wait-for-done\n',
    'object-format=sha1\n',
    'object-info\n',
    'server-option\n',
    'flush',
  ]);
}

/** The send set for a fetch: commits to send, the pack objects, and shallow/unshallow lines. */
function computeSendSet(
  repo: Repo,
  wants: readonly string[],
  haves: readonly string[],
  shallowSet: ReadonlySet<string>,
  depth: number,
): { commits: Set<string>; objects: Map<string, GitObject>; shallow: string[]; unshallow: string[] } {
  const wantedTags: string[] = [];
  const wantedCommits: string[] = [];
  for (const want of wants) {
    const object = repo.objects.get(want);
    if (!object) continue;
    if (object.type === 'tag') {
      wantedTags.push(want);
      wantedCommits.push(peelTag(repo, want));
    } else if (object.type === 'commit') {
      wantedCommits.push(want);
    }
  }
  // Walk from the wants, following parents, limited to `depth` generations (0 = unlimited).
  const wanted = new Set<string>();
  const queue: Array<{ oid: string; distance: number }> = wantedCommits.map((oid) => ({ oid, distance: 0 }));
  while (queue.length > 0) {
    const { oid, distance } = queue.pop()!;
    if (wanted.has(oid)) continue;
    const view = commitView(repo, oid);
    if (!view) continue;
    wanted.add(oid);
    if (depth === 0 || distance + 1 < depth) {
      for (const parent of view.parents) queue.push({ oid: parent, distance: distance + 1 });
    }
  }
  // Walk from the haves, stopping at shallow boundaries (their parents stay unknown to the client).
  const haveSet = new Set<string>();
  const haveQueue = [...haves];
  while (haveQueue.length > 0) {
    const oid = haveQueue.pop()!;
    if (haveSet.has(oid)) continue;
    const view = commitView(repo, oid);
    if (!view) continue;
    haveSet.add(oid);
    if (shallowSet.has(oid)) continue;
    for (const parent of view.parents) haveQueue.push(parent);
  }
  const commits = new Set<string>();
  for (const oid of wanted) if (!haveSet.has(oid)) commits.add(oid);
  // Pack objects: the sent commits plus everything under their trees (not their parents).
  const objects = new Map<string, GitObject>();
  const addObject = (oid: string): void => {
    const object = repo.objects.get(oid);
    if (object && !objects.has(oid)) objects.set(oid, object);
  };
  for (const tagOid of wantedTags) addObject(tagOid);
  for (const oid of commits) {
    addObject(oid);
    const view = commitView(repo, oid);
    if (!view) continue;
    for (const treeOid of collectReachable([view.tree], (candidate) => repo.objects.get(candidate))) {
      addObject(treeOid);
    }
  }
  // Shallow: a sent commit with a parent the client will not have after this fetch.
  const shallow: string[] = [];
  for (const oid of [...commits].sort()) {
    const view = commitView(repo, oid);
    if (!view || view.parents.length === 0) continue;
    if (view.parents.some((parent) => !commits.has(parent) && !haveSet.has(parent))) shallow.push(oid);
  }
  // Unshallow: a previously shallow commit whose parents are all present now.
  const unshallow: string[] = [];
  for (const oid of [...shallowSet].sort()) {
    const view = commitView(repo, oid);
    if (!view || view.parents.length === 0) continue;
    if (view.parents.every((parent) => commits.has(parent) || haveSet.has(parent))) unshallow.push(oid);
  }
  return { commits, objects, shallow, unshallow };
}

/** Split a packfile into sideband band-1 pkt-lines, terminated by a flush. */
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 65500;
  for (let offset = 0; offset < pack.length; offset += CHUNK) {
    const chunk = pack.subarray(offset, Math.min(pack.length, offset + CHUNK));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

function respondFetchV2(ctx: Ctx, repo: Repo, args: readonly string[]): void {
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow = new Set<string>();
  let depth = 0;
  for (const arg of args) {
    const [key, value] = arg.split(' ');
    if (key === 'want' && value) wants.push(value);
    else if (key === 'have' && value) haves.push(value);
    else if (key === 'shallow' && value) shallow.add(value);
    else if (key === 'deepen' && value) depth = Number.parseInt(value, 10) || 0;
  }
  const { objects, shallow: shallowLines, unshallow: unshallowLines } = computeSendSet(repo, wants, haves, shallow, depth);
  const pack = writePack(objects.values());
  const parts: Buffer[] = [pktLine('acknowledgments\n'), pktLine('NAK\n'), pktDelim()];
  parts.push(pktLine('shallow-info\n'));
  for (const oid of shallowLines) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of unshallowLines) parts.push(pktLine(`unshallow ${oid}\n`));
  parts.push(pktDelim());
  parts.push(pktLine('packfile\n'));
  parts.push(sidebandPack(pack));
  sendRaw(ctx.res, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
}

function respondFetchV0(ctx: Ctx, repo: Repo): void {
  const { packets, offset } = decodePktLines(ctx.body);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow = new Set<string>();
  let depth = 0;
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').trim();
    const nul = line.indexOf('\u0000');
    const clean = nul >= 0 ? line.slice(0, nul) : line;
    const [key, value] = clean.split(' ');
    if (key === 'want' && value) wants.push(value);
    else if (key === 'have' && value) haves.push(value);
    else if (key === 'shallow' && value) shallow.add(value);
    else if (key === 'deepen' && value) depth = Number.parseInt(value, 10) || 0;
  }
  void offset;
  const { objects } = computeSendSet(repo, wants, haves, shallow, depth);
  const pack = writePack(objects.values());
  sendRaw(ctx.res, 200, 'application/x-git-upload-pack-result', Buffer.concat([pktLine('NAK\n'), sidebandPack(pack)]));
}

function handleUploadPack(ctx: Ctx, repo: Repo): void {
  const protocol = (ctx.req.headers['git-protocol'] ?? '').toString();
  if (protocol === 'version=2') {
    const { packets } = decodePktLines(ctx.body);
    let command = '';
    const args: string[] = [];
    let afterDelim = false;
    for (const packet of packets) {
      if (packet.kind === 'data') {
        const line = packet.payload.toString('utf8');
        if (line.startsWith('command=')) command = line.slice(8).trim();
        else if (afterDelim) args.push(line.trim());
      } else if (packet.kind === 'delim') {
        afterDelim = true;
      } else if (packet.kind === 'flush') {
        break;
      }
    }
    if (command === 'ls-refs') {
      const peel = args.includes('peel');
      const symrefs = args.includes('symrefs');
      const unborn = args.includes('unborn');
      const prefixes = args.filter((arg) => arg.startsWith('ref-prefix ')).map((arg) => arg.slice('ref-prefix '.length));
      const matches = (name: string): boolean =>
        prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
      const lines: Buffer[] = [];
      const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      if (tip) {
        if (matches('HEAD')) {
          const attrs = symrefs ? ' symref-target:refs/heads/main' : '';
          lines.push(pktLine(`${tip} HEAD${attrs}\n`));
        }
        for (const name of [...repo.refs.keys()].sort()) {
          if (!matches(name)) continue;
          const oid = repo.refs.get(name)!;
          let line = `${oid} ${name}`;
          if (peel) {
            const object = repo.objects.get(oid);
            if (object?.type === 'tag') line += ` peeled:${peelTag(repo, oid)}`;
          }
          lines.push(pktLine(`${line}\n`));
        }
      } else if (unborn) {
        if (matches('HEAD')) {
          const attrs = symrefs ? ' symref-target:refs/heads/main' : '';
          lines.push(pktLine(`unborn HEAD${attrs}\n`));
        }
      }
      lines.push(pktFlush());
      sendRaw(ctx.res, 200, 'application/x-git-upload-pack-result', Buffer.concat(lines));
      return;
    }
    if (command === 'fetch') {
      respondFetchV2(ctx, repo, args);
      return;
    }
    sendError(ctx.res, 400, `Unknown command '${command}'`);
    return;
  }
  respondFetchV0(ctx, repo);
}

interface PushCommand {
  old: string;
  next: string;
  ref: string;
}

function handleReceivePack(ctx: Ctx, repo: Repo): void {
  const { packets, offset } = decodePktLines(ctx.body);
  const commands: PushCommand[] = [];
  for (const packet of packets) {
    if (packet.kind === 'flush') break;
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8');
    const nul = line.indexOf('\u0000');
    const clean = (nul >= 0 ? line.slice(0, nul) : line).trim();
    const parts = clean.split(' ');
    if (parts.length >= 3 && isOid(parts[0]!) && isOid(parts[1]!)) {
      commands.push({ old: parts[0]!, next: parts[1]!, ref: parts.slice(2).join(' ') });
    }
  }
  const results: Array<{ ref: string; ok: boolean; reason?: string }> = [];
  let unpackOk = true;
  let unpackError = '';
  // Unpack first: a refused push still keeps its objects.
  const packBytes = ctx.body.subarray(offset);
  if (packBytes.length > 0) {
    try {
      const objects = readPack(packBytes, (oid) => repo.objects.get(oid));
      for (const [oid, object] of objects) {
        if (!repo.objects.has(oid)) {
          repo.objects.set(oid, object);
          if (object.type === 'commit') repo.commitMeta.set(oid, parseCommit(object.data));
        }
      }
    } catch (err) {
      unpackOk = false;
      unpackError = err instanceof Error ? err.message : 'unpack failed';
    }
  }
  for (const command of commands) {
    if (!unpackOk) {
      results.push({ ref: command.ref, ok: false, reason: 'unpack failed' });
      continue;
    }
    const current = repo.refs.get(command.ref);
    if (command.next === ZERO_OID) {
      // Delete.
      if (current === undefined) {
        results.push({ ref: command.ref, ok: false, reason: 'remote ref does not exist' });
      } else {
        repo.refs.delete(command.ref);
        results.push({ ref: command.ref, ok: true });
      }
      continue;
    }
    if (command.old === ZERO_OID) {
      // Create.
      if (current !== undefined) {
        results.push({ ref: command.ref, ok: false, reason: 'already exists' });
      } else if (!repo.objects.has(command.next)) {
        results.push({ ref: command.ref, ok: false, reason: 'object not found' });
      } else {
        repo.refs.set(command.ref, command.next);
        results.push({ ref: command.ref, ok: true });
      }
      continue;
    }
    // Update: fast-forward only.
    if (current === undefined) {
      results.push({ ref: command.ref, ok: false, reason: 'remote ref does not exist' });
    } else if (current !== command.old) {
      results.push({ ref: command.ref, ok: false, reason: 'stale info' });
    } else if (command.next === command.old) {
      results.push({ ref: command.ref, ok: true });
    } else if (!repo.objects.has(command.next)) {
      results.push({ ref: command.ref, ok: false, reason: 'object not found' });
    } else if (!isAncestor(repo, command.old, command.next)) {
      results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
    } else {
      repo.refs.set(command.ref, command.next);
      results.push({ ref: command.ref, ok: true });
    }
  }
  const lines: string[] = [];
  lines.push(unpackOk ? 'unpack ok\n' : `unpack error ${unpackError}\n`);
  for (const result of results) {
    lines.push(result.ok ? `ok ${result.ref}\n` : `ng ${result.ref} ${result.reason ?? 'failed'}\n`);
  }
  const parts: Buffer[] = [];
  for (const line of lines) parts.push(pktLine(Buffer.concat([Buffer.from([1]), Buffer.from(line, 'utf8')])));
  parts.push(pktFlush());
  sendRaw(ctx.res, 200, 'application/x-git-receive-pack-result', Buffer.concat(parts));
}

function routeGit(ctx: Ctx): void {
  const segments = ctx.segments;
  if (segments.length < 3) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  const owner = decodeSegment(segments[1]!);
  const repoSegment = decodeSegment(segments[2]!);
  if (!repoSegment.endsWith('.git')) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  const name = repoSegment.slice(0, -'.git'.length);
  const repo = lookupRepo(owner, name);
  if (!repo) {
    sendError(ctx.res, 404, 'Not Found');
    return;
  }
  const rest = segments.slice(3);
  if (rest.length === 2 && rest[0] === 'info' && rest[1] === 'refs' && ctx.method === 'GET') {
    const service = ctx.query.get('service') ?? '';
    if (service === 'git-upload-pack') {
      const protocol = (ctx.req.headers['git-protocol'] ?? '').toString();
      if (protocol === 'version=2') {
        sendRaw(ctx.res, 200, 'application/x-git-upload-pack-advertisement', advertisementV2());
      } else {
        sendRaw(ctx.res, 200, 'application/x-git-upload-pack-advertisement', advertisementV0(repo, 'git-upload-pack', UPLOAD_PACK_CAPS_V0));
      }
      return;
    }
    if (service === 'git-receive-pack') {
      sendRaw(ctx.res, 200, 'application/x-git-receive-pack-advertisement', advertisementV0(repo, 'git-receive-pack', RECEIVE_PACK_CAPS_V0));
      return;
    }
    sendError(ctx.res, 400, 'service is required');
    return;
  }
  if (rest.length === 1 && rest[0] === 'git-upload-pack' && ctx.method === 'POST') {
    if (ctx.body.length > 0 && !/^[0-9a-f]{4}/.test(ctx.body.subarray(0, 4).toString('ascii'))) {
      sendError(ctx.res, 400, 'Malformed request');
      return;
    }
    handleUploadPack(ctx, repo);
    return;
  }
  if (rest.length === 1 && rest[0] === 'git-receive-pack' && ctx.method === 'POST') {
    handleReceivePack(ctx, repo);
    return;
  }
  sendError(ctx.res, 404, 'Not Found');
}

// ---------------------------------------------------------------------------------------------
// GraphQL: a small parser for the documents the suite sends
// ---------------------------------------------------------------------------------------------

type GqlValueNode =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: GqlValueNode[] }
  | { kind: 'object'; fields: Array<{ name: string; value: GqlValueNode }> };

interface GqlFieldSelection {
  kind: 'field';
  name: string;
  alias: string | null;
  args: Array<{ name: string; value: GqlValueNode }>;
  directives: Array<{ name: string; args: Array<{ name: string; value: GqlValueNode }> }>;
  selectionSet: GqlSelection[] | null;
}

interface GqlInlineFragment {
  kind: 'inlineFragment';
  typeCondition: string | null;
  selectionSet: GqlSelection[];
}

interface GqlFragmentSpread {
  kind: 'fragmentSpread';
  name: string;
}

type GqlSelection = GqlFieldSelection | GqlInlineFragment | GqlFragmentSpread;

interface GqlOperation {
  kind: 'operation';
  operation: 'query' | 'mutation';
  name: string | null;
  variables: Array<{ name: string; defaultValue: GqlValueNode | null }>;
  selectionSet: GqlSelection[];
}

interface GqlFragment {
  kind: 'fragment';
  name: string;
  typeCondition: string;
  selectionSet: GqlSelection[];
}

interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, GqlFragment>;
}

interface GqlToken {
  kind: 'name' | 'string' | 'int' | 'float' | 'punct' | 'spread' | 'variable';
  value: string;
}

function tokenizeGraphql(source: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let index = 0;
  while (index < source.length) {
    const char = source[index]!;
    if (char === ' ' || char === '\t' || char === '\n' || char === '\r' || char === ',') {
      index += 1;
      continue;
    }
    if (char === '#') {
      while (index < source.length && source[index] !== '\n') index += 1;
      continue;
    }
    if (char === '.' && source.slice(index, index + 3) === '...') {
      tokens.push({ kind: 'spread', value: '...' });
      index += 3;
      continue;
    }
    if (char === '$') {
      const match = /^\$[_A-Za-z][_0-9A-Za-z]*/.exec(source.slice(index));
      if (!match) throw new Error(`Invalid variable at offset ${index}`);
      tokens.push({ kind: 'variable', value: match[0].slice(1) });
      index += match[0].length;
      continue;
    }
    if (char === '"') {
      let value = '';
      index += 1;
      while (index < source.length && source[index] !== '"') {
        if (source[index] === '\\' && index + 1 < source.length) {
          const escaped = source[index + 1]!;
          value += escaped === 'n' ? '\n' : escaped === 't' ? '\t' : escaped === 'r' ? '\r' : escaped;
          index += 2;
        } else {
          value += source[index];
          index += 1;
        }
      }
      if (index >= source.length) throw new Error('Unterminated string');
      index += 1;
      tokens.push({ kind: 'string', value });
      continue;
    }
    if (/[0-9-]/.test(char)) {
      const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(index));
      if (!match) throw new Error(`Invalid number at offset ${index}`);
      const text = match[0];
      tokens.push({ kind: text.includes('.') || /[eE]/.test(text) ? 'float' : 'int', value: text });
      index += text.length;
      continue;
    }
    if (/[_A-Za-z]/.test(char)) {
      const match = /^[_A-Za-z][_0-9A-Za-z]*/.exec(source.slice(index));
      tokens.push({ kind: 'name', value: match![0] });
      index += match![0].length;
      continue;
    }
    if ('{}()[]:!@='.includes(char)) {
      tokens.push({ kind: 'punct', value: char });
      index += 1;
      continue;
    }
    throw new Error(`Unexpected character '${char}' at offset ${index}`);
  }
  return tokens;
}

class GqlParser {
  private tokens: GqlToken[];
  private position = 0;

  constructor(source: string) {
    this.tokens = tokenizeGraphql(source);
  }

  private peek(): GqlToken | null {
    return this.tokens[this.position] ?? null;
  }

  private next(): GqlToken {
    const token = this.tokens[this.position];
    if (!token) throw new Error('Unexpected end of document');
    this.position += 1;
    return token;
  }

  private expectPunct(value: string): void {
    const token = this.next();
    if (token.kind !== 'punct' || token.value !== value) throw new Error(`Expected '${value}' but got '${token.value}'`);
  }

  private expectName(value?: string): string {
    const token = this.next();
    if (token.kind !== 'name') throw new Error(`Expected a name but got '${token.value}'`);
    if (value !== undefined && token.value !== value) throw new Error(`Expected '${value}' but got '${token.value}'`);
    return token.value;
  }

  private isPunct(value: string): boolean {
    const token = this.peek();
    return token !== null && token.kind === 'punct' && token.value === value;
  }

  private isName(value: string): boolean {
    const token = this.peek();
    return token !== null && token.kind === 'name' && token.value === value;
  }

  parseDocument(): GqlDocument {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, GqlFragment>();
    while (this.peek() !== null) {
      if (this.isName('fragment')) {
        const fragment = this.parseFragment();
        fragments.set(fragment.name, fragment);
      } else {
        operations.push(this.parseOperation());
      }
    }
    return { operations, fragments };
  }

  private parseOperation(): GqlOperation {
    let operation: 'query' | 'mutation' = 'query';
    let name: string | null = null;
    if (this.isPunct('{')) {
      return { kind: 'operation', operation, name, variables: [], selectionSet: this.parseSelectionSet() };
    }
    const keyword = this.expectName();
    if (keyword === 'query' || keyword === 'mutation') operation = keyword;
    else throw new Error(`Unsupported operation type '${keyword}'`);
    const token = this.peek();
    if (token !== null && token.kind === 'name') name = this.next().value;
    const variables = this.isPunct('(') ? this.parseVariableDefinitions() : [];
    this.parseDirectives();
    return { kind: 'operation', operation, name, variables, selectionSet: this.parseSelectionSet() };
  }

  private parseVariableDefinitions(): Array<{ name: string; defaultValue: GqlValueNode | null }> {
    const variables: Array<{ name: string; defaultValue: GqlValueNode | null }> = [];
    this.expectPunct('(');
    while (!this.isPunct(')')) {
      const variable = this.next();
      if (variable.kind !== 'variable') throw new Error('Expected a variable definition');
      this.expectPunct(':');
      this.parseTypeName();
      let defaultValue: GqlValueNode | null = null;
      if (this.isPunct('=')) {
        this.next();
        defaultValue = this.parseValue();
      }
      variables.push({ name: variable.value, defaultValue });
    }
    this.expectPunct(')');
    return variables;
  }

  private parseTypeName(): void {
    if (this.isPunct('[')) {
      this.next();
      this.parseTypeName();
      this.expectPunct(']');
    } else {
      this.expectName();
    }
    if (this.isPunct('!')) this.next();
  }

  private parseFragment(): GqlFragment {
    this.expectName('fragment');
    const name = this.expectName();
    this.expectName('on');
    const typeCondition = this.expectName();
    this.parseDirectives();
    return { kind: 'fragment', name, typeCondition, selectionSet: this.parseSelectionSet() };
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const selections: GqlSelection[] = [];
    while (!this.isPunct('}')) {
      selections.push(this.parseSelection());
    }
    this.expectPunct('}');
    return selections;
  }

  private parseSelection(): GqlSelection {
    if (this.peek()?.kind === 'spread') {
      this.next();
      const token = this.peek();
      if (token !== null && token.kind === 'name' && token.value === 'on') {
        this.next();
        const typeCondition = this.expectName();
        this.parseDirectives();
        return { kind: 'inlineFragment', typeCondition, selectionSet: this.parseSelectionSet() };
      }
      if (token !== null && token.kind === 'name') {
        const name = this.next().value;
        this.parseDirectives();
        return { kind: 'fragmentSpread', name };
      }
      this.parseDirectives();
      return { kind: 'inlineFragment', typeCondition: null, selectionSet: this.parseSelectionSet() };
    }
    const first = this.expectName();
    let name = first;
    let alias: string | null = null;
    if (this.isPunct(':')) {
      this.next();
      alias = first;
      name = this.expectName();
    }
    const args = this.isPunct('(') ? this.parseArguments() : [];
    const directives = this.parseDirectives();
    const selectionSet = this.isPunct('{') ? this.parseSelectionSet() : null;
    return { kind: 'field', name, alias, args, directives, selectionSet };
  }

  private parseArguments(): Array<{ name: string; value: GqlValueNode }> {
    const args: Array<{ name: string; value: GqlValueNode }> = [];
    this.expectPunct('(');
    while (!this.isPunct(')')) {
      const name = this.expectName();
      this.expectPunct(':');
      args.push({ name, value: this.parseValue() });
    }
    this.expectPunct(')');
    return args;
  }

  private parseDirectives(): Array<{ name: string; args: Array<{ name: string; value: GqlValueNode }> }> {
    const directives: Array<{ name: string; args: Array<{ name: string; value: GqlValueNode }> }> = [];
    while (this.isPunct('@')) {
      this.next();
      const name = this.expectName();
      const args = this.isPunct('(') ? this.parseArguments() : [];
      directives.push({ name, args });
    }
    return directives;
  }

  private parseValue(): GqlValueNode {
    const token = this.next();
    if (token.kind === 'variable') return { kind: 'variable', name: token.value };
    if (token.kind === 'string') return { kind: 'string', value: token.value };
    if (token.kind === 'int') return { kind: 'int', value: Number.parseInt(token.value, 10) };
    if (token.kind === 'float') return { kind: 'float', value: Number.parseFloat(token.value) };
    if (token.kind === 'name') {
      if (token.value === 'true') return { kind: 'boolean', value: true };
      if (token.value === 'false') return { kind: 'boolean', value: false };
      if (token.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: token.value };
    }
    if (token.kind === 'punct' && token.value === '[') {
      const values: GqlValueNode[] = [];
      while (!this.isPunct(']')) values.push(this.parseValue());
      this.expectPunct(']');
      return { kind: 'list', values };
    }
    if (token.kind === 'punct' && token.value === '{') {
      const fields: Array<{ name: string; value: GqlValueNode }> = [];
      while (!this.isPunct('}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields.push({ name, value: this.parseValue() });
      }
      this.expectPunct('}');
      return { kind: 'object', fields };
    }
    throw new Error(`Unexpected value token '${token.value}'`);
  }
}

function parseGraphql(source: string): GqlDocument {
  return new GqlParser(source).parseDocument();
}

// ---------------------------------------------------------------------------------------------
// GraphQL: introspection tables
// ---------------------------------------------------------------------------------------------

const INTROSPECTION_TYPES: Record<
  string,
  { kind: 'OBJECT' | 'ENUM' | 'INTERFACE'; fields?: string[]; enumValues?: string[] }
> = {
  Query: { kind: 'OBJECT', fields: ['viewer', 'repository', 'node', 'search', '__type', '__schema'] },
  Mutation: { kind: 'OBJECT', fields: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'] },
  Repository: {
    kind: 'OBJECT',
    fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'description', 'url', 'createdAt', 'updatedAt'],
  },
  Issue: {
    kind: 'OBJECT',
    fields: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'url', 'author', 'repository', 'comments', 'createdAt', 'updatedAt'],
  },
  PullRequest: {
    kind: 'OBJECT',
    fields: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'files', 'repository', 'author', 'createdAt', 'updatedAt', 'mergedAt', 'mergeCommit'],
  },
  User: { kind: 'OBJECT', fields: ['id', 'databaseId', 'login', 'name', 'email'] },
  Ref: { kind: 'OBJECT', fields: ['name', 'target'] },
  GitObject: { kind: 'OBJECT', fields: ['oid'] },
  IssueConnection: { kind: 'OBJECT', fields: ['nodes', 'edges', 'pageInfo', 'totalCount'] },
  IssueEdge: { kind: 'OBJECT', fields: ['node', 'cursor'] },
  PullRequestConnection: { kind: 'OBJECT', fields: ['nodes', 'edges', 'pageInfo', 'totalCount'] },
  PullRequestEdge: { kind: 'OBJECT', fields: ['node', 'cursor'] },
  IssueCommentConnection: { kind: 'OBJECT', fields: ['nodes', 'edges', 'pageInfo', 'totalCount'] },
  IssueCommentEdge: { kind: 'OBJECT', fields: ['node', 'cursor'] },
  PullRequestChangedFileConnection: { kind: 'OBJECT', fields: ['nodes', 'edges', 'pageInfo', 'totalCount'] },
  PullRequestChangedFileEdge: { kind: 'OBJECT', fields: ['node', 'cursor'] },
  PageInfo: { kind: 'OBJECT', fields: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'] },
  IssueComment: { kind: 'OBJECT', fields: ['id', 'databaseId', 'body', 'author', 'createdAt', 'updatedAt'] },
  PullRequestChangedFile: { kind: 'OBJECT', fields: ['path', 'additions', 'deletions', 'changes'] },
  Node: { kind: 'INTERFACE', fields: ['id'] },
  SearchType: { kind: 'ENUM', enumValues: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE', 'MILESTONE', 'LABEL', 'ORGANIZATION'] },
  IssueState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED'] },
  PullRequestState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED', 'MERGED'] },
  MergeableState: { kind: 'ENUM', enumValues: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'] },
  RepositoryPermission: { kind: 'ENUM', enumValues: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'] },
};

// ---------------------------------------------------------------------------------------------
// GraphQL: executor
// ---------------------------------------------------------------------------------------------

const SCALAR_TYPES = new Set(['String', 'Int', 'Float', 'Boolean', 'ID']);
const ENUM_TYPES = new Set(['IssueState', 'PullRequestState', 'MergeableState', 'RepositoryPermission', 'SearchType', 'IssueOrderField', 'OrderDirection']);

interface GqlRuntime {
  __typename: string;
  [key: string]: unknown;
}

function gqlObject(typename: string, fields: Record<string, unknown>): GqlRuntime {
  return { __typename: typename, ...fields };
}

function evalGqlValue(node: GqlValueNode, variables: Record<string, unknown>): unknown {
  switch (node.kind) {
    case 'variable': {
      const value = variables[node.name];
      return value === undefined ? null : value;
    }
    case 'string':
      return node.value;
    case 'int':
    case 'float':
      return node.value;
    case 'boolean':
      return node.value;
    case 'null':
      return null;
    case 'enum':
      return node.value;
    case 'list':
      return node.values.map((child) => evalGqlValue(child, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of node.fields) out[field.name] = evalGqlValue(field.value, variables);
      return out;
    }
  }
}

function evalGqlArgs(args: Array<{ name: string; value: GqlValueNode }>, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const arg of args) out[arg.name] = evalGqlValue(arg.value, variables);
  return out;
}

function directiveSkip(directives: Array<{ name: string; args: Array<{ name: string; value: GqlValueNode }> }>, variables: Record<string, unknown>): boolean {
  for (const directive of directives) {
    const args = evalGqlArgs(directive.args, variables);
    if (directive.name === 'skip' && args.if === true) return true;
    if (directive.name === 'include' && args.if === false) return true;
  }
  return false;
}

function viewerUserObj(): GqlRuntime {
  return gqlObject('User', { login: VIEWER_LOGIN, id: VIEWER_ID, databaseId: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL });
}

function repoObj(repo: Repo): GqlRuntime {
  return gqlObject('Repository', { _repo: repo });
}

function issueObj(repo: Repo, issue: Issue): GqlRuntime {
  return gqlObject('Issue', { _repo: repo, _issue: issue });
}

function pullObj(repo: Repo, pull: Pull): GqlRuntime {
  return gqlObject('PullRequest', { _repo: repo, _pull: pull });
}

function commentObj(repo: Repo, comment: IssueComment): GqlRuntime {
  return gqlObject('IssueComment', { _repo: repo, _comment: comment });
}

function cursorFor(index: number): string {
  return b64url(`cursor:${index}`);
}

function indexFromCursor(cursor: unknown): number {
  if (typeof cursor !== 'string') return -1;
  const text = unb64url(cursor);
  const match = /^cursor:(\d+)$/.exec(text);
  return match ? Number.parseInt(match[1]!, 10) : -1;
}

interface PageArgs {
  first?: number;
  after?: string | null;
}

function paginateGql<T>(items: readonly T[], args: PageArgs): { page: T[]; hasNextPage: boolean; startCursor: string | null; endCursor: string | null; startIndex: number } {
  const first = typeof args.first === 'number' && args.first > 0 ? Math.min(args.first, 100) : 30;
  const afterIndex = indexFromCursor(args.after ?? null);
  const startIndex = afterIndex + 1;
  const page = items.slice(startIndex, startIndex + first);
  const hasNextPage = startIndex + first < items.length;
  const startCursor = page.length > 0 ? cursorFor(startIndex) : null;
  const endCursor = page.length > 0 ? cursorFor(startIndex + page.length - 1) : null;
  return { page, hasNextPage, startCursor, endCursor, startIndex };
}

function connectionObj<T>(typename: string, edgeTypename: string, items: readonly T[], toNode: (item: T) => GqlRuntime, args: PageArgs): GqlRuntime {
  const { page, hasNextPage, startCursor, endCursor, startIndex } = paginateGql(items, args);
  const edges = page.map((item, offset) => gqlObject(edgeTypename, { node: toNode(item), cursor: cursorFor(startIndex + offset) }));
  return gqlObject(typename, {
    nodes: page.map((item) => toNode(item)),
    edges,
    pageInfo: gqlObject('PageInfo', { hasNextPage, hasPreviousPage: startIndex > 0, startCursor, endCursor }),
    totalCount: items.length,
  });
}

function issueStateFilter(args: Record<string, unknown>): (issue: Issue) => boolean {
  const states = args.states;
  if (!Array.isArray(states) || states.length === 0) return () => true;
  const wanted = new Set(states.map((state) => String(state)));
  return (issue) => wanted.has(issue.state === 'open' ? 'OPEN' : 'CLOSED');
}

function sortedIssues(repo: Repo, args: Record<string, unknown>): Issue[] {
  let items = [...repo.issues.values()].filter(issueStateFilter(args));
  const orderBy = args.orderBy as Record<string, unknown> | undefined;
  const direction = orderBy?.direction === 'ASC' ? 1 : -1;
  items.sort((a, b) => direction * (a.number - b.number));
  return items;
}

function sortedPulls(repo: Repo, args: Record<string, unknown>): Pull[] {
  const states = args.states;
  let items = [...repo.pulls.values()];
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((state) => String(state)));
    items = items.filter((pull) => {
      const state = pull.state === 'open' ? 'OPEN' : pull.merged ? 'MERGED' : 'CLOSED';
      return wanted.has(state);
    });
  }
  const orderBy = args.orderBy as Record<string, unknown> | undefined;
  const direction = orderBy?.direction === 'ASC' ? 1 : -1;
  items.sort((a, b) => direction * (a.number - b.number));
  return items;
}

function findRepoById(id: number): Repo | null {
  for (const repo of reposByName.values()) if (repo.id === id) return repo;
  return null;
}

function findIssueByGlobalId(id: string): { repo: Repo; issue: Issue } | null {
  const parsed = parseGlobalId(id);
  if (!parsed || parsed.kind !== 'Issue') return null;
  const repoId = Math.floor(parsed.num / 1_000_000);
  const number = parsed.num % 1_000_000;
  const repo = findRepoById(repoId);
  if (!repo) return null;
  const issue = repo.issues.get(number);
  return issue ? { repo, issue } : null;
}

function findPullByGlobalId(id: string): { repo: Repo; pull: Pull } | null {
  const parsed = parseGlobalId(id);
  if (!parsed || parsed.kind !== 'PullRequest') return null;
  const repoId = Math.floor(parsed.num / 1_000_000);
  const number = parsed.num % 1_000_000;
  const repo = findRepoById(repoId);
  if (!repo) return null;
  const pull = repo.pulls.get(number);
  return pull ? { repo, pull } : null;
}

type Resolver = (obj: GqlRuntime, args: Record<string, unknown>) => unknown;

const GQL_FIELD_TYPES: Record<string, Record<string, string>> = {
  Query: { viewer: 'User', repository: 'Repository', node: 'Node', search: 'SearchResultItemConnection', __type: '__Type', __schema: '__Schema' },
  Mutation: { createIssue: 'CreateIssuePayload', closeIssue: 'CloseIssuePayload', createPullRequest: 'CreatePullRequestPayload', mergePullRequest: 'MergePullRequestPayload', addComment: 'AddCommentPayload' },
  Repository: { id: 'ID', databaseId: 'Int', name: 'String', nameWithOwner: 'String', owner: 'User', defaultBranchRef: 'Ref', viewerPermission: 'RepositoryPermission', hasIssuesEnabled: 'Boolean', issue: 'Issue', issues: 'IssueConnection', pullRequest: 'PullRequest', pullRequests: 'PullRequestConnection', description: 'String', url: 'String', createdAt: 'String', updatedAt: 'String' },
  Issue: { id: 'ID', databaseId: 'Int', number: 'Int', title: 'String', body: 'String', state: 'IssueState', url: 'String', author: 'User', repository: 'Repository', comments: 'IssueCommentConnection', createdAt: 'String', updatedAt: 'String' },
  PullRequest: { id: 'ID', databaseId: 'Int', number: 'Int', title: 'String', body: 'String', state: 'PullRequestState', merged: 'Boolean', mergeable: 'MergeableState', headRefName: 'String', baseRefName: 'String', headRefOid: 'String', baseRefOid: 'String', files: 'PullRequestChangedFileConnection', repository: 'Repository', author: 'User', createdAt: 'String', updatedAt: 'String', mergedAt: 'String', mergeCommit: 'Commit' },
  User: { id: 'ID', databaseId: 'Int', login: 'String', name: 'String', email: 'String' },
  Ref: { name: 'String', target: 'GitObject' },
  GitObject: { oid: 'String' },
  IssueConnection: { nodes: '[Issue]', edges: '[IssueEdge]', pageInfo: 'PageInfo', totalCount: 'Int' },
  IssueEdge: { node: 'Issue', cursor: 'String' },
  PullRequestConnection: { nodes: '[PullRequest]', edges: '[PullRequestEdge]', pageInfo: 'PageInfo', totalCount: 'Int' },
  PullRequestEdge: { node: 'PullRequest', cursor: 'String' },
  IssueCommentConnection: { nodes: '[IssueComment]', edges: '[IssueCommentEdge]', pageInfo: 'PageInfo', totalCount: 'Int' },
  IssueCommentEdge: { node: 'IssueComment', cursor: 'String' },
  PullRequestChangedFileConnection: { nodes: '[PullRequestChangedFile]', edges: '[PullRequestChangedFileEdge]', pageInfo: 'PageInfo', totalCount: 'Int' },
  PullRequestChangedFileEdge: { node: 'PullRequestChangedFile', cursor: 'String' },
  PageInfo: { hasNextPage: 'Boolean', hasPreviousPage: 'Boolean', startCursor: 'String', endCursor: 'String' },
  IssueComment: { id: 'ID', databaseId: 'Int', body: 'String', author: 'User', createdAt: 'String', updatedAt: 'String' },
  PullRequestChangedFile: { path: 'String', additions: 'Int', deletions: 'Int', changes: 'Int' },
  CreateIssuePayload: { issue: 'Issue' },
  CloseIssuePayload: { issue: 'Issue' },
  CreatePullRequestPayload: { pullRequest: 'PullRequest' },
  MergePullRequestPayload: { pullRequest: 'PullRequest' },
  AddCommentPayload: { commentEdge: 'IssueCommentEdge' },
  IssueCommentEdge: { node: 'IssueComment', cursor: 'String' },
  PullRequestChangedFileEdge: { node: 'PullRequestChangedFile', cursor: 'String' },
  __Type: { name: 'String', kind: 'String', description: 'String', fields: '[__Field]', enumValues: '[__EnumValue]' },
  __Field: { name: 'String', description: 'String' },
  __EnumValue: { name: 'String', description: 'String' },
  __Schema: { queryType: '__Type', mutationType: '__Type' },
  Node: { id: 'ID' },
  SearchResultItemConnection: { nodes: '[Node]', edges: '[SearchResultItemEdge]', pageInfo: 'PageInfo', totalCount: 'Int' },
  SearchResultItemEdge: { node: 'Node', cursor: 'String' },
  Commit: { oid: 'String' },
};

function repoOf(obj: GqlRuntime): Repo {
  return obj._repo as Repo;
}

function issueOf(obj: GqlRuntime): Issue {
  return obj._issue as Issue;
}

function pullOf(obj: GqlRuntime): Pull {
  return obj._pull as Pull;
}

const GQL_RESOLVERS: Record<string, Record<string, Resolver>> = {
  Query: {
    viewer: () => viewerUserObj(),
    repository: (_obj, args) => {
      const owner = String(args.owner ?? '');
      const name = String(args.name ?? '');
      if (owner !== VIEWER_LOGIN) return null;
      const repo = reposByName.get(name);
      return repo ? repoObj(repo) : null;
    },
    node: (_obj, args) => {
      const parsed = parseGlobalId(String(args.id ?? ''));
      if (!parsed) return null;
      if (parsed.kind === 'Repository') {
        const repo = findRepoById(parsed.num);
        return repo ? repoObj(repo) : null;
      }
      if (parsed.kind === 'Issue') {
        const found = findIssueByGlobalId(String(args.id ?? ''));
        return found ? issueObj(found.repo, found.issue) : null;
      }
      if (parsed.kind === 'PullRequest') {
        const found = findPullByGlobalId(String(args.id ?? ''));
        return found ? pullObj(found.repo, found.pull) : null;
      }
      return null;
    },
    search: (_obj, args) => {
      const type = String(args.type ?? 'ISSUE');
      const query = String(args.query ?? '').toLowerCase();
      const nodes: GqlRuntime[] = [];
      for (const repo of reposByName.values()) {
        if (type === 'REPOSITORY' && repo.name.toLowerCase().includes(query)) nodes.push(repoObj(repo));
        if (type === 'ISSUE') {
          for (const issue of repo.issues.values()) {
            if (issue.title.toLowerCase().includes(query) || issue.body.toLowerCase().includes(query)) nodes.push(issueObj(repo, issue));
          }
        }
        if (type === 'PULL_REQUEST') {
          for (const pull of repo.pulls.values()) {
            if (pull.title.toLowerCase().includes(query) || pull.body.toLowerCase().includes(query)) nodes.push(pullObj(repo, pull));
          }
        }
      }
      return connectionObj('SearchResultItemConnection', 'SearchResultItemEdge', nodes, (node) => node, args as PageArgs);
    },
    __type: (_obj, args) => {
      const info = INTROSPECTION_TYPES[String(args.name ?? '')];
      if (!info) return null;
      return gqlObject('__Type', {
        name: String(args.name ?? ''),
        kind: info.kind,
        description: null,
        fields: (info.fields ?? []).map((name) => gqlObject('__Field', { name, description: null })),
        enumValues: (info.enumValues ?? []).map((name) => gqlObject('__EnumValue', { name, description: null })),
      });
    },
    __schema: () => gqlObject('__Schema', {
      queryType: gqlObject('__Type', { name: 'Query', kind: 'OBJECT', description: null, fields: [], enumValues: [] }),
      mutationType: gqlObject('__Type', { name: 'Mutation', kind: 'OBJECT', description: null, fields: [], enumValues: [] }),
    }),
  },
  Mutation: {
    createIssue: (_obj, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const parsed = parseGlobalId(String(input.repositoryId ?? ''));
      if (!parsed || parsed.kind !== 'Repository') throw new Error('Unknown repository');
      const repo = findRepoById(parsed.num);
      if (!repo) throw new Error('Unknown repository');
      const title = String(input.title ?? '');
      if (title === '') throw new Error('title is required');
      const issue: Issue = {
        id: nextId(),
        number: repo.nextNumber++,
        title,
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        labels: [],
        comments: [],
      };
      repo.issues.set(issue.number, issue);
      return gqlObject('CreateIssuePayload', { issue: issueObj(repo, issue) });
    },
    closeIssue: (_obj, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const found = findIssueByGlobalId(String(input.issueId ?? ''));
      if (!found) throw new Error('Unknown issue');
      found.issue.state = 'closed';
      return gqlObject('CloseIssuePayload', { issue: issueObj(found.repo, found.issue) });
    },
    createPullRequest: (_obj, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const parsed = parseGlobalId(String(input.repositoryId ?? ''));
      if (!parsed || parsed.kind !== 'Repository') throw new Error('Unknown repository');
      const repo = findRepoById(parsed.num);
      if (!repo) throw new Error('Unknown repository');
      const head = String(input.headRefName ?? '');
      const base = String(input.baseRefName ?? '');
      const headSha = resolveRef(repo, head);
      const baseSha = resolveRef(repo, base);
      if (!headSha || !baseSha) throw new Error('head or base branch not found');
      const baseOf = mergeBase(repo, headSha, baseSha);
      if (baseOf === null) throw new Error('No common ancestor between head and base');
      const pull: Pull = {
        id: nextId(),
        number: repo.nextNumber++,
        title: String(input.title ?? ''),
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        headRef: head,
        baseRef: base,
        headSha,
        baseSha,
        mergeBase: baseOf,
      };
      repo.pulls.set(pull.number, pull);
      return gqlObject('CreatePullRequestPayload', { pullRequest: pullObj(repo, pull) });
    },
    mergePullRequest: (_obj, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const found = findPullByGlobalId(String(input.pullRequestId ?? ''));
      if (!found) throw new Error('Unknown pull request');
      const { repo, pull } = found;
      if (pull.state !== 'open') throw new Error('Pull request is already closed');
      const sha = squashMerge(repo, pull);
      if (sha === null) throw new Error('Merge conflict');
      repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
      pull.state = 'closed';
      pull.merged = true;
      pull.mergedAt = TRIAL_NOW_ISO;
      pull.mergeCommitSha = sha;
      return gqlObject('MergePullRequestPayload', { pullRequest: pullObj(repo, pull) });
    },
    addComment: (_obj, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const found = findIssueByGlobalId(String(input.subjectId ?? ''));
      if (!found) throw new Error('Unknown subject');
      const body = String(input.body ?? '');
      if (body === '') throw new Error('body is required');
      const comment: IssueComment = { id: found.repo.nextCommentId++, body };
      found.issue.comments.push(comment);
      return gqlObject('AddCommentPayload', {
        commentEdge: gqlObject('IssueCommentEdge', { node: commentObj(found.repo, comment), cursor: cursorFor(found.issue.comments.length - 1) }),
      });
    },
  },
  Repository: {
    id: (obj) => repoGlobalId(repoOf(obj)),
    databaseId: (obj) => repoOf(obj).id,
    name: (obj) => repoOf(obj).name,
    nameWithOwner: (obj) => `${repoOf(obj).owner}/${repoOf(obj).name}`,
    owner: () => viewerUserObj(),
    defaultBranchRef: (obj) => {
      const repo = repoOf(obj);
      const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      if (!tip) return null;
      return gqlObject('Ref', { name: repo.defaultBranch, _oid: tip, _repo: repo });
    },
    viewerPermission: () => 'ADMIN',
    hasIssuesEnabled: () => true,
    description: (obj) => repoOf(obj).description,
    url: (obj) => `https://github.com/${repoOf(obj).owner}/${repoOf(obj).name}`,
    createdAt: () => TRIAL_NOW_ISO,
    updatedAt: () => TRIAL_NOW_ISO,
    issue: (obj, args) => {
      const issue = repoOf(obj).issues.get(Number(args.number ?? -1));
      return issue ? issueObj(repoOf(obj), issue) : null;
    },
    issues: (obj, args) => {
      const repo = repoOf(obj);
      return connectionObj('IssueConnection', 'IssueEdge', sortedIssues(repo, args), (issue) => issueObj(repo, issue), args as PageArgs);
    },
    pullRequest: (obj, args) => {
      const pull = repoOf(obj).pulls.get(Number(args.number ?? -1));
      return pull ? pullObj(repoOf(obj), pull) : null;
    },
    pullRequests: (obj, args) => {
      const repo = repoOf(obj);
      return connectionObj('PullRequestConnection', 'PullRequestEdge', sortedPulls(repo, args), (pull) => pullObj(repo, pull), args as PageArgs);
    },
  },
  Issue: {
    id: (obj) => issueGlobalId(repoOf(obj), issueOf(obj)),
    databaseId: (obj) => issueOf(obj).id,
    number: (obj) => issueOf(obj).number,
    title: (obj) => issueOf(obj).title,
    body: (obj) => issueOf(obj).body,
    state: (obj) => (issueOf(obj).state === 'open' ? 'OPEN' : 'CLOSED'),
    url: (obj) => `https://github.com/${repoOf(obj).owner}/${repoOf(obj).name}/issues/${issueOf(obj).number}`,
    author: () => viewerUserObj(),
    repository: (obj) => repoObj(repoOf(obj)),
    comments: (obj, args) => {
      const repo = repoOf(obj);
      const issue = issueOf(obj);
      return connectionObj('IssueCommentConnection', 'IssueCommentEdge', issue.comments, (comment) => commentObj(repo, comment), args as PageArgs);
    },
    createdAt: () => TRIAL_NOW_ISO,
    updatedAt: () => TRIAL_NOW_ISO,
  },
  PullRequest: {
    id: (obj) => pullGlobalId(repoOf(obj), pullOf(obj)),
    databaseId: (obj) => pullOf(obj).id,
    number: (obj) => pullOf(obj).number,
    title: (obj) => pullOf(obj).title,
    body: (obj) => pullOf(obj).body,
    state: (obj) => {
      const pull = pullOf(obj);
      return pull.state === 'open' ? 'OPEN' : pull.merged ? 'MERGED' : 'CLOSED';
    },
    merged: (obj) => pullOf(obj).merged,
    mergeable: (obj) => {
      const pull = pullOf(obj);
      if (pull.state !== 'open') return 'UNKNOWN';
      return pullIsMergeable(repoOf(obj), pull) ? 'MERGEABLE' : 'CONFLICTING';
    },
    headRefName: (obj) => pullOf(obj).headRef,
    baseRefName: (obj) => pullOf(obj).baseRef,
    headRefOid: (obj) => pullOf(obj).headSha,
    baseRefOid: (obj) => pullOf(obj).baseSha,
    files: (obj, args) => {
      const repo = repoOf(obj);
      const files = pullFiles(repo, pullOf(obj));
      const nodes = files.map((file) => gqlObject('PullRequestChangedFile', { path: file.filename, additions: file.additions, deletions: file.deletions, changes: file.changes }));
      return connectionObj('PullRequestChangedFileConnection', 'PullRequestChangedFileEdge', nodes, (node) => node, args as PageArgs);
    },
    repository: (obj) => repoObj(repoOf(obj)),
    author: () => viewerUserObj(),
    createdAt: () => TRIAL_NOW_ISO,
    updatedAt: () => TRIAL_NOW_ISO,
    mergedAt: (obj) => pullOf(obj).mergedAt,
    mergeCommit: (obj) => {
      const sha = pullOf(obj).mergeCommitSha;
      return sha ? gqlObject('Commit', { oid: sha }) : null;
    },
  },
  User: {
    id: (obj) => globalId('User', Number(obj.databaseId ?? VIEWER_ID)),
    databaseId: (obj) => Number(obj.databaseId ?? VIEWER_ID),
    login: (obj) => String(obj.login ?? VIEWER_LOGIN),
    name: (obj) => String(obj.name ?? VIEWER_NAME),
    email: (obj) => String(obj.email ?? VIEWER_EMAIL),
  },
  Ref: {
    name: (obj) => String(obj.name ?? ''),
    target: (obj) => gqlObject('GitObject', { oid: String(obj._oid ?? '') }),
  },
  GitObject: {
    oid: (obj) => String(obj.oid ?? ''),
  },
  Commit: {
    oid: (obj) => String(obj.oid ?? ''),
  },
  IssueConnection: {
    nodes: (obj) => obj.nodes as unknown[],
    edges: (obj) => obj.edges as unknown[],
    pageInfo: (obj) => obj.pageInfo as GqlRuntime,
    totalCount: (obj) => Number(obj.totalCount ?? 0),
  },
  IssueEdge: {
    node: (obj) => obj.node as GqlRuntime,
    cursor: (obj) => String(obj.cursor ?? ''),
  },
  PullRequestConnection: {
    nodes: (obj) => obj.nodes as unknown[],
    edges: (obj) => obj.edges as unknown[],
    pageInfo: (obj) => obj.pageInfo as GqlRuntime,
    totalCount: (obj) => Number(obj.totalCount ?? 0),
  },
  PullRequestEdge: {
    node: (obj) => obj.node as GqlRuntime,
    cursor: (obj) => String(obj.cursor ?? ''),
  },
  IssueCommentConnection: {
    nodes: (obj) => obj.nodes as unknown[],
    edges: (obj) => obj.edges as unknown[],
    pageInfo: (obj) => obj.pageInfo as GqlRuntime,
    totalCount: (obj) => Number(obj.totalCount ?? 0),
  },
  IssueCommentEdge: {
    node: (obj) => obj.node as GqlRuntime,
    cursor: (obj) => String(obj.cursor ?? ''),
  },
  PullRequestChangedFileConnection: {
    nodes: (obj) => obj.nodes as unknown[],
    edges: (obj) => obj.edges as unknown[],
    pageInfo: (obj) => obj.pageInfo as GqlRuntime,
    totalCount: (obj) => Number(obj.totalCount ?? 0),
  },
  PullRequestChangedFileEdge: {
    node: (obj) => obj.node as GqlRuntime,
    cursor: (obj) => String(obj.cursor ?? ''),
  },
  PageInfo: {
    hasNextPage: (obj) => Boolean(obj.hasNextPage),
    hasPreviousPage: (obj) => Boolean(obj.hasPreviousPage),
    startCursor: (obj) => (obj.startCursor as string | null) ?? null,
    endCursor: (obj) => (obj.endCursor as string | null) ?? null,
  },
  IssueComment: {
    id: (obj) => commentGlobalId(obj._repo as Repo, obj._comment as IssueComment),
    databaseId: (obj) => (obj._comment as IssueComment).id,
    body: (obj) => (obj._comment as IssueComment).body,
    author: () => viewerUserObj(),
    createdAt: () => TRIAL_NOW_ISO,
    updatedAt: () => TRIAL_NOW_ISO,
  },
  PullRequestChangedFile: {
    path: (obj) => String(obj.path ?? ''),
    additions: (obj) => Number(obj.additions ?? 0),
    deletions: (obj) => Number(obj.deletions ?? 0),
    changes: (obj) => Number(obj.changes ?? 0),
  },
  CreateIssuePayload: { issue: (obj) => obj.issue as GqlRuntime },
  CloseIssuePayload: { issue: (obj) => obj.issue as GqlRuntime },
  CreatePullRequestPayload: { pullRequest: (obj) => obj.pullRequest as GqlRuntime },
  MergePullRequestPayload: { pullRequest: (obj) => obj.pullRequest as GqlRuntime },
  AddCommentPayload: { commentEdge: (obj) => obj.commentEdge as GqlRuntime },
  __Type: {
    name: (obj) => String(obj.name ?? ''),
    kind: (obj) => String(obj.kind ?? 'OBJECT'),
    description: (obj) => (obj.description as string | null) ?? null,
    fields: (obj) => (obj.fields as unknown[]) ?? [],
    enumValues: (obj) => (obj.enumValues as unknown[]) ?? [],
  },
  __Field: {
    name: (obj) => String(obj.name ?? ''),
    description: (obj) => (obj.description as string | null) ?? null,
  },
  __EnumValue: {
    name: (obj) => String(obj.name ?? ''),
    description: (obj) => (obj.description as string | null) ?? null,
  },
  __Schema: {
    queryType: (obj) => obj.queryType as GqlRuntime,
    mutationType: (obj) => obj.mutationType as GqlRuntime,
  },
  Node: {
    id: (obj) => String(obj.id ?? ''),
  },
  SearchResultItemConnection: {
    nodes: (obj) => obj.nodes as unknown[],
    edges: (obj) => obj.edges as unknown[],
    pageInfo: (obj) => obj.pageInfo as GqlRuntime,
    totalCount: (obj) => Number(obj.totalCount ?? 0),
  },
  SearchResultItemEdge: {
    node: (obj) => obj.node as GqlRuntime,
    cursor: (obj) => String(obj.cursor ?? ''),
  },
};

function executeGqlValue(
  typeName: string,
  value: unknown,
  selectionSet: GqlSelection[] | null,
  variables: Record<string, unknown>,
  fragments: Map<string, GqlFragment>,
  errors: Array<Record<string, unknown>>,
): unknown {
  if (value === null || value === undefined) return null;
  if (selectionSet === null) return value;
  if (typeName.startsWith('[') && typeName.endsWith(']')) {
    const inner = typeName.slice(1, -1);
    if (!Array.isArray(value)) return null;
    return value.map((item) => executeGqlValue(inner, item, selectionSet, variables, fragments, errors));
  }
  if (SCALAR_TYPES.has(typeName) || ENUM_TYPES.has(typeName)) return value;
  const runtime = value as GqlRuntime;
  const runtimeType = runtime.__typename ?? typeName;
  return executeGqlSelectionSet(runtimeType, runtime, selectionSet, variables, fragments, errors);
}

function executeGqlSelectionSet(
  typeName: string,
  obj: GqlRuntime,
  selections: readonly GqlSelection[],
  variables: Record<string, unknown>,
  fragments: Map<string, GqlFragment>,
  errors: Array<Record<string, unknown>>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'inlineFragment') {
      if (selection.typeCondition !== null && selection.typeCondition !== typeName && selection.typeCondition !== obj.__typename) continue;
      Object.assign(out, executeGqlSelectionSet(typeName, obj, selection.selectionSet, variables, fragments, errors));
      continue;
    }
    if (selection.kind === 'fragmentSpread') {
      const fragment = fragments.get(selection.name);
      if (!fragment) {
        errors.push({ message: `Unknown fragment "${selection.name}".` });
        continue;
      }
      if (fragment.typeCondition !== typeName && fragment.typeCondition !== obj.__typename) continue;
      Object.assign(out, executeGqlSelectionSet(typeName, obj, fragment.selectionSet, variables, fragments, errors));
      continue;
    }
    if (directiveSkip(selection.directives, variables)) continue;
    const responseKey = selection.alias ?? selection.name;
    if (selection.name === '__typename') {
      out[responseKey] = obj.__typename ?? typeName;
      continue;
    }
    const fieldTypes = GQL_FIELD_TYPES[typeName];
    const resolvers = GQL_RESOLVERS[typeName];
    const fieldType = fieldTypes?.[selection.name];
    const resolver = resolvers?.[selection.name];
    if (!fieldType || !resolver) {
      errors.push({ message: `Cannot query field "${selection.name}" on type "${typeName}".` });
      out[responseKey] = null;
      continue;
    }
    const args = evalGqlArgs(selection.args, variables);
    let value: unknown;
    try {
      value = resolver(obj, args);
    } catch (err) {
      errors.push({ message: err instanceof Error ? err.message : 'Field resolution failed' });
      out[responseKey] = null;
      continue;
    }
    out[responseKey] = executeGqlValue(fieldType, value, selection.selectionSet, variables, fragments, errors);
  }
  return out;
}

function executeGraphqlOperation(item: unknown): Record<string, unknown> {
  if (!item || typeof item !== 'object') return { errors: [{ message: 'Invalid GraphQL request' }] };
  const request = item as Record<string, unknown>;
  if (typeof request.query !== 'string') return { errors: [{ message: 'query is required' }] };
  let document: GqlDocument;
  try {
    document = parseGraphql(request.query);
  } catch (err) {
    return { errors: [{ message: err instanceof Error ? err.message : 'Syntax error' }] };
  }
  const variables = (request.variables !== null && typeof request.variables === 'object' ? request.variables : {}) as Record<string, unknown>;
  const operationName = typeof request.operationName === 'string' ? request.operationName : undefined;
  let operation: GqlOperation | undefined;
  if (operationName !== undefined) {
    operation = document.operations.find((candidate) => candidate.name === operationName);
    if (!operation) return { errors: [{ message: `Unknown operation named "${operationName}".` }] };
  } else {
    operation = document.operations[0];
  }
  if (!operation) return { errors: [{ message: 'No operation provided' }] };
  const mergedVariables: Record<string, unknown> = { ...variables };
  for (const variable of operation.variables) {
    if (mergedVariables[variable.name] === undefined && variable.defaultValue !== null) {
      mergedVariables[variable.name] = evalGqlValue(variable.defaultValue, variables);
    }
  }
  const rootType = operation.operation === 'mutation' ? 'Mutation' : 'Query';
  const root = gqlObject(rootType, {});
  const errors: Array<Record<string, unknown>> = [];
  const data = executeGqlSelectionSet(rootType, root, operation.selectionSet, mergedVariables, document.fragments, errors);
  const result: Record<string, unknown> = { data };
  if (errors.length > 0) result.errors = errors;
  return result;
}

function handleGraphql(ctx: Ctx): void {
  let body: unknown;
  try {
    body = JSON.parse(ctx.body.toString('utf8'));
  } catch {
    sendJson(ctx.res, 400, { errors: [{ message: 'Invalid JSON body' }] });
    return;
  }
  if (Array.isArray(body)) {
    sendJson(ctx.res, 200, body.map((item) => executeGraphqlOperation(item)));
    return;
  }
  sendJson(ctx.res, 200, executeGraphqlOperation(body));
}

// ---------------------------------------------------------------------------------------------
// MCP: JSON-RPC 2.0 over Streamable HTTP
// ---------------------------------------------------------------------------------------------

const MCP_SERVER_INFO = { name: 'github-core-clone-01-forge', version: '1.0.0' };
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

interface McpTool {
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Record<string, { type: string; description: string }>; required?: string[] };
}

const MCP_TOOLS: McpTool[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'list_repos',
    description: 'List repositories owned by the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
      },
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state: open, closed or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'get_issue',
    description: 'Get an issue by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        issue_number: { type: 'number', description: 'Issue number' },
      },
      required: ['owner', 'repo', 'issue_number'],
    },
  },
  {
    name: 'close_issue',
    description: 'Close an issue by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        issue_number: { type: 'number', description: 'Issue number' },
      },
      required: ['owner', 'repo', 'issue_number'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch onto a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
        body: { type: 'string', description: 'Pull request body' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'list_pull_requests',
    description: 'List pull requests in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Pull request state: open, closed or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'number', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpPick(args: Record<string, unknown>, ...names: string[]): unknown {
  for (const name of names) {
    const value = args[name];
    if (value !== undefined && value !== null) return value;
  }
  return undefined;
}

function mcpOwnerRepo(args: Record<string, unknown>): { owner: string; repo: string } | null {
  const fullName = mcpPick(args, 'full_name');
  let owner = mcpPick(args, 'owner', 'owner_login') as string | undefined;
  let repo = mcpPick(args, 'repo', 'repository') as string | undefined;
  if ((!owner || !repo) && typeof fullName === 'string' && fullName.includes('/')) {
    const [left, right] = fullName.split('/');
    owner = owner ?? left;
    repo = repo ?? right;
  }
  if (typeof owner !== 'string' || owner === '' || typeof repo !== 'string' || repo === '') return null;
  return { owner, repo };
}

function mcpTextResult(structured: unknown): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: JSON.stringify(structured) }],
    structuredContent: structured,
  };
}

function mcpErrorResult(message: string): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: message }],
    structuredContent: { error: message },
    isError: true,
  };
}

function callMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const tool = MCP_TOOLS.find((candidate) => candidate.name === name);
  if (!tool) throw Object.assign(new Error(`Unknown tool '${name}'`), { code: -32601 });
  for (const required of tool.inputSchema.required ?? []) {
    if (args[required] === undefined || args[required] === null || args[required] === '') {
      return mcpErrorResult(`Missing required argument: ${required}`);
    }
  }
  switch (name) {
    case 'create_repo': {
      const repoName = String(args.name ?? '');
      if (reposByName.has(repoName)) return mcpErrorResult(`Repository ${repoName} already exists`);
      const repo = createRepo(repoName, args.private === true, typeof args.description === 'string' ? args.description : '');
      return mcpTextResult(repoJson(repo));
    }
    case 'get_repo': {
      const target = mcpOwnerRepo(args);
      if (!target) return mcpErrorResult('owner and repo are required');
      const repo = lookupRepo(target.owner, target.repo);
      if (!repo) return mcpErrorResult('Not Found');
      return mcpTextResult(repoJson(repo));
    }
    case 'list_repos': {
      const repos = [...reposByName.values()].sort((a, b) => a.id - b.id).map((repo) => repoJson(repo));
      return mcpTextResult({ repositories: repos });
    }
    case 'create_issue': {
      const target = mcpOwnerRepo(args);
      if (!target) return mcpErrorResult('owner and repo are required');
      const repo = lookupRepo(target.owner, target.repo);
      if (!repo) return mcpErrorResult('Not Found');
      const title = String(args.title ?? '');
      if (title === '') return mcpErrorResult('title is required');
      const labels = Array.isArray(args.labels) ? args.labels.map(String) : [];
      for (const label of labels) {
        if (!repo.labels.has(label)) return mcpErrorResult(`Label '${label}' does not exist`);
      }
      const issue: Issue = {
        id: nextId(),
        number: repo.nextNumber++,
        title,
        body: typeof args.body === 'string' ? args.body : '',
        state: 'open',
        labels,
        comments: [],
      };
      repo.issues.set(issue.number, issue);
      return mcpTextResult(issueJson(repo, issue));
    }
    case 'list_issues': {
      const target = mcpOwnerRepo(args);
      if (!target) return mcpErrorResult('owner and repo are required');
      const repo = lookupRepo(target.owner, target.repo);
      if (!repo) return mcpErrorResult('Not Found');
      const state = typeof args.state === 'string' ? args.state : 'open';
      let items = [...repo.issues.values()];
      if (state === 'open') items = items.filter((issue) => issue.state === 'open');
      else if (state === 'closed') items = items.filter((issue) => issue.state === 'closed');
      items.sort((a, b) => b.number - a.number);
      const list = items.map((issue) => issueJson(repo, issue));
      return mcpTextResult({ issues: list });
    }
    case 'get_issue':
    case 'close_issue': {
      const target = mcpOwnerRepo(args);
      if (!target) return mcpErrorResult('owner and repo are required');
      const repo = lookupRepo(target.owner, target.repo);
      if (!repo) return mcpErrorResult('Not Found');
      const number = Number(mcpPick(args, 'issue_number', 'number'));
      const issue = repo.issues.get(number);
      if (!issue) return mcpErrorResult('Not Found');
      if (name === 'close_issue') issue.state = 'closed';
      return mcpTextResult(issueJson(repo, issue));
    }
    case 'create_pull_request': {
      const target = mcpOwnerRepo(args);
      if (!target) return mcpErrorResult('owner and repo are required');
      const repo = lookupRepo(target.owner, target.repo);
      if (!repo) return mcpErrorResult('Not Found');
      const head = String(args.head ?? '');
      const base = String(args.base ?? '');
      const headSha = resolveRef(repo, head);
      const baseSha = resolveRef(repo, base);
      if (!headSha || !baseSha) return mcpErrorResult('head or base branch not found');
      const baseOf = mergeBase(repo, headSha, baseSha);
      if (baseOf === null) return mcpErrorResult('No common ancestor between head and base');
      const pull: Pull = {
        id: nextId(),
        number: repo.nextNumber++,
        title: String(args.title ?? ''),
        body: typeof args.body === 'string' ? args.body : '',
        state: 'open',
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        headRef: head,
        baseRef: base,
        headSha,
        baseSha,
        mergeBase: baseOf,
      };
      repo.pulls.set(pull.number, pull);
      return mcpTextResult(pullJson(repo, pull));
    }
    case 'list_pull_requests': {
      const target = mcpOwnerRepo(args);
      if (!target) return mcpErrorResult('owner and repo are required');
      const repo = lookupRepo(target.owner, target.repo);
      if (!repo) return mcpErrorResult('Not Found');
      const state = typeof args.state === 'string' ? args.state : 'open';
      let items = [...repo.pulls.values()];
      if (state === 'open') items = items.filter((pull) => pull.state === 'open');
      else if (state === 'closed') items = items.filter((pull) => pull.state === 'closed');
      items.sort((a, b) => b.number - a.number);
      const list = items.map((pull) => pullJson(repo, pull));
      return mcpTextResult({ pull_requests: list });
    }
    case 'merge_pull_request': {
      const target = mcpOwnerRepo(args);
      if (!target) return mcpErrorResult('owner and repo are required');
      const repo = lookupRepo(target.owner, target.repo);
      if (!repo) return mcpErrorResult('Not Found');
      const number = Number(mcpPick(args, 'pull_number', 'number'));
      const pull = repo.pulls.get(number);
      if (!pull) return mcpErrorResult('Not Found');
      if (pull.state !== 'open') return mcpErrorResult('Pull request is already closed');
      const sha = squashMerge(repo, pull);
      if (sha === null) return mcpErrorResult('Merge conflict');
      repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
      pull.state = 'closed';
      pull.merged = true;
      pull.mergedAt = TRIAL_NOW_ISO;
      pull.mergeCommitSha = sha;
      return mcpTextResult({ sha, merged: true, ...pullJson(repo, pull) });
    }
    default:
      return mcpErrorResult(`Unknown tool '${name}'`);
  }
}

function handleMcp(ctx: Ctx): void {
  if (!authed(ctx.req)) {
    sendJson(ctx.res, 401, { jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Unauthorized' } });
    return;
  }
  let body: unknown;
  try {
    body = JSON.parse(ctx.body.toString('utf8'));
  } catch {
    sendJson(ctx.res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    sendJson(ctx.res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  const request = body as Record<string, unknown>;
  const id = request.id === undefined ? null : request.id;
  const method = typeof request.method === 'string' ? request.method : '';
  const params = (request.params !== null && typeof request.params === 'object' ? request.params : {}) as Record<string, unknown>;

  // Notifications carry no id and get no JSON-RPC reply.
  if (id === null || id === undefined) {
    ctx.res.writeHead(202, { 'x-github-request-id': `forge-${++requestCounter}` });
    ctx.res.end();
    return;
  }

  const ok = (result: unknown): void => {
    sendJson(ctx.res, 200, { jsonrpc: '2.0', id, result });
  };
  const fail = (code: number, message: string): void => {
    sendJson(ctx.res, 200, { jsonrpc: '2.0', id, error: { code, message } });
  };

  if (method === 'server/discover') {
    ok({
      supportedVersions: [...MCP_SUPPORTED_VERSIONS],
      serverInfo: { ...MCP_SERVER_INFO },
      capabilities: { tools: {} },
      _meta: { 'io.modelcontextprotocol/serverInfo': { ...MCP_SERVER_INFO } },
    });
    return;
  }
  if (method === 'initialize') {
    const requested = String(params.protocolVersion ?? '');
    const protocolVersion = MCP_SUPPORTED_VERSIONS.includes(requested) ? requested : '2025-11-25';
    ok({
      protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { ...MCP_SERVER_INFO },
    });
    return;
  }
  if (method === 'ping') {
    ok({});
    return;
  }
  if (method === 'tools/list') {
    ok({ tools: MCP_TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const toolName = String(params.name ?? '');
    const toolArgs = (params.arguments !== null && typeof params.arguments === 'object' ? params.arguments : {}) as Record<string, unknown>;
    try {
      ok(callMcpTool(toolName, toolArgs));
    } catch (err) {
      const code = (err as { code?: number }).code ?? -32602;
      fail(code, err instanceof Error ? err.message : 'Tool call failed');
    }
    return;
  }
  fail(-32601, `Method not found: ${method}`);
}

// ---------------------------------------------------------------------------------------------
// App entrypoint (used by main.ts)
// ---------------------------------------------------------------------------------------------

export function createApp(): Server {
  const server = createServer((req, res) => {
    void (async () => {
      try {
        const method = req.method ?? 'GET';
        const path = pathOf(req);
        const needsBody = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
        const body = needsBody ? await readBody(req) : Buffer.alloc(0);
        const ctx: Ctx = {
          req,
          res,
          method,
          path,
          segments: path.split('/'),
          query: queryOf(req),
          body,
          bodyJson: undefined,
        };
        if (path === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }
        if (path === '/api/graphql' && method === 'POST') {
          if (!authed(req)) {
            sendJson(res, 401, { message: 'Unauthorized' });
            return;
          }
          handleGraphql(ctx);
          return;
        }
        if (path === '/mcp' && method === 'POST') {
          handleMcp(ctx);
          return;
        }
        if (path.startsWith('/api/v3')) {
          if (!authed(req)) {
            sendJson(res, 401, { message: 'Unauthorized' });
            return;
          }
          routeRest(ctx);
          return;
        }
        if (ctx.segments.length >= 3 && ctx.segments[2]!.endsWith('.git')) {
          if (!authed(req)) {
            sendJson(res, 401, { message: 'Unauthorized' });
            return;
          }
          routeGit(ctx);
          return;
        }
        sendError(res, 404, 'Not Found');
      } catch (err) {
        if (!res.headersSent) {
          const status = (err as { status?: number }).status ?? 500;
          sendError(res, status, err instanceof Error ? err.message : 'Internal error');
        } else {
          res.end();
        }
      }
    })();
  });
  return server;
}
