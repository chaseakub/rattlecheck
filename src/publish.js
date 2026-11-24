// `rattlecheck --publish`: asks the public badge service to grade this
// project's GitHub repository.
//
// Nothing about the local check is sent. The request carries the repository
// name and the project folder, and the service fetches and checks the pushed
// code itself. That is the point: a published grade can't be talked up from a
// laptop, and it can only be published by a repository that says, in its own
// committed config, that it wants one.
import { execFileSync } from 'node:child_process';

export const PUBLISH_SERVICE = 'https://rattlecheck.chase-000.workers.dev';

export class PublishFailed extends Error {
  constructor(message, code = 5) {
    super(message);
    this.code = code;
  }
}

/** owner/name from a GitHub remote URL, or null for anything else. */
export function parseGitHubRemote(url) {
  const m = /^(?:https?:\/\/(?:[^@/]+@)?github\.com\/|git@github\.com:|ssh:\/\/git@github\.com(?::\d+)?\/)([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+?)(?:\.git)?\/?$/.exec(String(url).trim());
  return m ? `${m[1]}/${m[2]}` : null;
}

function defaultGit(root, args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
}

/**
 * @param {object} opts
 * @param {string} opts.root        project folder
 * @param {(dir:string)=>{optedIn:boolean, hint:string}} opts.consent
 *   whether the config at the top of the repository opts this folder in
 * @param {string} [opts.repo]      owner/name, when not read from the git remote
 * @param {object} [opts.env]
 * @param {Function} [opts.fetchImpl]
 * @param {(root:string, args:string[])=>string} [opts.git]
 */
export async function publishProject({ root, consent, repo, env = process.env, fetchImpl = globalThis.fetch, git = defaultGit, userAgent = 'rattlecheck' }) {
  const tryGit = (args) => {
    try {
      return git(root, args);
    } catch {
      return null;
    }
  };
  let target = repo;
  if (!target) {
    const remote = tryGit(['remote', 'get-url', 'origin']);
    target = remote && parseGitHubRemote(remote);
    if (!target) {
      throw new PublishFailed(
        remote
          ? `The git remote "origin" (${remote.replace(/\/\/[^@/]+@/, '//')}) is not a GitHub repository. Only public GitHub repositories can be published. Pass --repo owner/name if it lives on GitHub under another remote.`
          : 'Could not find a git remote called "origin" here. Run this inside your project\'s git checkout, or pass --repo owner/name.',
        2,
      );
    }
  }
  const dir = (tryGit(['rev-parse', '--show-prefix']) ?? '').replace(/\/+$/, '');
  const top = tryGit(['rev-parse', '--show-toplevel']) ?? root;
  const { optedIn, hint } = consent({ dir, top });
  if (!optedIn) {
    throw new PublishFailed(`This project has not opted in to a public grade. ${hint} Commit it, push it, and run rattlecheck --publish again.`, 2);
  }
  const localCommit = tryGit(['rev-parse', 'HEAD']);

  const base = (env.RATTLECHECK_PUBLISH_URL || PUBLISH_SERVICE).replace(/\/+$/, '');
  let res;
  let body;
  try {
    res = await fetchImpl(`${base}/api/publish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': userAgent },
      body: JSON.stringify({ repo: target, dir }),
    });
    body = await res.json();
  } catch {
    throw new PublishFailed(`Could not reach the publish service at ${base}. Nothing was published.`);
  }
  if (!res.ok) throw new PublishFailed(`Not published: ${body?.message ?? `the service answered ${res.status}`}`);
  return { ...body, target, localCommit };
}

/** What the command line prints after a successful publish. */
export function renderPublished(p, localGrade) {
  const where = p.dir ? `${p.target} (${p.dir})` : p.target;
  const lines = [
    '',
    `  Published  ${where}: grade ${p.grade.letter} (${p.grade.label})`,
    `  Page       ${p.page}`,
    `  Badge      ${p.markdown}`,
    '',
  ];
  if (p.fresh === false) lines.push('  This project was checked less than a minute ago, so this is that result.');
  if (p.commit && p.localCommit && p.commit !== p.localCommit) {
    lines.push(`  The grade is for commit ${p.commit.slice(0, 7)}, the latest on the default branch. Your checkout is at ${p.localCommit.slice(0, 7)}; push and merge to publish that.`);
  } else if (localGrade && localGrade !== p.grade.letter) {
    lines.push(`  The published grade (${p.grade.letter}) differs from the local one (${localGrade}). The service only sees what is pushed.`);
  }
  if (lines[lines.length - 1] !== '') lines.push('');
  return `${lines.join('\n')}\n`;
}
