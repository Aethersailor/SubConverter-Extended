'use strict';

const BUILD = 'build-dockerhub.yml';
const REFRESH_TITLE = 'Refresh upstream dependencies on dev';
const GENERATED_TITLE = 'chore: update generated development inputs after build [skip ci]';
const MAX_ATTEMPTS = 3;
const DAY = 86400000;

function eligible(pull, repository) {
  return pull.state === 'open' && !pull.draft &&
    pull.user?.login === 'dependabot[bot]' && pull.base?.ref === 'dev' &&
    pull.base.repo?.full_name === repository && pull.head?.repo?.full_name === repository &&
    pull.head.ref.startsWith('dependabot/') &&
    pull.labels.some(label => label.name === 'automerge') &&
    /^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(\([^)]+\))?!?: .+/.test(pull.title);
}

function trustedFiles(files, pull) {
  const allowed = path =>
    ['Dockerfile', 'docker/Dockerfile.debian', 'docker/Dockerfile.armv7-cross',
      'bridge/go.mod', 'bridge/go.sum'].includes(path) ||
    /^\.github\/(workflows\/[^/]+\.ya?ml|actions\/[^/]+\/action\.ya?ml)$/.test(path);
  return files.length > 0 && files.length === pull.changed_files &&
    files.every(file => ['modified', 'added'].includes(file.status) &&
      !file.previous_filename && allowed(file.filename));
}

function verifiedCommits(commits, pull) {
  return commits.length > 0 && commits.length === pull.commits &&
    commits.every(commit => commit.author?.login === 'dependabot[bot]' &&
      commit.commit?.verification?.verified === true) &&
    commits.at(-1).sha === pull.head.sha;
}

function latest(runs) {
  return [...runs].sort((a, b) => b.id - a.id)[0];
}

module.exports = async function maintain({github, context, core, rebaseGithub}) {
  const event = context.eventName;
  if ((['push', 'workflow_dispatch'].includes(event) && context.ref !== 'refs/heads/dev') ||
      (event === 'workflow_run' && context.payload?.workflow_run?.head_branch !== 'dev') ||
      (event === 'pull_request_target' && context.payload?.pull_request?.base?.ref !== 'dev')) {
    return core.notice('Dependabot maintenance only handles dev.');
  }
  const mode = (process.env.AUTOMERGE_MODE || 'active').toLowerCase();
  if (!['off', 'observe', 'active'].includes(mode)) throw new Error(`Invalid AUTOMERGE_MODE: ${mode}`);
  if (mode === 'off') return core.notice('Dependabot maintenance is disabled.');
  const dry = mode === 'observe' || process.env.DRY_RUN === 'true';
  const repo = context.repo;
  const repository = `${repo.owner}/${repo.repo}`;
  const rebaser = rebaseGithub || (process.env.REBASE_TOKEN ?
    new github.constructor({auth: process.env.REBASE_TOKEN}) : null);
  const rows = [];
  const note = message => { rows.push(message); core.info(message); };
  const act = async (description, operation) => {
    note(`${dry ? '[observe] ' : ''}${description}`);
    if (!dry) return operation();
  };
  const branch = async () => (await github.rest.repos.getBranch({...repo, branch: 'dev'})).data.commit.sha;
  const runsFor = async (workflow, extra = {}) => github.paginate(github.rest.actions.listWorkflowRuns, {
    ...repo, workflow_id: workflow, per_page: 100, ...extra,
  });
  const retry = async run => {
    if (run.status !== 'completed' || run.conclusion === 'success') return;
    if (!['failure', 'timed_out', 'startup_failure'].includes(run.conclusion)) {
      core.warning(`Run ${run.id} needs attention (${run.conclusion}): ${run.html_url}`);
      return;
    }
    if (run.run_attempt >= MAX_ATTEMPTS) {
      core.warning(`Run ${run.id} still fails after ${MAX_ATTEMPTS} attempts; waiting for maintainer attention: ${run.html_url}`);
      return;
    }
    await act(`Retry failed jobs in run ${run.id} (attempt ${run.run_attempt + 1}/${MAX_ATTEMPTS}).`, () =>
      github.rest.actions.reRunWorkflowFailedJobs({...repo, run_id: run.id}));
  };

  // GITHUB_TOKEN merges do not emit ordinary push CI. Repair a missed dispatch
  // on the next event/schedule too, including a crash between merge and dispatch.
  async function reconcileDelivery() {
    const head = await branch();
    const {data: commit} = await github.rest.repos.getCommit({...repo, ref: head});
    const generated = commit.parents.length === 1 &&
      commit.commit.message.split('\n')[0] === GENERATED_TITLE &&
      commit.committer?.login === 'github-actions[bot]';
    const source = generated ? commit.parents[0].sha : head;
    const runs = await runsFor(BUILD, {branch: 'dev', head_sha: source});
    if (source !== head) runs.push(...await runsFor(BUILD, {branch: 'dev', head_sha: head}));
    // A speculative upstream refresh must not poison routine dev delivery.
    // Wait while it runs, but retain the last successful baseline if it fails.
    if (runs.some(run => run.status !== 'completed')) return false;
    const run = latest(runs.filter(run =>
      run.display_title !== REFRESH_TITLE || run.conclusion === 'success'));
    if (!run) {
      if (await branch() !== head) return false;
      await act(`Dispatch ${BUILD} on dev (${head}).`, () => github.rest.actions.createWorkflowDispatch({
        ...repo, workflow_id: BUILD, ref: 'dev',
      }));
      return false;
    }
    if (run.conclusion !== 'success') {
      await retry(run);
      return false;
    }
    return true;
  }

  try {
    if (['schedule', 'workflow_dispatch'].includes(context.eventName)) {
      // Refresh the schedule's activity through the Actions API, without dummy
      // source commits. Never re-enable a workflow deliberately disabled by a user.
      const {data: self} = await github.rest.actions.getWorkflow({
        ...repo, workflow_id: 'auto-merge-dependabot.yml',
      });
      if (self.state === 'active') await act('Keep the maintenance schedule active.', () =>
        github.rest.actions.enableWorkflow({...repo, workflow_id: self.id}));
    }
    const deliveryReady = await reconcileDelivery();
    const pulls = await github.paginate(github.rest.pulls.list, {...repo, state: 'open', base: 'dev', per_page: 100});
    const candidates = pulls.filter(pull => eligible(pull, repository));
    for (const listed of candidates) {
      try {
        const {data: pull} = await github.rest.pulls.get({...repo, pull_number: listed.number});
        if (!eligible(pull, repository)) continue;
        const base = await branch();

        const files = await github.paginate(github.rest.pulls.listFiles, {
          ...repo, pull_number: pull.number, per_page: 100,
        });
        const commits = await github.paginate(github.rest.pulls.listCommits, {
          ...repo, pull_number: pull.number, per_page: 100,
        });
        if (!trustedFiles(files, pull) || !verifiedCommits(commits, pull)) {
          core.warning(`Skipping #${pull.number}: unexpected files or unsigned/non-Dependabot commits.`);
          continue;
        }
        const {data: fresh} = await github.rest.pulls.get({...repo, pull_number: pull.number});
        if (!eligible(fresh, repository) || fresh.head.sha !== pull.head.sha || await branch() !== base) {
          note(`State changed for #${pull.number}; reconcile again on the next event.`);
          continue;
        }
        if (fresh.mergeable === false) {
          // Ask Dependabot to resolve real merge conflicts. A clean PR does
          // not need a rebase merely because dev has advanced.
          const comments = await github.paginate(github.rest.issues.listComments, {
            ...repo, issue_number: pull.number, per_page: 100,
          });
          const marker = '<!-- dependabot-maintenance:rebase -->';
          const recent = comments.some(comment => ['OWNER', 'MEMBER', 'COLLABORATOR'].includes(comment.author_association) &&
            comment.body?.includes(marker) && comment.body.includes(`(${base}).`) &&
            Date.now() - Date.parse(comment.created_at) < DAY);
          if (!rebaser && !dry) { core.warning('PAT_TOKEN is required only to request a Dependabot rebase.'); continue; }
          if (!recent) await act(`Request Dependabot rebase for #${pull.number} onto dev ${base}.`, () =>
            rebaser.rest.issues.createComment({...repo, issue_number: pull.number,
              body: `@dependabot rebase\n\n${marker}\nUpdate against the current dev branch (${base}).`}));
          else note(`Waiting for Dependabot to rebase #${pull.number}.`);
          continue;
        }

        // Merge only the verified head into dev with the repository Actions token.
        // Never execute a PR checkout or use an administrator PAT for merging.
        const result = await act(`Merge Dependabot #${pull.number} at ${pull.head.sha}.`, () =>
          github.rest.pulls.merge({...repo, pull_number: pull.number, sha: pull.head.sha,
            merge_method: 'squash', commit_title: `${pull.title} (#${pull.number})`}));
        if (dry) continue;
        if (!result.data.merged) throw new Error(result.data.message);
        note(`Merged #${pull.number} as ${result.data.sha}.`);
        await reconcileDelivery();
        break;
      } catch (error) {
        if ([405, 409].includes(error.status)) core.warning(`GitHub deferred merge: ${error.message}`);
        else core.setFailed(error.message);
      }
    }

    if (candidates.length === 0 && deliveryReady &&
        (context.eventName === 'schedule' || process.env.REFRESH_DEPENDENCIES === 'true')) {
      const refreshRuns = (await runsFor(BUILD, {branch: 'dev', event: 'workflow_dispatch'}))
        .filter(run => run.display_title === REFRESH_TITLE);
      const previous = latest(refreshRuns);
      if (!previous || Date.now() - Date.parse(previous.created_at) >= 7 * DAY) {
        await act('Dispatch the weekly upstream refresh on dev.', () => github.rest.actions.createWorkflowDispatch({
          ...repo, workflow_id: BUILD, ref: 'dev', inputs: {refresh_dependencies: 'true'},
        }));
      } else note(`Weekly upstream refresh already attempted: ${previous.html_url}`);
    }
  } finally {
    await core.summary.addHeading('Dependabot maintenance').addList(rows.length ? rows : ['No action needed.']).write();
  }
};
module.exports.eligible = eligible;
module.exports.trustedFiles = trustedFiles;
module.exports.verifiedCommits = verifiedCommits;
module.exports.latest = latest;
