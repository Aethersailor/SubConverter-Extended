'use strict';

const VALIDATION = 'pr-validation.yml';
const BUILD = 'build-dockerhub.yml';
const CODEQL = 'codeql.yml';
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

function validated(run, pull, repository, jobs) {
  return run?.path === `.github/workflows/${VALIDATION}` &&
    run.event === 'pull_request' && run.actor?.login === 'dependabot[bot]' &&
    run.head_repository?.full_name === repository && run.head_sha === pull.head.sha &&
    run.status === 'completed' && run.conclusion === 'success' &&
    jobs.some(job => job.name === 'PR Gate' && job.status === 'completed' && job.conclusion === 'success') &&
    jobs.every(job => job.status === 'completed' && ['success', 'skipped'].includes(job.conclusion));
}

function latest(runs) {
  return [...runs].sort((a, b) => b.id - a.id)[0];
}

module.exports = async function maintain({github, context, core, rebaseGithub}) {
  const mode = (process.env.AUTOMERGE_MODE || 'off').toLowerCase();
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
    if (!['failure', 'cancelled', 'timed_out', 'startup_failure'].includes(run.conclusion)) {
      core.warning(`Run ${run.id} needs attention (${run.conclusion}): ${run.html_url}`);
      return;
    }
    if (run.run_attempt >= MAX_ATTEMPTS) {
      core.warning(`Run ${run.id} still fails after ${MAX_ATTEMPTS} attempts; keeping the gate closed: ${run.html_url}`);
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
    let ready = true;
    for (const workflow of [BUILD, CODEQL]) {
      const checkedSource = workflow === CODEQL ? head : source;
      const runs = await runsFor(workflow, {branch: 'dev', head_sha: checkedSource});
      if (checkedSource !== head) runs.push(...await runsFor(workflow, {branch: 'dev', head_sha: head}));
      // A speculative upstream refresh must not poison routine dev delivery.
      // Wait while it runs, but retain the last successful baseline if it fails.
      if (runs.some(run => run.status !== 'completed')) { ready = false; continue; }
      const run = latest(runs.filter(run =>
        run.display_title !== REFRESH_TITLE || run.conclusion === 'success'));
      if (!run) {
        ready = false;
        if (await branch() !== head) return false;
        await act(`Dispatch ${workflow} on dev (${head}).`, () => github.rest.actions.createWorkflowDispatch({
          ...repo, workflow_id: workflow, ref: 'dev',
        }));
      } else if (run.status !== 'completed' || run.conclusion !== 'success') {
        ready = false;
        await retry(run);
      }
    }
    return ready;
  }

  try {
    const deliveryReady = await reconcileDelivery();
    const pulls = await github.paginate(github.rest.pulls.list, {...repo, state: 'open', base: 'dev', per_page: 100});
    const candidates = pulls.filter(pull => eligible(pull, repository));
    for (const listed of candidates) {
      try {
        const {data: pull} = await github.rest.pulls.get({...repo, pull_number: listed.number});
        if (!eligible(pull, repository)) continue;
        const base = await branch();
        const {data: comparison} = await github.rest.repos.compareCommits({
          ...repo, base, head: pull.head.sha,
        });
        if (comparison.merge_base_commit.sha !== base) {
          // Dependabot owns its branch. Ask its rebaser to refresh the branch so
          // the resulting bot push starts the normal unprivileged PR CI.
          const comments = await github.paginate(github.rest.issues.listComments, {
            ...repo, issue_number: pull.number, per_page: 100,
          });
          const marker = '<!-- dependabot-maintenance:rebase -->';
          const recent = comments.some(comment => ['OWNER', 'MEMBER', 'COLLABORATOR'].includes(comment.author_association) &&
            comment.body?.includes(marker) && Date.now() - Date.parse(comment.created_at) < DAY);
          if (!rebaser && !dry) { core.warning('PAT_TOKEN is required only to request a Dependabot rebase.'); continue; }
          if (!recent) await act(`Request Dependabot rebase for #${pull.number} onto dev ${base}.`, () =>
            rebaser.rest.issues.createComment({...repo, issue_number: pull.number,
              body: `@dependabot rebase\n\n${marker}\nRevalidate against the current dev branch (${base}).`}));
          else note(`Waiting for Dependabot to rebase #${pull.number}.`);
          continue;
        }

        const run = latest(await runsFor(VALIDATION, {event: 'pull_request', head_sha: pull.head.sha}));
        if (!run) { core.warning(`No PR Validation run for #${pull.number} at ${pull.head.sha}.`); continue; }
        if (run.status !== 'completed' || run.conclusion !== 'success') { await retry(run); continue; }
        const jobs = await github.paginate(github.rest.actions.listJobsForWorkflowRun, {
          ...repo, run_id: run.id, filter: 'latest', per_page: 100,
        });
        if (!validated(run, pull, repository, jobs)) throw new Error(`Untrusted or incomplete validation for #${pull.number}`);
        const {data: fresh} = await github.rest.pulls.get({...repo, pull_number: pull.number});
        if (!eligible(fresh, repository) || fresh.head.sha !== pull.head.sha || await branch() !== base) {
          note(`State changed for #${pull.number}; reconcile again on the next event.`);
          continue;
        }
        if (!deliveryReady) { note(`Waiting for current dev delivery before merging #${pull.number}.`); continue; }
        // Let GitHub enforce PR Gate, strict baseline and CodeQL rules with the
        // repository-scoped Actions token. Never use an administrator PAT here.
        const result = await act(`Merge validated Dependabot #${pull.number} at ${pull.head.sha}.`, () =>
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
module.exports.validated = validated;
module.exports.latest = latest;
