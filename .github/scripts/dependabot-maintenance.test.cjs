'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const maintain = require('./dependabot-maintenance.cjs');
const repository = 'Aethersailor/SubConverter-Extended';
const pull = () => ({number: 134, state: 'open', draft: false,
  user: {login: 'dependabot[bot]'}, title: 'build(deps): update Go dependencies',
  base: {ref: 'dev', repo: {full_name: repository}},
  head: {ref: 'dependabot/gomod/update', sha: 'candidate', repo: {full_name: repository}},
  labels: [{name: 'automerge'}]});
const run = () => ({id: 42, path: '.github/workflows/pr-validation.yml', event: 'pull_request',
  actor: {login: 'dependabot[bot]'}, head_repository: {full_name: repository}, head_sha: 'candidate',
  status: 'completed', conclusion: 'success', run_attempt: 1});
const jobs = () => [{name: 'PR Gate', status: 'completed', conclusion: 'success'}];

test('only labeled, same-repository Dependabot updates targeting dev are eligible', () => {
  assert.equal(maintain.eligible(pull(), repository), true);
  for (const change of [p => p.user.login = 'contributor', p => p.base.ref = 'master',
    p => p.head.repo.full_name = 'outside/fork', p => p.draft = true,
    p => p.state = 'closed', p => p.labels = [], p => p.title = 'unstructured update',
    p => p.head.ref = 'feature/update']) {
    const candidate = pull(); change(candidate);
    assert.equal(maintain.eligible(candidate, repository), false);
  }
});

test('a successful lookalike or stale workflow cannot authorize a merge', () => {
  assert.equal(maintain.validated(run(), pull(), repository, jobs()), true);
  for (const change of [r => r.path = '.github/workflows/other.yml', r => r.event = 'push',
    r => r.actor.login = 'contributor', r => r.head_repository.full_name = 'outside/fork',
    r => r.head_sha = 'stale', r => r.conclusion = 'failure', r => r.status = 'in_progress']) {
    const result = run(); change(result);
    assert.equal(maintain.validated(result, pull(), repository, jobs()), false);
  }
  assert.equal(maintain.validated(run(), pull(), repository, []), false);
  assert.equal(maintain.validated(run(), pull(), repository,
    [...jobs(), {name: 'CodeQL', status: 'completed', conclusion: 'failure'}]), false);
});

function fixture(options = {}) {
  let head = 'base';
  const writes = [];
  const errors = [];
  const rest = {repos: {}, pulls: {}, actions: {}, issues: {}};
  rest.repos.getBranch = async () => ({data: {commit: {sha: head}}});
  rest.repos.getCommit = async () => ({data: {parents: [], commit: {message: 'fix: baseline'}}});
  rest.repos.compareCommits = async () => ({data: {merge_base_commit: {sha: options.behind ? 'old' : head}}});
  rest.pulls.get = async () => ({data: pull()});
  rest.pulls.merge = async args => {
    writes.push(['merge', args]); head = 'merged'; return {data: {merged: true, sha: head}};
  };
  for (const name of ['createWorkflowDispatch', 'reRunWorkflowFailedJobs']) {
    rest.actions[name] = async args => { writes.push([name, args]); };
  }
  rest.issues.createComment = async args => { writes.push(['comment', args]); };
  rest.actions.listWorkflowRuns = 'runs';
  rest.actions.listJobsForWorkflowRun = 'jobs';
  rest.pulls.list = 'pulls';
  rest.issues.listComments = 'comments';
  const github = {rest, paginate: async (method, args) => {
    if (method === 'pulls') return options.empty ? [] : [pull()];
    if (method === 'jobs') return jobs();
    if (method === 'comments') return options.recentRebase ? [{user: {login: 'github-actions[bot]'},
      body: '<!-- dependabot-maintenance:rebase -->', created_at: new Date().toISOString()}] : [];
    if (method === 'runs') {
      if (args.workflow_id === 'pr-validation.yml') return [{...run(), ...options.validation}];
      if (args.event === 'workflow_dispatch') return options.refreshRuns || [];
      if (head === 'merged' || options.missingDelivery) return [];
      const normal = {id: 10, run_attempt: 1, status: 'completed', conclusion: 'success'};
      return options.failedRefresh ? [normal, {id: 20, status: 'completed', conclusion: 'failure',
        display_title: 'Refresh upstream dependencies on dev'}] : [normal];
    }
    throw new Error(`Unexpected API request: ${method}`);
  }};
  const summary = {addHeading() {return this;}, addList() {return this;}, async write() {}};
  const core = {info() {}, notice() {}, warning() {}, setFailed(message) {errors.push(message);}, summary};
  return {github, core, writes, errors, context: {repo: {owner: 'Aethersailor', repo: 'SubConverter-Extended'},
    eventName: options.eventName || 'workflow_run'}};
}

async function execute(options = {}) {
  const before = {...process.env};
  process.env.AUTOMERGE_MODE = options.mode || 'active';
  process.env.DRY_RUN = options.dry ? 'true' : 'false';
  process.env.REFRESH_DEPENDENCIES = 'false';
  try {
    const f = fixture(options); await maintain(f); return f;
  } finally {
    for (const key of ['AUTOMERGE_MODE', 'DRY_RUN', 'REFRESH_DEPENDENCIES']) {
      if (before[key] === undefined) delete process.env[key]; else process.env[key] = before[key];
    }
  }
}

test('successful current candidate merges with SHA precondition and dispatches both dev workflows', async () => {
  const f = await execute();
  assert.deepEqual(f.errors, []);
  assert.deepEqual(f.writes.map(w => w[0]), ['merge', 'createWorkflowDispatch', 'createWorkflowDispatch']);
  assert.equal(f.writes[0][1].sha, 'candidate');
  assert.deepEqual(f.writes.slice(1).map(w => [w[1].workflow_id, w[1].ref]),
    [['build-dockerhub.yml', 'dev'], ['codeql.yml', 'dev']]);
});

test('observe, dry-run and off modes never write', async () => {
  for (const options of [{mode: 'observe'}, {dry: true}, {mode: 'off'}]) {
    assert.deepEqual((await execute(options)).writes, []);
  }
});

test('outdated baseline requests official rebase and deduplicates requests', async () => {
  const f = await execute({behind: true});
  assert.deepEqual(f.writes.map(w => w[0]), ['comment']);
  assert.match(f.writes[0][1].body, /^@dependabot rebase/);
  assert.deepEqual((await execute({behind: true, recentRebase: true})).writes, []);
});

test('failed validation retries only failed jobs and stops at the attempt budget', async () => {
  const f = await execute({validation: {conclusion: 'failure'}});
  assert.deepEqual(f.writes.map(w => w[0]), ['reRunWorkflowFailedJobs']);
  for (const validation of [{conclusion: 'failure', run_attempt: 3},
    {status: 'in_progress', conclusion: null}]) {
    assert.deepEqual((await execute({validation})).writes, []);
  }
});

test('missing post-merge CI is repaired without merging another dependency first', async () => {
  const f = await execute({missingDelivery: true});
  assert.deepEqual(f.writes.map(w => w[0]), ['createWorkflowDispatch', 'createWorkflowDispatch']);
});

test('failed speculative refresh does not block a validated routine update', async () => {
  assert.equal((await execute({failedRefresh: true})).writes[0][0], 'merge');
});

test('weekly refresh runs on dev with an empty queue and is deduplicated', async () => {
  const f = await execute({empty: true, eventName: 'schedule'});
  assert.equal(f.writes.length, 1);
  assert.deepEqual(f.writes[0][1].inputs, {refresh_dependencies: 'true'});
  assert.equal(f.writes[0][1].ref, 'dev');
  const recent = {id: 60, display_title: 'Refresh upstream dependencies on dev', created_at: new Date().toISOString()};
  assert.deepEqual((await execute({empty: true, eventName: 'schedule', refreshRuns: [recent]})).writes, []);
});
