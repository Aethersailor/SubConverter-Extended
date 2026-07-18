'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const manageInactiveIssues = require('./manage-inactive-issues.cjs');
const {
  evaluateIssue,
  lastHumanActivityAt,
} = manageInactiveIssues;

const NOW = new Date('2026-07-10T12:00:00Z');

function issue(overrides = {}) {
  return {
    number: 1,
    state: 'open',
    created_at: new Date(NOW - 20 * 24 * 60 * 60 * 1000).toISOString(),
    user: { login: 'reporter', type: 'User' },
    author_association: 'NONE',
    labels: [],
    milestone: null,
    ...overrides,
  };
}

function comment(daysAgo, association, overrides = {}) {
  return {
    created_at: new Date(NOW - daysAgo * 24 * 60 * 60 * 1000).toISOString(),
    author_association: association,
    user: { login: association === 'OWNER' ? 'maintainer' : 'reporter', type: 'User' },
    body: '',
    ...overrides,
  };
}

function evaluate(targetIssue, comments) {
  return evaluateIssue({
    issue: targetIssue,
    comments,
    now: NOW,
    waitDays: 14,
  });
}

test('waits until a new issue has been inactive for fourteen days', () => {
  const target = issue({
    created_at: new Date(NOW - 13 * 24 * 60 * 60 * 1000).toISOString(),
  });
  assert.equal(evaluate(target, []).action, 'wait');
});

test('closes an issue with no replies at the fourteen day boundary', () => {
  const target = issue({
    created_at: new Date(NOW - 14 * 24 * 60 * 60 * 1000).toISOString(),
  });
  assert.equal(evaluate(target, []).action, 'close');
});

test('any recent human reply resets the inactivity period', () => {
  assert.equal(evaluate(issue(), [comment(5, 'NONE')]).action, 'wait');
  assert.equal(evaluate(issue(), [comment(5, 'OWNER')]).action, 'wait');
});

test('closes fourteen days after the latest human reply', () => {
  assert.equal(evaluate(issue(), [comment(18, 'OWNER'), comment(14, 'NONE')]).action, 'close');
});

test('bot comments do not extend the inactivity period', () => {
  const botComment = comment(1, 'NONE', {
    user: { login: 'github-actions[bot]', type: 'Bot' },
  });
  assert.equal(evaluate(issue(), [comment(15, 'OWNER'), botComment]).action, 'close');
});

test('uses the newest human reply regardless of comment order', () => {
  const latest = lastHumanActivityAt(issue(), [comment(3, 'NONE'), comment(9, 'OWNER')]);
  assert.equal(latest.toISOString(), comment(3, 'NONE').created_at);
});

test('labels and milestones do not change the inactivity rule', () => {
  const target = issue({ labels: [{ name: 'status: keep-open' }], milestone: { number: 1 } });
  assert.equal(evaluate(target, []).action, 'close');
});

test('skips pull requests and closed issues', () => {
  assert.equal(evaluate(issue({ pull_request: {} }), []).reason, 'pull-request');
  assert.equal(evaluate(issue({ state: 'closed' }), []).reason, 'not-open');
});

test('scheduled run closes an inactive issue without calling label APIs', async () => {
  const calls = [];
  const listForRepo = Symbol('listForRepo');
  const listComments = Symbol('listComments');
  const github = {
    rest: {
      issues: {
        listForRepo,
        listComments,
        createComment: async (params) => calls.push(['comment', params]),
        update: async (params) => calls.push(['update', params]),
      },
    },
    paginate: async (endpoint) => endpoint === listForRepo ? [issue()] : [],
  };
  const summary = {
    addHeading() { return this; },
    addTable() { return this; },
    async write() {},
  };
  const previousWaitDays = process.env.INACTIVE_ISSUE_WAIT_DAYS;
  const previousDryRun = process.env.INACTIVE_ISSUE_DRY_RUN;
  process.env.INACTIVE_ISSUE_WAIT_DAYS = '14';
  process.env.INACTIVE_ISSUE_DRY_RUN = 'false';

  try {
    await manageInactiveIssues({
      github,
      context: { repo: { owner: 'Aethersailor', repo: 'SubConverter-Extended' } },
      core: { info() {}, summary },
    });
  } finally {
    if (previousWaitDays === undefined) delete process.env.INACTIVE_ISSUE_WAIT_DAYS;
    else process.env.INACTIVE_ISSUE_WAIT_DAYS = previousWaitDays;
    if (previousDryRun === undefined) delete process.env.INACTIVE_ISSUE_DRY_RUN;
    else process.env.INACTIVE_ISSUE_DRY_RUN = previousDryRun;
  }

  assert.deepEqual(calls.map(([operation]) => operation), ['comment', 'update']);
  assert.equal(calls[1][1].state, 'closed');
  assert.equal(calls[1][1].state_reason, 'not_planned');
});
