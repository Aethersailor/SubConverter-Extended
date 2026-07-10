'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  evaluateIssue,
  inferCloseReason,
  LABELS,
  WARNING_MARKER,
} = require('./manage-inactive-issues.cjs');

const NOW = new Date('2026-07-10T12:00:00Z');

function issue(overrides = {}) {
  return {
    number: 1,
    state: 'open',
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
    graceDays: 7,
  });
}

test('does not touch an issue before a maintainer responds', () => {
  assert.deepEqual(evaluate(issue(), [comment(20, 'NONE')]), {
    action: 'clear',
    reason: 'no-maintainer-response',
  });
});

test('starts waiting automatically after a recent maintainer response', () => {
  assert.equal(evaluate(issue(), [comment(5, 'OWNER')]).action, 'wait');
});

test('clears automation labels after a community response', () => {
  const outcome = evaluate(issue(), [comment(10, 'OWNER'), comment(2, 'NONE')]);
  assert.deepEqual(outcome, {
    action: 'clear',
    reason: 'external-reply-after-maintainer',
  });
});

test('warns after fourteen days without feedback', () => {
  assert.equal(evaluate(issue(), [comment(14, 'OWNER')]).action, 'warn');
});

test('waits through the seven day warning grace period', () => {
  const warning = comment(3, 'NONE', {
    user: { login: 'github-actions[bot]', type: 'Bot' },
    body: WARNING_MARKER,
  });
  assert.equal(evaluate(issue(), [comment(20, 'OWNER'), warning]).action, 'grace');
});

test('closes after the warning grace period', () => {
  const warning = comment(8, 'NONE', {
    user: { login: 'github-actions[bot]', type: 'Bot' },
    body: WARNING_MARKER,
  });
  assert.equal(evaluate(issue(), [comment(23, 'OWNER'), warning]).action, 'close');
});

test('ignores an old warning after a newer maintainer response', () => {
  const warning = comment(20, 'NONE', {
    user: { login: 'github-actions[bot]', type: 'Bot' },
    body: WARNING_MARKER,
  });
  assert.equal(evaluate(issue(), [warning, comment(5, 'OWNER')]).action, 'wait');
});

test('exempts milestones and keep-open issues', () => {
  const keepOpen = issue({ labels: [{ name: LABELS.keepOpen.name }] });
  const milestone = issue({ milestone: { number: 1 } });
  assert.equal(evaluate(keepOpen, [comment(30, 'OWNER')]).reason, 'explicitly-exempt');
  assert.equal(evaluate(milestone, [comment(30, 'OWNER')]).reason, 'explicitly-exempt');
});

test('uses completed only when a maintainer explicitly reports completion', () => {
  assert.equal(inferCloseReason('已修复，请测试'), 'completed');
  assert.equal(inferCloseReason('请补充完整日志'), 'not_planned');
});
