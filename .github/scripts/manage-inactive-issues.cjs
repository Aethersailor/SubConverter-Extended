'use strict';

const DAY_MS = 24 * 60 * 60 * 1000;
const REMINDER_MARKER = '<!-- inactive-issue-reminder -->';
const CLOSE_MARKER = '<!-- inactive-issue-auto-close -->';
const ISSUE_QUERY = `query($owner: String!, $repo: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $repo) {
    issue(number: $number) {
      number state createdAt updatedAt lastEditedAt
      editor { __typename }
      timelineItems(last: 1, itemTypes: [REOPENED_EVENT]) {
        nodes { ... on ReopenedEvent { createdAt } }
      }
      comments(first: 100, after: $cursor) {
        nodes {
          id body createdAt lastEditedAt
          author { login __typename }
          editor { __typename }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}`;

function isHuman(actor) {
  return actor?.__typename !== 'Bot';
}

function isAutomationComment(comment) {
  return comment.author?.__typename === 'Bot'
    && ['github-actions', 'github-actions[bot]'].includes(comment.author.login);
}

function activityMarker(lastActivityAt) {
  return `<!-- inactive-issue-activity:${lastActivityAt.toISOString()} -->`;
}

function lastHumanActivityAt(issue, comments) {
  const timestamps = [issue.createdAt, issue.reopenedAt];
  if (isHuman(issue.editor)) timestamps.push(issue.lastEditedAt);
  for (const comment of comments) {
    if (isHuman(comment.author)) timestamps.push(comment.createdAt);
    if (isHuman(comment.editor)) timestamps.push(comment.lastEditedAt);
  }
  return new Date(Math.max(...timestamps.filter(Boolean).map((value) => new Date(value).getTime())));
}

function evaluateIssue({ issue, comments, now, waitDays = 30, graceDays = 7 }) {
  if (issue.pull_request) return { action: 'skip', reason: 'pull-request' };
  if (issue.state !== 'OPEN') return { action: 'skip', reason: 'not-open' };

  const lastActivityAt = lastHumanActivityAt(issue, comments);
  const remindAfter = new Date(lastActivityAt.getTime() + waitDays * DAY_MS);
  const marker = activityMarker(lastActivityAt);
  const reminderTimes = comments
    .filter((comment) => isAutomationComment(comment)
      && comment.body.includes(REMINDER_MARKER) && comment.body.includes(marker))
    .map((comment) => new Date(comment.createdAt).getTime())
    .filter((time) => time >= remindAfter.getTime() && time <= now.getTime());
  const reminderAt = reminderTimes.length ? new Date(Math.min(...reminderTimes)) : null;
  const nextActionAt = reminderAt
    ? new Date(reminderAt.getTime() + graceDays * DAY_MS) : remindAfter;
  const action = now < nextActionAt ? 'wait' : reminderAt ? 'close' : 'remind';
  return { action, lastActivityAt, reminderAt, nextActionAt };
}

function reminderBody(outcome, waitDays, graceDays) {
  return `${REMINDER_MARKER}\n${activityMarker(outcome.lastActivityAt)}\n`
    + `此 Issue 已连续 ${waitDays} 天没有人工活动。如果仍无人工更新，将在本提醒发出至少 ${graceDays} 天后自动归档关闭。若仍需跟进，请回复当前情况；新增或编辑人工评论、编辑正文或重新打开，都会重新开始计时。自动归档不表示问题已解决。\n\n`
    + `This issue has had no human activity for ${waitDays} days. If there are no human updates, it will be automatically closed for inactivity at least ${graceDays} days after this reminder. If follow-up is still needed, please reply with the current status. A new or edited human comment, a body edit, or reopening the issue restarts the timer. Automatic closure does not mean the problem is resolved.`;
}

function closeBody(outcome, graceDays) {
  return `${CLOSE_MARKER}\n${activityMarker(outcome.lastActivityAt)}\n`
    + `此 Issue 在提醒发出后至少 ${graceDays} 天仍无人工活动，现因长期无活动自动归档关闭。这不表示问题已解决，讨论不会被自动锁定。若仍需跟进，请补充当前情况后重新打开；若无法重新打开，可新建 Issue 并关联本帖。重新打开后将重新开始计时。\n\n`
    + `This issue is being automatically closed for inactivity because there has been no human activity for at least ${graceDays} days after the reminder. This does not mean the problem is resolved, and the discussion will not be automatically locked. If follow-up is still needed, add the current status and reopen the issue. If you cannot reopen it, create a new issue and link to this one. Reopening restarts the timer.`;
}

async function run({ github, context, core }) {
  const { owner, repo } = context.repo;
  const waitDays = Number(process.env.INACTIVE_ISSUE_WAIT_DAYS || 30);
  const graceDays = Number(process.env.INACTIVE_ISSUE_GRACE_DAYS || 7);
  const dryRun = process.env.INACTIVE_ISSUE_DRY_RUN === 'true';
  const now = new Date();
  const results = [];
  if (![waitDays, graceDays].every((days) => Number.isFinite(days) && days >= 1)) {
    throw new Error('等待期和宽限期必须为正天数。 / Waiting and grace periods must be positive day counts.');
  }

  async function mutate(description, operation) {
    core.info(`${dryRun ? '[仅预览 / dry-run] ' : ''}${description}`);
    if (!dryRun) await operation();
  }

  async function getSnapshot(number) {
    let cursor = null;
    let issue;
    const comments = [];
    do {
      const data = await github.graphql(ISSUE_QUERY, { owner, repo, number, cursor });
      const page = data.repository?.issue;
      if (!page) throw new Error(`无法读取 Issue #${number}。 / Cannot read issue #${number}.`);
      if (!issue) {
        const { comments: connection, timelineItems, ...metadata } = page;
        issue = { ...metadata, reopenedAt: timelineItems.nodes[0]?.createdAt };
      } else if (issue.updatedAt !== page.updatedAt) {
        throw new Error(`读取期间 Issue #${number} 已变化，请重新运行。 / Issue #${number} changed during pagination; rerun the workflow.`);
      }
      comments.push(...page.comments.nodes);
      cursor = page.comments.pageInfo.hasNextPage ? page.comments.pageInfo.endCursor : null;
    } while (cursor);
    return { issue, comments };
  }

  function evaluate(snapshot) {
    return evaluateIssue({ ...snapshot, now, waitDays, graceDays });
  }

  const issues = await github.paginate(github.rest.issues.listForRepo, {
    owner, repo, state: 'open', sort: 'updated', direction: 'desc', per_page: 100,
  });
  for (const listedIssue of issues.filter((issue) => !issue.pull_request)) {
    const number = listedIssue.number;
    const snapshot = await getSnapshot(number);
    let outcome = evaluate(snapshot);
    let reason = '';
    if (outcome.action === 'remind' || outcome.action === 'close') {
      const fresh = await getSnapshot(number);
      if (JSON.stringify(snapshot) !== JSON.stringify(fresh)) {
        outcome = { ...evaluate(fresh), action: 'skip' };
        reason = '读取后状态或活动已变化 / State or activity changed after reading';
      } else if (outcome.action === 'remind') {
        await mutate(`提醒 Issue #${number} / Remind issue #${number}`, () => github.rest.issues.createComment({
          owner, repo, issue_number: number, body: reminderBody(outcome, waitDays, graceDays),
        }));
      } else {
        const alreadyCommented = fresh.comments.some((comment) => isAutomationComment(comment)
          && comment.body.includes(CLOSE_MARKER)
          && comment.body.includes(activityMarker(outcome.lastActivityAt))
          && new Date(comment.createdAt) >= outcome.reminderAt);
        if (!alreadyCommented) {
          await mutate(`发表评论后归档 Issue #${number} / Comment before archiving issue #${number}`, () => github.rest.issues.createComment({
            owner, repo, issue_number: number, body: closeBody(outcome, graceDays),
          }));
        }
        const final = evaluate(await getSnapshot(number));
        if (final.action !== 'close' || final.lastActivityAt.getTime() !== outcome.lastActivityAt.getTime()
          || final.reminderAt.getTime() !== outcome.reminderAt.getTime()) {
          outcome = { ...final, action: 'skip' };
          reason = '关闭前状态或活动已变化 / State or activity changed before closure';
        } else {
          await mutate(`归档关闭 Issue #${number} / Close issue #${number} for inactivity`, () => github.rest.issues.update({
            owner, repo, issue_number: number, state: 'closed', state_reason: 'not_planned',
          }));
        }
      }
    }
    const reasons = {
      'pull-request': '跳过 PR / Pull request excluded',
      'not-open': 'Issue 已关闭 / Issue is not open',
    };
    results.push([
      `#${number}`,
      { wait: '等待 / Wait', remind: '提醒 / Remind', close: '关闭 / Close', skip: '跳过 / Skip' }[outcome.action],
      outcome.lastActivityAt?.toISOString() || '—',
      outcome.reminderAt?.toISOString() || '—',
      outcome.nextActionAt?.toISOString() || '—',
      reason || reasons[outcome.reason] || '—',
    ]);
  }
  await core.summary
    .addHeading(`不活跃 Issue 归档 / Inactive issue archival${dryRun ? '（仅预览 / dry run）' : ''}`)
    .addTable([
      ['Issue / 议题', '操作 / Action', '最后人工活动 / Last human activity (UTC)',
        '提醒时间 / Reminder (UTC)', '下次操作时间 / Next action (UTC)', '原因 / Reason']
        .map((data) => ({ data, header: true })),
      ...results,
    ])
    .write();
}

module.exports = run;
module.exports.evaluateIssue = evaluateIssue;
module.exports.lastHumanActivityAt = lastHumanActivityAt;
module.exports.activityMarker = activityMarker;
module.exports.REMINDER_MARKER = REMINDER_MARKER;
module.exports.CLOSE_MARKER = CLOSE_MARKER;
