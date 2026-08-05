'use strict';

const DAY_MS = 24 * 60 * 60 * 1000;
const CLOSE_MARKER = '<!-- inactive-issue-auto-close -->';

function isHuman(comment) {
  return comment.user?.type !== 'Bot';
}

function lastHumanActivityAt(issue, comments) {
  return comments
    .filter(isHuman)
    .reduce((latest, comment) => {
      const createdAt = new Date(comment.created_at);
      return createdAt > latest ? createdAt : latest;
    }, new Date(issue.created_at));
}

function evaluateIssue({ issue, comments, now, waitDays }) {
  if (issue.pull_request) return { action: 'skip', reason: 'pull-request' };
  if (issue.state !== 'open') return { action: 'skip', reason: 'not-open' };

  const lastActivityAt = lastHumanActivityAt(issue, comments);
  const inactiveDays = (now - lastActivityAt) / DAY_MS;
  return inactiveDays >= waitDays
    ? { action: 'close', lastActivityAt, inactiveDays }
    : { action: 'wait', lastActivityAt, inactiveDays };
}

async function run({ github, context, core }) {
  const owner = context.repo.owner;
  const repo = context.repo.repo;
  const waitDays = Number(process.env.INACTIVE_ISSUE_WAIT_DAYS || 14);
  const dryRun = process.env.INACTIVE_ISSUE_DRY_RUN === 'true';
  const now = new Date();
  const results = [];

  if (!Number.isFinite(waitDays) || waitDays < 1) {
    throw new Error('The inactivity period must be a positive number.');
  }

  async function mutate(description, operation) {
    if (dryRun) {
      core.info(`[dry-run] ${description}`);
      return;
    }
    core.info(description);
    await operation();
  }

  async function getIssues() {
    const issues = await github.paginate(github.rest.issues.listForRepo, {
      owner,
      repo,
      state: 'open',
      sort: 'updated',
      direction: 'desc',
      per_page: 100,
    });
    return issues.filter((issue) => !issue.pull_request);
  }

  const issues = await getIssues();

  for (const issue of issues) {
    const comments = await github.paginate(github.rest.issues.listComments, {
      owner,
      repo,
      issue_number: issue.number,
      per_page: 100,
    });
    const outcome = evaluateIssue({ issue, comments, now, waitDays });
    results.push({ issue: `#${issue.number}`, action: outcome.action, reason: outcome.reason || '' });

    if (outcome.action !== 'close') continue;

    const alreadyCommented = comments.some((comment) =>
      comment.body?.includes(CLOSE_MARKER)
        && new Date(comment.created_at) >= outcome.lastActivityAt,
    );
    if (!alreadyCommented) {
      await mutate(`Comment before closing #${issue.number}`, () => github.rest.issues.createComment({
        owner,
        repo,
        issue_number: issue.number,
        body: `${CLOSE_MARKER}\n此 Issue 已连续 ${waitDays} 天没有收到新回复，现自动关闭。若问题仍然存在，请补充最新版本、复现步骤和相关日志后重新打开。`,
      }));
    }
    await mutate(`Close #${issue.number} after ${waitDays} inactive days`, () => github.rest.issues.update({
      owner,
      repo,
      issue_number: issue.number,
      state: 'closed',
      state_reason: 'not_planned',
    }));
  }

  await core.summary
    .addHeading(`Inactive issue closure${dryRun ? ' (dry run)' : ''}`)
    .addTable([
      [{ data: 'Issue', header: true }, { data: 'Action', header: true }, { data: 'Reason', header: true }],
      ...results.map((result) => [result.issue, result.action, result.reason]),
    ])
    .write();
}

module.exports = run;
module.exports.evaluateIssue = evaluateIssue;
module.exports.lastHumanActivityAt = lastHumanActivityAt;
module.exports.CLOSE_MARKER = CLOSE_MARKER;
