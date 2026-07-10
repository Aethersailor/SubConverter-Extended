'use strict';

const DAY_MS = 24 * 60 * 60 * 1000;
const MAINTAINER_ASSOCIATIONS = new Set(['OWNER', 'MEMBER', 'COLLABORATOR']);
const WARNING_MARKER = '<!-- inactive-issue-feedback-warning -->';
const CLOSE_MARKER = '<!-- inactive-issue-auto-close -->';

const LABELS = {
  waiting: {
    name: 'status: waiting-feedback',
    color: 'FBCA04',
    description: 'Waiting for the issue author or community to respond',
  },
  stale: {
    name: 'status: stale',
    color: 'D93F0B',
    description: 'No response after the maintainer feedback deadline',
  },
  keepOpen: {
    name: 'status: keep-open',
    color: '1D76DB',
    description: 'Exempt this issue from automatic inactivity closure',
  },
  autoClosed: {
    name: 'status: auto-closed',
    color: '6E7781',
    description: 'Automatically closed after no response to a maintainer',
  },
};

function isMaintainer(comment) {
  return MAINTAINER_ASSOCIATIONS.has(comment.author_association);
}

function isHuman(comment) {
  return comment.user?.type !== 'Bot';
}

function labelNames(issue) {
  return new Set((issue.labels || []).map((label) =>
    typeof label === 'string' ? label : label.name,
  ));
}

function inferCloseReason(body = '') {
  const completed = /(?:已修复|已经修复|修复完成|已解决|已经解决|问题已解决|已实现|已经实现|已完成|已经完成|已更新|已经更新|已回补|fixed|resolved|implemented|completed)/i;
  return completed.test(body) ? 'completed' : 'not_planned';
}

function evaluateIssue({ issue, comments, now, waitDays, graceDays }) {
  if (issue.pull_request) return { action: 'skip', reason: 'pull-request' };
  if (issue.state !== 'open') return { action: 'skip', reason: 'not-open' };
  if (issue.user?.type === 'Bot' || MAINTAINER_ASSOCIATIONS.has(issue.author_association)) {
    return { action: 'clear', reason: 'maintainer-or-bot-authored' };
  }

  const labels = labelNames(issue);
  if (labels.has(LABELS.keepOpen.name) || issue.milestone) {
    return { action: 'clear', reason: 'explicitly-exempt' };
  }

  const orderedComments = [...comments].sort((left, right) =>
    new Date(left.created_at) - new Date(right.created_at),
  );
  const humanComments = orderedComments.filter(isHuman);
  const maintainerComments = humanComments.filter(isMaintainer);
  const lastMaintainer = maintainerComments.at(-1);
  if (!lastMaintainer) return { action: 'clear', reason: 'no-maintainer-response' };

  const externalReply = humanComments.find((comment) =>
    !isMaintainer(comment)
      && new Date(comment.created_at) > new Date(lastMaintainer.created_at),
  );
  if (externalReply) return { action: 'clear', reason: 'external-reply-after-maintainer' };

  const maintainerAt = new Date(lastMaintainer.created_at);
  const inactiveDays = (now - maintainerAt) / DAY_MS;
  if (inactiveDays < waitDays) {
    return { action: 'wait', lastMaintainer, inactiveDays };
  }

  const validWarnings = orderedComments.filter((comment) =>
    comment.user?.type === 'Bot'
      && comment.body?.includes(WARNING_MARKER)
      && new Date(comment.created_at) >= maintainerAt,
  );
  const warning = validWarnings.at(-1);
  if (!warning) return { action: 'warn', lastMaintainer, inactiveDays };

  const warningDays = (now - new Date(warning.created_at)) / DAY_MS;
  if (warningDays < graceDays) {
    return { action: 'grace', lastMaintainer, inactiveDays, warningDays };
  }

  return {
    action: 'close',
    lastMaintainer,
    inactiveDays,
    warningDays,
    closeReason: inferCloseReason(lastMaintainer.body),
  };
}

async function run({ github, context, core }) {
  const owner = context.repo.owner;
  const repo = context.repo.repo;
  const waitDays = Number(process.env.INACTIVE_ISSUE_WAIT_DAYS || 14);
  const graceDays = Number(process.env.INACTIVE_ISSUE_GRACE_DAYS || 7);
  const dryRun = process.env.INACTIVE_ISSUE_DRY_RUN === 'true';
  const now = new Date();
  const results = [];

  if (!Number.isFinite(waitDays) || waitDays < 1 || !Number.isFinite(graceDays) || graceDays < 1) {
    throw new Error('The inactivity and grace periods must be positive numbers.');
  }

  async function mutate(description, operation) {
    if (dryRun) {
      core.info(`[dry-run] ${description}`);
      return;
    }
    core.info(description);
    await operation();
  }

  async function ensureLabels() {
    for (const label of Object.values(LABELS)) {
      try {
        await github.rest.issues.getLabel({ owner, repo, name: label.name });
      } catch (error) {
        if (error.status !== 404) throw error;
        await mutate(`Create label ${label.name}`, () => github.rest.issues.createLabel({
          owner,
          repo,
          name: label.name,
          color: label.color,
          description: label.description,
        }));
      }
    }
  }

  async function addLabel(issueNumber, currentLabels, label) {
    if (currentLabels.has(label)) return;
    await mutate(`Add ${label} to #${issueNumber}`, () => github.rest.issues.addLabels({
      owner,
      repo,
      issue_number: issueNumber,
      labels: [label],
    }));
    currentLabels.add(label);
  }

  async function removeLabel(issueNumber, currentLabels, label) {
    if (!currentLabels.has(label)) return;
    await mutate(`Remove ${label} from #${issueNumber}`, async () => {
      try {
        await github.rest.issues.removeLabel({ owner, repo, issue_number: issueNumber, name: label });
      } catch (error) {
        if (error.status !== 404) throw error;
      }
    });
    currentLabels.delete(label);
  }

  async function clearActiveLabels(issueNumber, currentLabels) {
    await removeLabel(issueNumber, currentLabels, LABELS.waiting.name);
    await removeLabel(issueNumber, currentLabels, LABELS.stale.name);
    await removeLabel(issueNumber, currentLabels, LABELS.autoClosed.name);
  }

  async function getIssues() {
    if (context.eventName === 'issue_comment') {
      if (context.payload.issue?.pull_request || context.payload.sender?.type === 'Bot') return [];
      const { data } = await github.rest.issues.get({
        owner,
        repo,
        issue_number: context.payload.issue.number,
      });
      return [data];
    }

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

  await ensureLabels();
  const issues = await getIssues();

  for (const issue of issues) {
    const comments = await github.paginate(github.rest.issues.listComments, {
      owner,
      repo,
      issue_number: issue.number,
      per_page: 100,
    });
    const outcome = evaluateIssue({ issue, comments, now, waitDays, graceDays });
    const currentLabels = labelNames(issue);
    results.push({ issue: `#${issue.number}`, action: outcome.action, reason: outcome.reason || '' });

    if (outcome.action === 'skip') continue;
    if (outcome.action === 'clear') {
      await clearActiveLabels(issue.number, currentLabels);
      continue;
    }

    await addLabel(issue.number, currentLabels, LABELS.waiting.name);

    if (outcome.action === 'wait') {
      await removeLabel(issue.number, currentLabels, LABELS.stale.name);
      await removeLabel(issue.number, currentLabels, LABELS.autoClosed.name);
      continue;
    }

    if (outcome.action === 'warn') {
      await addLabel(issue.number, currentLabels, LABELS.stale.name);
      await mutate(`Warn #${issue.number} about inactivity`, () => github.rest.issues.createComment({
        owner,
        repo,
        issue_number: issue.number,
        body: `${WARNING_MARKER}\n维护者回复后已等待 ${waitDays} 天，但尚未收到进一步反馈。此 Issue 已被自动标记为等待关闭；如果接下来 ${graceDays} 天内仍无新回复，它将被自动关闭。`,
      }));
      continue;
    }

    if (outcome.action === 'grace') {
      await addLabel(issue.number, currentLabels, LABELS.stale.name);
      continue;
    }

    if (outcome.action === 'close') {
      await mutate(`Comment before closing #${issue.number}`, () => github.rest.issues.createComment({
        owner,
        repo,
        issue_number: issue.number,
        body: `${CLOSE_MARKER}\n维护者最后一次回复后未收到进一步反馈，本 Issue 现已自动关闭。若问题仍然存在，请补充最新版本、复现步骤和相关日志，维护者可以据此重新打开。`,
      }));
      await addLabel(issue.number, currentLabels, LABELS.autoClosed.name);
      await removeLabel(issue.number, currentLabels, LABELS.waiting.name);
      await removeLabel(issue.number, currentLabels, LABELS.stale.name);
      await mutate(`Close #${issue.number} as ${outcome.closeReason}`, () => github.rest.issues.update({
        owner,
        repo,
        issue_number: issue.number,
        state: 'closed',
        state_reason: outcome.closeReason,
      }));
    }
  }

  await core.summary
    .addHeading(`Inactive issue management${dryRun ? ' (dry run)' : ''}`)
    .addTable([
      [{ data: 'Issue', header: true }, { data: 'Action', header: true }, { data: 'Reason', header: true }],
      ...results.map((result) => [result.issue, result.action, result.reason]),
    ])
    .write();
}

module.exports = run;
module.exports.evaluateIssue = evaluateIssue;
module.exports.inferCloseReason = inferCloseReason;
module.exports.LABELS = LABELS;
module.exports.WARNING_MARKER = WARNING_MARKER;
