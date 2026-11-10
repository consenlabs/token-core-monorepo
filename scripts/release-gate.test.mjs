import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const scripts = ['ios', 'android'].map(platform => {
  const yaml = readFileSync(new URL(`../.github/workflows/build-release-${platform}.yml`, import.meta.url), 'utf8');
  const block = yaml.split('          script: |\n')[1].split('\n\n      - name:')[0];
  return block.split('\n').map(line => line.slice(12)).join('\n');
});
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const evaluate = new AsyncFunction('github', 'context', scripts[0]);
const names = ['cargo fmt', 'cargo clippy', 'cargo test --no-run',
  'host-safe unit tests', 'wasm check', 'dependency audit and licenses'];

function fixture() {
  const state = {
    pr: { head: { sha: 'reviewed' } },
    review: { state: 'APPROVED', commit_id: 'reviewed' },
    runs: [{ id: 1, head_sha: 'reviewed', path: '.github/workflows/run-unittest.yml',
      pull_requests: [{ number: 42 }], status: 'completed', conclusion: 'success' }],
    jobs: names.map(name => ({ name, status: 'completed', conclusion: 'success' })),
  };
  const listRuns = () => state.runs;
  const listJobs = () => state.jobs;
  const github = {
    rest: {
      pulls: { get: async () => ({ data: state.pr }), getReview: async () => ({ data: state.review }) },
      actions: { listWorkflowRunsForRepo: listRuns, listJobsForWorkflowRun: listJobs },
    },
    paginate: async (method, params) => method(params),
  };
  const context = { issue: { owner: 'owner', repo: 'repo', number: 42 },
    payload: { review: { id: 7, commit_id: 'reviewed' } } };
  return { state, run: () => evaluate(github, context) };
}

test('both release workflows enforce the same policy', () => assert.equal(scripts[0], scripts[1]));
test('publishes exactly the reviewed commit after passing gates', async () => {
  assert.equal(await fixture().run(), 'reviewed');
});
for (const [name, change] of [
  ['head advanced while awaiting environment approval', s => { s.pr.head.sha = 'unreviewed'; }],
  ['approval dismissed', s => { s.review.state = 'DISMISSED'; }],
  ['no CI on reviewed SHA', s => { s.runs = []; }],
  ['CI belongs to another PR', s => { s.runs[0].pull_requests = [{ number: 99 }]; }],
  ['latest CI attempt failed', s => { s.runs.push({ ...s.runs[0], id: 2, conclusion: 'failure' }); }],
  ['CI still running', s => { s.runs[0].status = 'in_progress'; }],
  ['missing required job', s => { s.jobs.pop(); }],
  ['skipped job', s => { s.jobs[0].conclusion = 'skipped'; }],
]) {
  test(`rejects ${name}`, async () => {
    const { state, run } = fixture();
    change(state);
    await assert.rejects(run);
  });
}
