"""Read-only fail-closed environment and immutable-context guard. No credentials."""
import argparse
import json
import os
import re
import subprocess

REPO = 'GameRisker/lattice-node-releases'
OWNER_ID = 1212241


def validate_environment(environment, policies, name):
    if name not in ('codex-unix-sign', 'codex-unix-publish') or environment.get('name') != name:
        raise ValueError('Unexpected environment')
    if environment.get('can_admins_bypass') is not False:
        raise ValueError('Administrator bypass must be disabled')
    if environment.get('deployment_branch_policy') != {'protected_branches': False, 'custom_branch_policies': True}:
        raise ValueError('Exact custom main branch policy required')
    rules = environment.get('protection_rules', [])
    if sorted(r.get('type', '') for r in rules) != ['branch_policy', 'required_reviewers']:
        raise ValueError('Exact owner approval gate required')
    reviewers = next(r for r in rules if r['type'] == 'required_reviewers')
    if reviewers.get('prevent_self_review') is not False:
        raise ValueError('Single owner must be able to review own dispatch')
    people = reviewers.get('reviewers', [])
    if (len(people) != 1 or people[0].get('type') != 'User'
            or people[0].get('reviewer', {}).get('login') != 'GameRisker'
            or people[0].get('reviewer', {}).get('id') != OWNER_ID):
        raise ValueError('Only the owner is an approval reviewer')
    branches = policies.get('branch_policies', [])
    if (policies.get('total_count') != 1 or len(branches) != 1
            or branches[0].get('name') != 'main' or branches[0].get('type') != 'branch'):
        raise ValueError('Only branch main, not tags or globs, may access environment')


def validate_context(env):
    sha = env.get('REVIEWED_WORKFLOW_SHA', '')
    if (env.get('GITHUB_REPOSITORY') != REPO or env.get('GITHUB_REF') != 'refs/heads/main'
            or env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or env.get('GITHUB_RUN_ATTEMPT') != '1'
            or not re.fullmatch('[a-f0-9]{40}', sha) or env.get('GITHUB_SHA') != sha):
        raise ValueError('Reviewed first-attempt main workflow only')
    if env.get('REQUEST_PUBLICATION') == 'true':
        expected = 'publish:' + env.get('RELEASE_TAG', '') + ':' + env.get('SOURCE_SHA', '') + ':' + env.get('ARTIFACT_SHA256', '')
        if env.get('OWNER_RELEASE_APPROVAL') != expected:
            raise ValueError('Exact owner-approved publication identity required')
    elif env.get('REQUEST_PUBLICATION') != 'false':
        raise ValueError('Explicit publication choice required')


def api(path):
    result = subprocess.run(['gh', 'api', path], capture_output=True, check=False)
    if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError('Environment metadata unavailable')
    return json.loads(result.stdout)


def check(name):
    validate_context(os.environ)
    current = api(f'repos/{REPO}/git/ref/heads/main')
    if current.get('object', {}).get('sha') != os.environ['REVIEWED_WORKFLOW_SHA']:
        raise ValueError('Reviewed public workflow is no longer current main')
    prefix = f'repos/{REPO}/environments/{name}'
    validate_environment(api(prefix), api(prefix + '/deployment-branch-policies?per_page=100'), name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--environment', required=True, choices=['codex-unix-sign', 'codex-unix-publish'])
    args = parser.parse_args()
    try:
        check(args.environment)
    except Exception:
        parser.exit(1, 'Reviewed environment or context check failed; no signing/publication authorized.\n')
