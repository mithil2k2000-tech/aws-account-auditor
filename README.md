# aws-account-auditor

A command-line tool that reads an AWS account and reports the security
gaps and wasted spend most likely to hurt: root without MFA, SSH open to
the internet, buckets that could go public, databases with public
addresses, volumes and IPs being paid for that nothing uses.

It is **read-only**. Every API call is a `Describe`, `List` or `Get`;
`iam-policy.json` is the exact permission set it needs and nothing more.

```
$ aws-audit --regions eu-west-2

Account 123456789012, 1 region(s)

CRITICAL global         The root user has no MFA device: a leaked password is enough to take over the account.
HIGH     eu-west-2      SSH (port 22) is open to 0.0.0.0/0.
HIGH     global         User alice can sign in to the console with only a password.
HIGH     eu-west-2      Bucket team-uploads doesn't block public access (...), so one wrong policy or ACL could expose it.
MEDIUM   eu-west-2      No trail is logging this region. ...
LOW      eu-west-2      Elastic IP 127.63.125.158 is allocated but attached to nothing.  (~$3.65/month)
LOW      eu-west-2      100 GB gp3 volume vol-f2b47b05d320f9e76 is attached to nothing.  (~$8.00/month)

Findings: critical 1, high 3, medium 1, low 2
Estimated monthly spend on unused resources: $11.65
```

_(Output from a simulated account; see the tests.)_

## Checks

| Check | Scope | Severity |
| --- | --- | --- |
| `iam-root-access-keys` – root user has access keys | global | critical |
| `iam-root-mfa` – root user has no MFA | global | critical |
| `iam-user-mfa` – console users with only a password | global | high |
| `iam-old-access-keys` – active keys older than 90 days | global | medium |
| `s3-public-access` – buckets not fully blocking public access (account-wide block respected) | global | high |
| `s3-versioning` – buckets without versioning | global | low |
| `ec2-open-admin-ports` – SSH, RDP and database ports open to `0.0.0.0/0` or `::/0` | per region | high |
| `ec2-imdsv1` – instances still accepting IMDSv1 | per region | medium |
| `ec2-required-tags` – instances missing `Project`/`Owner` (configurable) | per region | low |
| `rds-public` – databases with a public address | per region | high |
| `rds-unencrypted` – databases without storage encryption | per region | medium |
| `cloudtrail-enabled` – no trail logging the region | per region | medium |
| `cost-unattached-volumes` – EBS volumes attached to nothing, priced | per region | low |
| `cost-idle-elastic-ips` – Elastic IPs attached to nothing, priced | per region | low |
| `cost-old-snapshots` – snapshots older than 180 days, priced | per region | info |

Each finding says what's wrong in plain words and how to fix it. Cost
figures are rough list prices, not your bill.

## Running it

Python 3.11 or newer.

```
pip install git+https://github.com/mithil2k2000-tech/aws-account-auditor.git
aws-audit                                   # the profile's region
aws-audit --regions all                     # every enabled region, in parallel
aws-audit --profile work --regions eu-west-2,us-east-1
aws-audit --format markdown -o report.md    # a report to share
aws-audit --format json                     # for other tools
aws-audit --min-severity high               # only what matters most
aws-audit --require-tag Project --require-tag CostCentre
aws-audit --list-checks
```

The easiest place to try it is **AWS CloudShell**: it already has
Python and your credentials.

**Exit codes**, so it can gate a pipeline: `0` nothing at or above
`--fail-on` (default `high`), `1` something is, `2` the audit couldn't
run. `--fail-on none` always exits `0`.

A check that can't run (a missing permission, a service not enabled)
is reported at the end rather than stopping the audit.

## Developing

Built in PyCharm. Open the folder, let PyCharm create the virtualenv from
`pyproject.toml`, and the shared run configurations in `.run/` appear:
**Tests** and **Audit (default profile)**.

From a terminal:

```
python -m venv .venv && . .venv/bin/activate     # .venv\Scripts\activate on Windows
pip install -e '.[dev]'
pytest -q
ruff check src tests && ruff format --check src tests
```

The tests run against [moto](https://github.com/getmoto/moto), a
simulated AWS: no account or credentials needed, nothing to clean up.
CI runs them on Python 3.11, 3.12 and 3.13.

### Adding a check

1. Write a function `(session, region) -> list[Finding]` in
   `src/aws_auditor/checks/`. Read only.
2. Register it in `checks/__init__.py`, marked global if the service
   is (IAM, S3's bucket list).
3. Add its permissions to `iam-policy.json`.
4. Test it with moto: one case that should be flagged, one that shouldn't.

## Design notes

- **Global checks run once.** IAM and the bucket list are the same in
  every region; running them per region would repeat every finding.
- **Regions run in parallel**, each worker with its own boto3 session,
  because sessions aren't safe to share across threads.
- **The account-wide S3 Block Public Access setting is honoured**, so
  an account that blocks everything centrally doesn't get a finding per
  bucket.
- **SSH open to a private range is fine**; only the whole internet
  (`0.0.0.0/0`, `::/0`) is flagged, and a port range like `20-3400` is
  reported once per admin port it covers.
