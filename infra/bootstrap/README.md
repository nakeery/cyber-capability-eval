# Phase 0 AWS bootstrap

One-time setup for local runs. These steps change your AWS account, so **you** run them; nothing in the repo runs them automatically.

## Why not use the root user

The root user can do anything in the account, including closing it, and its access keys can't be restricted. The agent under test never sees AWS credentials, but the harness does, and a bug or a leaked key should be able to do almost nothing. The lab user below can call **two models in one region** and nothing else.

AWS recommends that the root user have **no access keys at all**. Once the lab user works, consider deleting the root keys in the console (*Security credentials → Access keys*) and doing admin work through an IAM Identity Center or admin IAM user instead.

## 1. Create the scoped lab user

Run these with an identity that can manage IAM (for this one-time step, that may still be your current profile):

```bash
aws iam create-user --user-name model-eval-lab
```

```bash
aws iam put-user-policy --user-name model-eval-lab --policy-name bedrock-invoke-nova --policy-document file://infra/bootstrap/bedrock-invoke-policy.json
```

```bash
aws iam create-access-key --user-name model-eval-lab
```

The last command prints a key ID and secret **once**. Store them in a new profile; don't paste them anywhere else:

```bash
aws configure --profile model-eval
```

Set the region to `us-east-1` when prompted.

**Why `bedrock:InvokeModel` only:** the Converse API is authorized through the `bedrock:InvokeModel` action, so no separate Converse permission exists or is needed.

## 2. Create the budget alarm

Copy the notifications template to a git-ignored local file and put your email in the copy, so your address never lands in the repo:

```bash
cp infra/bootstrap/budget-notifications.json infra/bootstrap/budget-notifications.local.json
```

Edit the `.local.json` copy (and `budget.json` if you want a different limit), then:

```bash
aws budgets create-budget --account-id <YOUR_ACCOUNT_ID> --budget file://infra/bootstrap/budget.json --notifications-with-subscribers file://infra/bootstrap/budget-notifications.local.json
```

Replace `<YOUR_ACCOUNT_ID>` on the command line only; don't commit it.

## 3. Verify

```bash
aws sts get-caller-identity --profile model-eval
```

The ARN should end in `:user/model-eval-lab`, not `:root`. Then run the smoke test from the repository root:

```bash
py -3.13 harness/smoke_test.py
```
