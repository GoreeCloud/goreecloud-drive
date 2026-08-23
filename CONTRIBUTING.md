# Contributing

GoreeCloud Drive uses a controlled source workflow.

1. Start from the current authoritative `main` revision.
2. Use a short-lived branch with a descriptive purpose.
3. Keep commits coherent and avoid unrelated edits.
4. Never place reusable secrets or private user data in source, tests, logs, examples, or pull requests.
5. Run `make verify` before proposing a merge.
6. Open a pull request that describes purpose, changes, validation, security/privacy impact, migration impact, limitations, and rollback considerations when applicable.
7. If the candidate head changes, rerun the checks required for that exact head.
8. Merge only the validated candidate according to repository protection and review rules.

Merge, release, deployment, production acceptance, and Stable promotion are separate states.
