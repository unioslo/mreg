# Contributing

The [README](./README.md) contains a [Getting started](./README.md#getting-started) section that provides a high-level overview of how to get started with the project. After you've read that, you can continue here for more detailed information on how to contribute to the project.

**Table of Contents**

- [Upgrading dependencies](#upgrading-dependencies)
  - [Single dependency](#single-dependency)
    - [Version ranges](#version-ranges)
  - [All dependencies](#all-dependencies)
  - [What about `pyproject.toml`?](#what-about-pyprojecttoml)

## Upgrading dependencies

The project uses a [uv](https://docs.astral.sh/uv/) [lock file](https://docs.astral.sh/uv/concepts/projects/#project-lockfile) to pin its dependencies. We use the pinned versions in the lock file when building the project to ensure a consistent environment.

Dependency versions only ever change when we explictly update them with `uv lock`, which we will look at in the next section.

### Single dependency

Most of the time, we only want to upgrade a single dependency.
To do this, we can run the following command:

```bash
uv lock --upgrade-package <package>
```

#### Version ranges

Sometimes, we want to upgrade to a specific version of a package:

```bash
uv lock --upgrade-package django==5.0.8
```

Or, we can specify a range of versions to upgrade to:

```bash
uv lock --upgrade-package django>=5.0,<5.1
```

### All dependencies

We can also upgrade all dependencies at once:

```bash
uv lock --upgrade
```

It's useful to perform a dry-run first to see what changes will be made:

```bash
uv lock --upgrade --dry-run
```

### What about `pyproject.toml`?

The `pyproject.toml` file specifies minimum versions of dependencies, while the lock file pins the exact versions used in the project. You should only need to update the `pyproject.toml` file if you want to change the minimum version of a dependency.
