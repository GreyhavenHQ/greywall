---
id: why-greywall
title: Why Greywall?
---

# Why Greywall?

Greywall is a default-deny sandbox for AI coding agents. It wraps any local agent or command so filesystem access, network traffic, and command execution all start closed, and are opened only where you choose. Boundaries are enforced at the OS layer, so they apply below the agent process and survive anything the agent's own tooling might do.

The goal is simple: keep the agent inside clear, local boundaries, without cutting it off from your real development environment.

## The Problem

An AI coding agent runs with your user's permissions. By default it can read any file you can read, write any file you can write, and reach any network your machine can reach. That is usually fine, until it isn't.

A typical bad day looks like this. You ask the agent to refactor a module. Midway through, it decides to read `.env` to "understand the environment", picks up a production API key, and makes a live call to iterate on a fix. By the time you notice, a bill has been incurred, a log has been written somewhere you did not expect, and the secret has moved somewhere you did not intend.

The agent did not do anything malicious. It simply inherited every permission your shell has. The boundary was never there in the first place.

## How Greywall Helps

Greywall draws the boundary at the process layer, before the agent starts:

- **Filesystem**: writes are denied by default. You grant access to specific directories, and sensitive paths stay denied even if they sit inside an allowed one.
- **Network**: outbound traffic is denied by default. You allow specific hosts or use [Greyproxy](/greyproxy) for richer rule matching, MITM inspection, and credential substitution.
- **Commands**: dangerous patterns (for example `rm -rf /`, `sudo`, package managers on system paths) can be blocked outright.
- **Observability**: every blocked attempt, every allowed connection, and every file touch is recorded as it happens, so you can see what the agent tried to do rather than guess.
- **Learning mode**: point Greywall at a workflow you trust, let it trace what the command actually needs, and it will write a config profile for you. Next time, the same workflow runs with a tight allowlist and no interactive prompts.

Enforcement sits below the agent, using `sandbox-exec` on macOS and `bubblewrap` with Linux namespaces on Linux. It is not a shim the agent can talk its way around.

## Why Not Just Use a Container?

Containers are the obvious alternative, and they work for some teams. They also come with friction that makes them a poor fit for iterative agent work: you lose access to your shell history, your local toolchain, your editor integrations, your SSH keys, and your already-checked-out repositories. Getting the agent close enough to your real environment to be useful usually means mounting most of it back in, which reopens the boundary you were trying to draw.

Greywall keeps the agent in your normal environment and draws the boundary differently. You keep your tools, your repos, and your muscle memory. The agent only sees what you grant.

## Where Greywall Fits Alongside Built-in Sandboxes

Some agents and platforms already ship their own sandboxing (Seatbelt, Landlock, and so on). Greywall is still useful when you want:

- **Tool-agnostic policy**: the same rules apply to any command you wrap, not only to one vendor's agent.
- **Shared configuration**: commit a profile to the repo and every developer and CI runner enforces the same boundary.
- **Defense in depth**: wrap an agent that already sandboxes itself, and add a second layer plus a unified audit trail.
- **Practical allowlisting**: start fully denied, use learning mode or monitor mode to discover what a real workflow needs, and tighten from there.

Greywall is also useful beyond the agent case, for anything where you would rather see what a command *tries* to do before you let it: `npm install` in an unfamiliar repo, build scripts, CI jobs, one-off scripts from the internet. The agent scenario is the sharpest version of the same problem.

## Non-Goals

Greywall is **not** a hardened containment boundary for actively malicious code.

- It does not attempt to prevent resource exhaustion (CPU, memory, disk), timing attacks, or kernel-level escapes.
- Host allowlisting is not content inspection. If you allow a domain, code running inside the sandbox can still exfiltrate through that domain. Pair Greywall with [Greyproxy](/greyproxy) if you need visibility into what actually flows over an allowed connection.

For the full threat model, see [Security Model](./security-model).
