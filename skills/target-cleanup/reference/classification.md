# Cleanup classification

## PRESERVE

Keep unconditionally:

- `ZDI`, `ZDI_STAGING`, numbered/submitted/accepted/rejected packages, hashes,
  signoff, and package evidence;
- target findings, PoCs, proof captures, coverage, notes, goals, scope records,
  cleanup manifests, and resume capsules;
- Ghidra/Binary Ninja/r2 projects, annotations, symbols, patches, scripts,
  corpora with unique provenance, and researcher-created analysis;
- dirty or unverified source trees and any resource with unique local changes;
- secrets themselves outside documentation; record retrieval procedures only.

## REHYDRATABLE

Eligible only when target ownership and exact restoration are both proven:

- generated build output, logs, temporary extraction, and disposable test data;
- target-specific stopped containers, images, volumes, VM disks, snapshots, and
  exported appliances that have no shared dependency;
- clean source clones after recording remote, commit/tag, submodules/LFS state,
  `git status --porcelain`, patches, and exact re-clone commands;
- downloads/installers with immutable official identity or tested hash/signature
  plus a credible restoration route.

Preserve one installer copy when its URL is mutable, gated, expiring, or likely
to disappear unless the operator explicitly requests deeper cleanup.

## AMBIGUOUS_OR_SHARED

Leave untouched:

- shared Docker layers/volumes/networks, base VMs, WSL distributions, SDKs,
  package caches, symbols, corpora, tools, or installers;
- resources whose ownership depends only on a name substring;
- active/mounted/locked resources;
- resources that contain or may contain preserved descendants;
- anything without a tested restoration route.

Ambiguity is not a reason to ask for blanket deletion authority. Report the
specific resource and the evidence needed to reclassify it.

