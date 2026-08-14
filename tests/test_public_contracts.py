from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROLE_WORD_BUDGETS = {
    "tools/review_mailbox/prompts/HUNTER_TASK.txt": 1800,
    "tools/review_mailbox/prompts/MIDLANE_LOOP_TASK.txt": 1000,
    "tools/review_mailbox/prompts/FINAL_REVIEWER_TASK.txt": 1400,
}
PUBLIC_SKILLS = (
    "crash-triage",
    "fuzz-harness",
    "package-preflight",
    "patch",
    "quickstart",
    "source-audit",
    "target-cleanup",
    "target-recon",
    "target-scoper",
    "threat-model",
    "triage",
    "vm-isolation",
    "vuln-scan",
    "windows-powershell-hygiene",
    "zdi-submission",
    "zdi-validation",
)
SOURCE_SUFFIXES = {
    ".css",
    ".csv",
    ".html",
    ".js",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".txt",
}


def skill_root(name: str) -> Path:
    public = ROOT / "skills" / name
    return public if public.is_dir() else ROOT / ".codex" / "skills" / name


def document_paths() -> list[Path]:
    public_document_roots = (
        ROOT / "AGENTS.md",
        ROOT / "README.md",
        ROOT / "WORKFLOW.md",
        ROOT / "docs" / "SETUP_AND_OPERATIONS.md",
        ROOT / "tools" / "review_mailbox" / "prompts",
        ROOT / "tools" / "review_mailbox" / "role_operations",
        *(skill_root(name) for name in PUBLIC_SKILLS),
    )
    paths: list[Path] = []
    for candidate in public_document_roots:
        if candidate.is_file():
            paths.append(candidate)
        elif candidate.is_dir():
            paths.extend(candidate.rglob("*.md"))
            paths.extend(candidate.rglob("*.txt"))
    return sorted(set(paths))


def explicit_source_references(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8-sig")
    references = {
        match.group(1).split("#", 1)[0]
        for match in re.finditer(r"\[[^\]]+\]\(([^)]+)\)", text)
    }
    references.update(
        match.group(1)
        for match in re.finditer(
            r"`((?:tools|skills|docs)[\\/][^`<>*{}]+)`",
            text,
        )
    )
    return {
        reference.strip().replace("\\", "/")
        for reference in references
        if reference.strip()
    }


class PublicContractTests(unittest.TestCase):
    def test_setup_guide_includes_plain_language_workflow_glossary(self) -> None:
        guide = (ROOT / "docs" / "SETUP_AND_OPERATIONS.md").read_text(
            encoding="utf-8-sig"
        )
        for required in (
            "## Workflow glossary",
            "| **Park** |",
            "| **Parked rehydratable** |",
            "| **Candidate Challenge** |",
            "| **READY / Ready to submit** |",
            "| **Mark seen** |",
            "| **Greenlight** |",
        ):
            self.assertIn(required, guide)

    def test_explicit_public_source_references_resolve(self) -> None:
        missing: list[str] = []
        for document in document_paths():
            for reference in explicit_source_references(document):
                if (
                    reference.startswith(("http://", "https://", "#"))
                    or any(character.isspace() for character in reference)
                    or any(token in reference for token in ("<", ">", "{", "}", "*"))
                ):
                    continue
                suffix = Path(reference).suffix.casefold()
                if suffix not in SOURCE_SUFFIXES:
                    continue
                if reference.startswith(("tools/", "skills/", "docs/")):
                    destination = ROOT / reference
                else:
                    destination = document.parent / reference
                if not destination.is_file():
                    missing.append(
                        f"{document.relative_to(ROOT).as_posix()} -> {reference}"
                    )
        self.assertEqual([], sorted(set(missing)))

    def test_role_contracts_fit_the_public_token_budget(self) -> None:
        over_budget: dict[str, tuple[int, int]] = {}
        for relative, budget in ROLE_WORD_BUDGETS.items():
            text = (ROOT / relative).read_text(encoding="utf-8-sig")
            words = len(re.findall(r"\b[\w$'-]+\b", text))
            if words > budget:
                over_budget[relative] = (words, budget)
        self.assertEqual({}, over_budget)

    def test_hunt_hypotheses_are_non_binding(self) -> None:
        documents = (
            ROOT / "AGENTS.md",
            skill_root("target-scoper") / "SKILL.md",
            skill_root("target-scoper")
            / "assets"
            / "standalone-goal-template.md",
            ROOT / "tools" / "review_mailbox" / "prompts" / "HUNTER_TASK.txt",
        )
        combined = "\n".join(
            path.read_text(encoding="utf-8-sig") for path in documents
        ).casefold()
        self.assertGreaterEqual(combined.count("non-binding starting hypotheses"), 3)
        self.assertNotIn("intersect the active goal's ranked lanes", combined)
        self.assertIn("may pivot", combined)

    def test_public_route_stays_zdi_only(self) -> None:
        crash_triage = (
            skill_root("crash-triage") / "SKILL.md"
        ).read_text(encoding="utf-8-sig").casefold()
        target_recon = (
            skill_root("target-recon") / "SKILL.md"
        ).read_text(encoding="utf-8-sig").casefold()
        self.assertNotIn("vendor bounty", crash_triage)
        self.assertNotIn("hackerone", crash_triage)
        self.assertNotIn("six-file", target_recon)
        self.assertIn("complete scope bundle", target_recon)


if __name__ == "__main__":
    unittest.main()
