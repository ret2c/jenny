"use strict";

const ACTIVE_POLL_MS = 1000;
const PARKED_POLL_MS = 60000;
const STATUS_FETCH_TIMEOUT_MS = 15000;
const SELECTION_RENDER_DEFERRAL_MS = 30000;
const COORDINATION_SEEN_STORAGE_KEY = "jenny.coordination.last-seen-midlane-message";
const HUNT_PROFILES = ["A_TIER_ONLY", "BALANCED", "INCLUDE_B_TIER"];
const HUNT_PROFILE_EFFECTS = {
  A_TIER_ONLY: "Intensive work stays limited to demonstrated CVSS 8.0+ and credible $10k+ outcomes, or an exceptional direct enterprise boundary; lower-value leads are banked.",
  BALANCED: "Intensive work may include demonstrated CVSS 7.0+ and credible $5k+ outcomes; smaller B-tier leads are banked unless the operator separately authorizes packaging.",
  INCLUDE_B_TIER: "Intensive work may include demonstrated CVSS 6.0+ findings with meaningful enterprise impact and credible paid value; Candidate Challenge and B-tier packaging authority still apply.",
};
const TERMINAL_COUNT_ORDER = ["SUBMITTED", "HOLD", "ACCEPTED", "REJECTED", "DEAD"];
const EVENT_LABELS = {
  WORKER_CHECKIN: "WORKER CHECK IN",
  WORKER_ACTIVITY_HEARTBEAT: "ACTIVITY HEARTBEAT",
  TARGET_STAND_DOWN_STARTED: "STANDING DOWN",
  TARGET_PARKED: "PARKED",
  SUBMISSION_RECONCILED: "OPERATOR SUBMITTED",
  OPERATOR_ACCEPTED: "OPERATOR ACCEPTED",
};
const MAJOR_EVENT_TYPES = new Set([
  "TARGET_STAND_DOWN_STARTED",
  "TARGET_PARKED",
  "SUBMISSION_RECONCILED",
  "OPERATOR_ACCEPTED",
]);
let inFlight = false;
let lastGood = null;
let pendingRender = null;
let pendingRenderTimer = null;
let pollTimer = null;
let minutePrecision = false;
let weeklyCountdownDeadline = 0;
let weeklyCountdownTimer = null;
let coordinationSeenMidlaneMessageId = readCoordinationSeenMidlaneMessageId();
const reportIssueAcknowledgementsInFlight = new Set();
let reportIssueGreenlightConfirmationTimer = null;

function readCoordinationSeenMidlaneMessageId() {
  try {
    return Number(window.localStorage.getItem(COORDINATION_SEEN_STORAGE_KEY)) || 0;
  } catch (_error) {
    return 0;
  }
}

function writeCoordinationSeenMidlaneMessageId(value) {
  coordinationSeenMidlaneMessageId = Math.max(coordinationSeenMidlaneMessageId, Number(value) || 0);
  try {
    window.localStorage.setItem(
      COORDINATION_SEEN_STORAGE_KEY,
      String(coordinationSeenMidlaneMessageId),
    );
  } catch (_error) {
    // Storage may be unavailable in a private or restricted browser context.
  }
}

function displayAge(value) {
  const text = String(value || "");
  if (!minutePrecision) return text;
  return text.replace(/^(\d+)m \d+s$/, "$1m");
}

function formatAgeSeconds(value) {
  let remaining = Math.max(0, Math.floor(Number(value) || 0));
  const weeks = Math.floor(remaining / 604800);
  remaining %= 604800;
  const days = Math.floor(remaining / 86400);
  remaining %= 86400;
  const hours = Math.floor(remaining / 3600);
  remaining %= 3600;
  const minutes = Math.floor(remaining / 60);
  const seconds = remaining % 60;
  if (weeks) return `${weeks}w ${days}d`;
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutePrecision) return `${minutes}m`;
  return `${minutes}m ${seconds}s`;
}

function issueReporterLabel(value) {
  const reporter = String(value || "system").toLowerCase();
  return {
    hunter: "Hunter",
    midlane: "Midlane",
    "final-reviewer": "Final Reviewer",
    "workflow-owner": "Workflow Owner",
    operator: "Operator",
  }[reporter] || String(value || "System");
}

function displayTime(value) {
  const text = String(value || "");
  if (!minutePrecision) return text;
  return text.replace(/^(\d{1,2}:\d{2}):\d{2} ([AP]M)$/, "$1 $2");
}

function hasActiveTextSelection() {
  const selection = window.getSelection();
  return Boolean(selection && !selection.isCollapsed && selection.toString().length);
}

function renderWhenCopySafe(snapshot, stale = false, errorMessage = "") {
  if (hasActiveTextSelection()) {
    pendingRender = { snapshot, stale, errorMessage };
    if (pendingRenderTimer === null) {
      pendingRenderTimer = setTimeout(() => {
        pendingRenderTimer = null;
        flushPendingRender(true);
      }, SELECTION_RENDER_DEFERRAL_MS);
    }
    return;
  }
  pendingRender = null;
  if (pendingRenderTimer !== null) {
    clearTimeout(pendingRenderTimer);
    pendingRenderTimer = null;
  }
  render(snapshot, stale, errorMessage);
}

function flushPendingRender(force = false) {
  if (
    !pendingRender
    || (!force && hasActiveTextSelection())
  ) return;
  const next = pendingRender;
  pendingRender = null;
  if (pendingRenderTimer !== null) {
    clearTimeout(pendingRenderTimer);
    pendingRenderTimer = null;
  }
  render(next.snapshot, next.stale, next.errorMessage);
}

function eventLabel(value) {
  const raw = String(value || "");
  if (!raw) return "none";
  const key = raw.toUpperCase();
  return EVENT_LABELS[key] || key.replaceAll("_", " ");
}

function packageLabel(value) {
  let label = String(value || "");
  label = label.replace(
    /^_(?:READY_TO_SUBMIT|SUBMITTED|ACCEPTED|DEAD|HOLD|REJECTED|WRITE_OFF)_/,
    "",
  );
  label = label.replace(/^\d+_/, "");
  label = label.replace(/_20\d{6}$/i, "");
  return label.replaceAll("_", " ") || "unnamed package";
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function setChildren(target, children) {
  target.replaceChildren(...children);
}

function showOperatorActionFeedback(kind, message) {
  const target = document.getElementById("operator-action-feedback");
  target.className = `panel operator-action-feedback ${kind === "error" ? "status-error" : "status-ok"}`;
  target.textContent = String(message || "The action could not be completed safely.");
  target.hidden = false;
}

function openConfirmationDialog(options) {
  const dialog = document.getElementById("confirmation-dialog");
  const title = document.getElementById("confirmation-title");
  const summary = document.getElementById("confirmation-summary");
  const changes = document.getElementById("confirmation-changes");
  const unchanged = document.getElementById("confirmation-unchanged");
  const unchangedSection = unchanged.closest(".confirmation-section");
  const warning = document.getElementById("confirmation-warning");
  const cancelButton = document.getElementById("confirmation-cancel");
  const confirmButton = document.getElementById("confirmation-confirm");

  title.textContent = options.title;
  summary.textContent = options.summary;
  setChildren(changes, options.changes.map((text) => element("li", "", text)));
  const unchangedItems = options.unchanged || [];
  setChildren(unchanged, unchangedItems.map((text) => element("li", "", text)));
  unchangedSection.hidden = unchangedItems.length === 0;
  warning.textContent = options.warning;
  confirmButton.textContent = options.confirmLabel;

  return new Promise((resolve) => {
    let settled = false;
    const finish = (confirmed) => {
      if (settled) return;
      settled = true;
      dialog.removeEventListener("cancel", cancel);
      dialog.removeEventListener("click", backdropCancel);
      cancelButton.onclick = null;
      confirmButton.onclick = null;
      if (dialog.open) dialog.close();
      resolve(confirmed);
    };
    const cancel = (event) => {
      event.preventDefault();
      finish(false);
    };
    const backdropCancel = (event) => {
      if (event.target === dialog) finish(false);
    };

    cancelButton.onclick = () => finish(false);
    confirmButton.onclick = () => finish(true);
    dialog.addEventListener("cancel", cancel);
    dialog.addEventListener("click", backdropCancel);
    dialog.showModal();
    cancelButton.focus();
  });
}

function line(label, value, valueClass = "", rowClass = "") {
  const row = element("div", `line ${rowClass}`.trim());
  row.append(
    element("span", "line-label", label),
    element("span", `line-value ${valueClass}`.trim(), value),
  );
  return row;
}

function stateClass(value) {
  const state = String(value || "").toUpperCase();
  if (state === "FINAL REWORK IN PROGRESS") return "status-muted";
  if (state === "BLOCKED") return "status-error";
  if (state === "PATCHED") return "status-error";
  if (state === "REJECTED") return "status-error";
  if (state === "LIKELY_EXACT_FIX") return "status-warn";
  if (state === "FIX_RELEASED_AFTER_SUBMISSION") return "status-warn";
  if (state === "PUBLIC_AFTER_SUBMISSION") return "status-warn";
  if (state === "PUBLIC_BEFORE_SUBMISSION") return "status-error";
  if (state === "ACCEPTED") return "status-ok";
  if (state === "CLEAR") return "status-ok";
  if (state === "UNDER INVESTIGATION") return "status-warn";
  if (state.includes("IN PROGRESS")) return "status-ok";
  if (state === "READY FOR MIDLANE") return "status-warn";
  if (state.includes("READY")) return "status-ready";
  if (
    state.includes("FINAL REVIEW") ||
    state === "STANDING DOWN" ||
    state === "NEEDS WORK" ||
    state === "HOLD"
  ) return "status-warn";
  if (state.includes("MISSING") || state.includes("STALE") || state === "ERROR") {
    return "status-error";
  }
  if (state === "WORKING" || state === "OK") return "status-ok";
  return "status-muted";
}

function gib(bytes) {
  if (!Number.isFinite(Number(bytes))) return "unknown";
  return `${(Number(bytes) / (1024 ** 3)).toFixed(1)} GiB`;
}

function card(targetId, title, rows) {
  const target = document.getElementById(targetId);
  const heading = element("h2", "", title);
  const content = element("div", "card-content");
  content.append(...rows);
  setChildren(target, [heading, content]);
}

function renderProjectIdentity(snapshot) {
  const project = snapshot.project || {};
  const displayName = project.display_name || "JENNY";
  document.getElementById("project-identity").textContent = displayName;
  document.title = `${displayName} Dashboard`;
}

function renderActiveTarget(snapshot) {
  const target = document.getElementById("active-target");
  const active = snapshot.active_target || {};
  let product = "No active target";
  if (active.status === "active") {
    product = active.product || active.slug || "Active target";
  } else if (active.status === "fault") {
    product = active.product || "Lifecycle fault";
  } else if (active.status === "unavailable") {
    product = "Lifecycle unavailable";
  }
  target.textContent = `Target: ${product}`;
}

function renderFirstRun(snapshot) {
  const firstRun = document.getElementById("first-run-card");
  const target = snapshot.active_target || {};
  const workers = Array.isArray(snapshot.workers) ? snapshot.workers : [];
  const activeWorker = workers.some((worker) =>
    ["WORKING", "BLOCKED"].includes(String(worker.state || "").toUpperCase()),
  );
  const pristine = target.status !== "active"
    && !(snapshot.active_items || []).length
    && !(snapshot.candidate_reviews || []).length
    && !(snapshot.recent_events || []).length
    && !(snapshot.terminal_items || []).length
    && !activeWorker;
  firstRun.hidden = !pristine;
}

function huntProfileLabel(preset) {
  return String(preset || "").replaceAll("_", " ");
}

async function selectHuntProfile(preset, button) {
  const current = lastGood && lastGood.hunt_profile;
  const active = current && current.active ? current.active.preset : "unknown";
  const pending = current && current.pending ? current.pending.preset : null;
  const target = lastGood && lastGood.active_target ? lastGood.active_target : {};
  const targetIsActive = String(target.status || "").toLowerCase() === "active";
  const changes = [
    `Creates a workspace-wide ${huntProfileLabel(preset)} policy revision${pending ? ` and supersedes pending ${huntProfileLabel(pending)}` : ""}.`,
    targetIsActive
      ? `Hunter receives a bounded policy delta for ${target.product || target.slug} and applies it at the next safe semantic checkpoint.`
      : "With no active target, the preset becomes active immediately for the next operator-activated target.",
    "The effective authority becomes the active GOAL intersected with the selected profile; the profile can narrow authority but cannot expand it.",
    HUNT_PROFILE_EFFECTS[preset],
  ];
  const confirmed = await openConfirmationDialog({
    title: "Change hunt profile?",
    summary: `${huntProfileLabel(active)} -> ${huntProfileLabel(preset)}`,
    changes,
    unchanged: [
      "Does not interrupt the current guarded replay, package build, Candidate Challenge, or Final rework.",
      "Does not rewrite GOAL.md, activate or park a target, mutate package bytes, or reopen BANK, HOLD, DEAD, or REJECTED work.",
      "Does not lower Candidate Challenge, currentness, duplicate, proof, or package-safety gates.",
    ],
    warning: targetIsActive
      ? "The current profile remains effective until Hunter records and acknowledges the new revision at a safe checkpoint."
      : "This changes policy only. No target or hunt starts automatically.",
    confirmLabel: "Change profile",
  });
  if (!confirmed) return;

  const error = document.getElementById("hunt-profile-error");
  error.textContent = "";
  button.disabled = true;
  try {
    const response = await fetch("/api/hunt-profile", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-JENNY-Operator": "confirm-hunt-profile",
      },
      body: JSON.stringify({ preset, confirmed: true }),
    });
    if (!response.ok) throw new Error(`profile change returned ${response.status}`);
    await response.json();
    await poll();
  } catch (requestError) {
    error.textContent = "Profile change failed. The prior profile remains active.";
  } finally {
    button.disabled = false;
  }
}

function renderHuntProfile(snapshot) {
  const profile = snapshot.hunt_profile || {};
  const active = profile.active || { preset: "A_TIER_ONLY", revision: 0 };
  const pending = profile.pending || null;
  const state = document.getElementById("hunt-profile-state");
  const controls = document.getElementById("hunt-profile-controls");
  const error = document.getElementById("hunt-profile-error");

  state.textContent = pending
    ? `Active: ${huntProfileLabel(active.preset)} | Pending: ${huntProfileLabel(pending.preset)}`
    : `Active: ${huntProfileLabel(active.preset)}`;
  state.className = pending
    ? "hunt-profile-state status-warn"
    : "hunt-profile-state";

  const buttons = HUNT_PROFILES.map((preset) => {
    const button = element("button", "hunt-profile-action", huntProfileLabel(preset));
    button.type = "button";
    button.disabled = !profile.available || (
      !pending && preset === active.preset
    ) || Boolean(pending && preset === pending.preset);
    if (!pending && preset === active.preset) button.classList.add("is-active");
    if (pending && preset === pending.preset) button.classList.add("is-pending");
    button.setAttribute("aria-pressed", String(
      (!pending && preset === active.preset)
      || Boolean(pending && preset === pending.preset),
    ));
    button.addEventListener("click", () => selectHuntProfile(preset, button));
    return button;
  });
  setChildren(controls, buttons);
  if (!profile.available) {
    error.textContent = profile.warning || "Hunt profile unavailable.";
  } else if (error.textContent === "Hunt profile unavailable.") {
    error.textContent = "";
  }
}

async function confirmDiminishingReturns(marker, button) {
  button.disabled = true;
  try {
    const response = await fetch("/api/ack-diminishing-returns", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-JENNY-Operator": "confirm-diminishing-returns",
      },
      body: JSON.stringify({ slug: marker.slug, marker_sha256: marker.marker_sha256, confirmed: true }),
    });
    if (!response.ok) throw new Error(`status ${response.status}`);
    await poll();
  } catch (_error) {
    showOperatorActionFeedback(
      "error",
      "The diminishing-returns marker could not be acknowledged. " +
      "Refresh and confirm that the active marker has not changed.",
    );
  } finally {
    button.disabled = false;
  }
}

function diminishingTextElement(tag, text) {
  const node = element(tag, "");
  const value = String(text || "");
  if (!/`[^`]+`/.test(value)) {
    node.textContent = value;
    return node;
  }

  let cursor = 0;
  for (const match of value.matchAll(/`([^`]+)`/g)) {
    if (match.index > cursor) {
      node.append(document.createTextNode(value.slice(cursor, match.index)));
    }
    node.append(element("code", "", match[1]));
    cursor = match.index + match[0].length;
  }
  if (cursor < value.length) {
    node.append(document.createTextNode(value.slice(cursor)));
  }
  return node;
}

function renderDiminishingMarkdown(message) {
  const container = element("div", "diminishing-message");
  let paragraph = [];
  let list = null;
  let listTag = "";

  const flushParagraph = () => {
    if (!paragraph.length) return;
    container.append(diminishingTextElement("p", paragraph.join(" ")));
    paragraph = [];
  };

  for (const rawLine of String(message || "").split(/\r?\n/)) {
    const text = rawLine.trim();
    if (!text) {
      flushParagraph();
      list = null;
      listTag = "";
      continue;
    }

    const heading = text.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      flushParagraph();
      list = null;
      listTag = "";
      const level = Math.min(5, heading[1].length + 2);
      container.append(diminishingTextElement(`h${level}`, heading[2]));
      continue;
    }

    const bullet = text.match(/^[-*]\s+(.+)$/);
    const numbered = text.match(/^\d+[.)]\s+(.+)$/);
    if (bullet || numbered) {
      flushParagraph();
      const nextTag = numbered ? "ol" : "ul";
      if (!list || listTag !== nextTag) {
        list = element(nextTag, "");
        listTag = nextTag;
        container.append(list);
      }
      list.append(diminishingTextElement("li", (bullet || numbered)[1]));
      continue;
    }

    list = null;
    listTag = "";
    paragraph.push(text);
  }
  flushParagraph();
  return container;
}

function renderDiminishingReturns(snapshot) {
  const target = document.getElementById("diminishing-returns-card");
  const content = document.getElementById("diminishing-returns-content");
  const marker = snapshot.diminishing_returns;
  if (!marker) {
    target.hidden = true;
    setChildren(content, []);
    return;
  }

  const rows = [];
  if (marker.message) {
    rows.push(renderDiminishingMarkdown(marker.message));
  } else {
    const values = [
      ["Recommendation", marker.recommendation],
      ["Strongest survivor", marker.strongest_survivor],
      ["Top blocker", marker.top_blocker],
      ["Operator decision", marker.operator_decision],
    ];
    for (const [label, value] of values) {
      if (value) rows.push(line(label, value));
    }
  }
  const button = element("button", "diminishing-action", "Acknowledge");
  button.type = "button";
  button.addEventListener("click", () => confirmDiminishingReturns(marker, button));
  rows.push(button);
  target.querySelector("h2").textContent =
    `Diminishing returns - ${marker.product || marker.slug}`;
  setChildren(content, rows);
  target.hidden = false;
}

async function acknowledgeWeeklyPatchWatch(watch, button) {
  button.disabled = true;
  try {
    const response = await fetch("/api/ack-weekly-patch-watch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-JENNY-Operator": "confirm-weekly-patch-watch",
      },
      body: JSON.stringify({
        monday_date: watch.monday_date,
        manifest_digest: watch.manifest_digest,
        confirmed: true,
      }),
    });
    if (!response.ok) throw new Error(`status ${response.status}`);
    await poll();
  } catch (_error) {
    showOperatorActionFeedback(
      "error",
      "The weekly patch-watch run could not be acknowledged. Refresh and try again.",
    );
  } finally {
    button.disabled = false;
  }
}

function renderWeeklyPatchAcknowledgement(snapshot) {
  const target = document.getElementById("weekly-patch-ack-card");
  const content = document.getElementById("weekly-patch-ack-content");
  const watch = snapshot.weekly_patch_watch;
  if (
    !watch
    || watch.state !== "COMPLETED"
    || !watch.report
    || !watch.manifest_digest
    || watch.acknowledged_at
  ) {
    target.hidden = true;
    setChildren(content, []);
    return;
  }

  const alerts = Array.isArray(watch.report.alerts) ? watch.report.alerts : [];
  const heading = element("h2", "", "Weekly Patch Watch complete");
  const summary = element(
    "p",
    "weekly-patch-ack-summary",
    `${watch.completed || 0}/${watch.total || 0} submitted packages checked. ` +
      `${alerts.length} result${alerts.length === 1 ? "" : "s"} require attention.`,
  );
  const button = element("button", "weekly-patch-ack-action", "Acknowledge");
  button.type = "button";
  button.addEventListener(
    "click",
    () => acknowledgeWeeklyPatchWatch(watch, button),
  );
  setChildren(content, [heading, summary, button]);
  target.hidden = false;
}

async function acknowledgeReportIssueItems(items, button = null, silent = false) {
  const acknowledgementItems = (Array.isArray(items) ? items : [])
    .filter((item) => item && item.issue_key && item.updated_at)
    .map((item) => ({
      issue_key: String(item.issue_key),
      updated_at: String(item.updated_at),
    }))
    .sort((left, right) => left.issue_key.localeCompare(right.issue_key));
  if (!acknowledgementItems.length) return;

  const signature = JSON.stringify(acknowledgementItems);
  if (reportIssueAcknowledgementsInFlight.has(signature)) return;
  reportIssueAcknowledgementsInFlight.add(signature);
  if (button) button.disabled = true;
  try {
    const response = await fetch("/api/ack-report-issues", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-JENNY-Operator": "confirm-report-issues-acknowledgement",
      },
      body: JSON.stringify({
        confirmed: true,
        issues: acknowledgementItems,
      }),
    });
    if (!response.ok) throw new Error(`status ${response.status}`);
    await poll();
  } catch (_error) {
    if (!silent) {
      showOperatorActionFeedback(
        "error",
        "The issue acknowledgement could not be recorded. Refresh and try again.",
      );
    }
  } finally {
    reportIssueAcknowledgementsInFlight.delete(signature);
    if (button) button.disabled = false;
  }
}

async function acknowledgeReportIssues(reportIssues, button) {
  await acknowledgeReportIssueItems(
    reportIssues.acknowledgement_items,
    button,
    false,
  );
}

function renderReportIssuesAcknowledgement(snapshot) {
  const target = document.getElementById("report-issues-ack-card");
  const content = document.getElementById("report-issues-ack-content");
  const reportIssues = snapshot.report_issues;
  const count = Number(reportIssues?.unacknowledged_count || 0);
  if (
    !reportIssues?.available
    || count < 1
    || !Array.isArray(reportIssues.acknowledgement_items)
    || reportIssues.acknowledgement_items.length !== count
  ) {
    target.hidden = true;
    setChildren(content, []);
    return;
  }
  const noun = count === 1 ? "item" : "items";
  const heading = element("h2", "", `${count} new ${noun} in issue queue`);
  const button = element("button", "report-issues-ack-action", "Acknowledge");
  button.type = "button";
  button.addEventListener(
    "click",
    () => acknowledgeReportIssues(reportIssues, button),
  );
  setChildren(content, [heading, button]);
  target.hidden = false;
}

function showWorkflowIssueUpdatedConfirmation(count) {
  const target = document.getElementById("report-issue-greenlight-confirmation");
  const normalizedCount = Math.max(1, Number(count) || 1);
  const message = normalizedCount === 1
    ? "1 workflow issue updated"
    : `${normalizedCount} workflow issues updated`;
  setChildren(target, [element("h2", "", message)]);
  target.hidden = false;
  if (reportIssueGreenlightConfirmationTimer !== null) {
    clearTimeout(reportIssueGreenlightConfirmationTimer);
  }
  reportIssueGreenlightConfirmationTimer = setTimeout(() => {
    target.hidden = true;
    setChildren(target, []);
    reportIssueGreenlightConfirmationTimer = null;
  }, 5000);
}

async function greenlightReportIssue(issue, button) {
  const confirmed = await openConfirmationDialog({
    title: "Greenlight this fixed issue?",
    summary: issue.title || issue.issue_key,
    changes: [
      `Closes only workflow issue ${issue.issue_key} in the durable issue ledger.`,
      "Removes it from the active workflow-issues card after refresh.",
    ],
    unchanged: [],
    warning: "Greenlight only after confirming the repair is satisfactory.",
    confirmLabel: "Greenlight",
  });
  if (!confirmed) return;

  button.disabled = true;
  try {
    const response = await fetch("/api/greenlight-report-issue", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-JENNY-Operator": "confirm-report-issue-greenlight",
      },
      body: JSON.stringify({
        issue_key: issue.issue_key,
        confirmed: true,
      }),
    });
    if (!response.ok) throw new Error(`status ${response.status}`);
    await poll();
    showWorkflowIssueUpdatedConfirmation(1);
  } catch (_error) {
    showOperatorActionFeedback(
      "error",
      "The issue could not be greenlit. Refresh and try again.",
    );
  } finally {
    button.disabled = false;
  }
}

function renderReportIssues(snapshot) {
  const card = document.getElementById("report-issues-card");
  const summary = document.getElementById("report-issues-summary");
  const content = document.getElementById("report-issues-content");
  const reportIssues = snapshot.report_issues;
  const issues = Array.isArray(reportIssues?.issues) ? reportIssues.issues : [];
  if (!reportIssues?.available || !issues.length) {
    card.hidden = true;
    card.open = false;
    setChildren(content, []);
    return;
  }
  summary.textContent = `Reported workflow issues - ${issues.length} active`;
  const rows = [];
  for (const issue of issues) {
    const row = element("article", "report-issue-row");
    const greenlightReady = issue.status === "RESOLVED_AWAITING_OPERATOR_GREENLIGHT";
    if (greenlightReady) {
      row.classList.add("is-greenlight-ready");
    } else if (!issue.acknowledged) {
      row.classList.add("is-new");
    }
    const header = element("div", "report-issue-header");
    const priority = String(issue.priority || "").toUpperCase();
    header.append(
      element("strong", "report-issue-title", issue.title || issue.issue_key),
      element(
        "span",
        `report-issue-priority priority-${priority.toLowerCase()}`,
        priority,
      ),
      element("span", "report-issue-age muted", formatAgeSeconds(issue.age_seconds || 0)),
    );
    row.append(header);
    const reporter = issueReporterLabel(issue.reported_by);
    const metadata = [
      issue.category,
      `Reported by ${reporter}`,
      issue.owner,
      issue.status,
    ]
      .filter(Boolean)
      .join(" - ");
    if (metadata) row.append(element("div", "report-issue-metadata muted", metadata));
    if (issue.next_action) {
      row.append(element("p", "report-issue-action", issue.next_action));
    }
    if (!greenlightReady && !issue.acknowledged) {
      const button = element("button", "report-issue-ack-action", "Mark seen");
      button.type = "button";
      button.addEventListener("click", () => acknowledgeReportIssueItems(
        [{ issue_key: issue.issue_key, updated_at: issue.updated_at }],
        button,
        true,
      ));
      row.append(button);
    }
    if (greenlightReady) {
      const button = element(
        "button",
        "report-issue-greenlight-action",
        "Greenlight",
      );
      button.type = "button";
      button.addEventListener("click", () => greenlightReportIssue(issue, button));
      row.append(button);
    }
    rows.push(row);
  }
  setChildren(content, rows);
  card.hidden = false;
}

async function acknowledgePackageOutcome(notification, button) {
  button.disabled = true;
  try {
    const response = await fetch("/api/ack-package-outcome", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-JENNY-Operator": "confirm-package-outcome",
      },
      body: JSON.stringify({
        notification_id: notification.notification_id,
        confirmed: true,
      }),
    });
    if (!response.ok) throw new Error(`status ${response.status}`);
    await poll();
  } catch (_error) {
    showOperatorActionFeedback(
      "error",
      "The package outcome could not be acknowledged. Refresh and try again.",
    );
  } finally {
    button.disabled = false;
  }
}

function renderPackageOutcomeNotifications(snapshot) {
  const target = document.getElementById("package-outcome-notifications");
  const notifications = Array.isArray(snapshot.package_outcome_notifications)
    ? snapshot.package_outcome_notifications
    : [];
  if (!notifications.length) {
    target.hidden = true;
    setChildren(target, []);
    return;
  }

  const cards = notifications.map((notification) => {
    const outcome = String(notification.outcome || "TERMINAL").toUpperCase();
    const number = notification.package_number || notification.item_id;
    const cardNode = element(
      "article",
      `package-outcome-notification package-outcome-${outcome.toLowerCase()}`,
    );
    const heading = element(
      "h2",
      stateClass(outcome),
      `Package #${number} placed on ${outcome}`,
    );
    const title = element(
      "div",
      "package-outcome-title",
      `${notification.product || "Unknown product"} - ${notification.title || "Untitled package"}`,
    );
    const reason = element(
      "div",
      "package-outcome-reason",
      notification.reason || "No reason recorded.",
    );
    const footer = element("div", "package-outcome-footer");
    const age = element("span", "package-outcome-age", displayAge(notification.age));
    const button = element("button", "package-outcome-action", "Acknowledge");
    button.type = "button";
    button.addEventListener(
      "click",
      () => acknowledgePackageOutcome(notification, button),
    );
    footer.append(age, button);
    cardNode.append(heading, title, reason, footer);
    return cardNode;
  });
  setChildren(target, cards);
  target.hidden = false;
}

function renderAlerts(snapshot, stale, errorMessage) {
  const target = document.getElementById("alerts");
  const alerts = Array.isArray(snapshot?.alerts) ? [...snapshot.alerts] : [];
  if (stale) {
    alerts.unshift({
      severity: "error",
      text: `Dashboard data is stale: ${errorMessage || "status unavailable"}`,
    });
  }
  if (!alerts.length) {
    target.hidden = true;
    setChildren(target, []);
    return;
  }
  const nodes = alerts.map((alert) =>
    element(
      "div",
      alertClass(alert),
      alert.text,
    ),
  );
  setChildren(target, nodes);
  target.hidden = false;
}

function captureCoordinationReplyDraft() {
  const editor = document.querySelector(".coordination-reply-editor:not([hidden])");
  if (!editor) return null;
  const textarea = editor.querySelector("textarea");
  if (!textarea) return null;
  return {
    messageId: Number(editor.dataset.messageId),
    text: textarea.value,
    focused: document.activeElement === textarea,
  };
}

function restoreCoordinationReplyDraft(draft) {
  if (!draft || !Number.isInteger(draft.messageId)) return;
  const editor = document.querySelector(
    `.coordination-reply-editor[data-message-id="${draft.messageId}"]`,
  );
  if (!editor) return;
  const textarea = editor.querySelector("textarea");
  if (!textarea) return;
  editor.hidden = false;
  textarea.value = draft.text;
  if (draft.focused) textarea.focus();
}

async function submitCoordinationReply(message, textarea, error) {
  const text = textarea.value.trim();
  if (!text) {
    error.textContent = "Reply text is required.";
    return;
  }
  error.textContent = "Sending reply";
  try {
    const response = await fetch("/api/coordination/reply", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-JENNY-Operator": "confirm-coordination-reply",
      },
      body: JSON.stringify({
        message_id: Number(message.id),
        expected_revision: Number(message.revision),
        text,
      }),
    });
    if (!response.ok) throw new Error(`reply failed (${response.status})`);
    error.textContent = "Reply recorded";
    const editor = textarea.closest(".coordination-reply-editor");
    textarea.value = "";
    if (editor) editor.hidden = true;
    await poll();
  } catch (problem) {
    error.textContent = problem instanceof Error ? problem.message : "Reply failed";
  }
}

async function submitCoordinationDecision(message, decision) {
  const approved = decision === "APPROVED";
  const confirmed = await openConfirmationDialog({
    title: approved ? "Approve this exact request?" : "Decline this request?",
    summary: `${message.scope_label || `${message.scope_kind} ${message.scope_ref}`}: ${message.requested_action}`,
    changes: [
      `Scope: ${message.scope_kind} ${message.scope_ref}.`,
      approved
        ? `Message #${message.id}, revision ${message.revision}: Hunter may perform only the exact requested action.`
        : `Message #${message.id}, revision ${message.revision}: close without delivery to Hunter.`,
    ],
    unchanged: [
      "The active goal, lifecycle, package state, formal mailbox, frozen bytes, and safety rules do not change.",
      "No broader or future action is authorized.",
    ],
    warning: "Approval applies only to this exact message revision and action.",
    confirmLabel: approved ? "Approve request" : "Decline request",
  });
  if (!confirmed) return;
  const reason = approved
    ? "Operator approved this exact dashboard request."
    : "Operator declined this exact dashboard request.";
  const status = document.getElementById("coordination-inbox-status");
  status.hidden = false;
  status.className = "coordination-inbox-status";
  status.textContent = approved ? "Approving request..." : "Declining request...";
  try {
    const response = await fetch("/api/coordination/decide", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-JENNY-Operator": "confirm-coordination-decision",
      },
      body: JSON.stringify({
        message_id: Number(message.id),
        expected_revision: Number(message.revision),
        decision,
        reason,
        confirmed: true,
      }),
    });
    if (!response.ok) {
      let detail = "";
      try {
        const payload = await response.json();
        detail = typeof payload.error === "string" ? `: ${payload.error}` : "";
      } catch (_problem) {
        detail = "";
      }
      if (detail) {
        const reason = detail.slice(2);
        const humanReason = reason.charAt(0).toUpperCase() + reason.slice(1);
        throw new Error(`Decision Failed: ${humanReason}`);
      }
      throw new Error(`Decision Failed (${response.status})`);
    }
    status.className = "coordination-inbox-status status-ready";
    status.textContent = approved
      ? "Request approved for Hunter pickup."
      : "Request declined and closed.";
    await poll();
  } catch (problem) {
    status.className = "coordination-inbox-status status-error";
    status.textContent = problem instanceof Error ? problem.message : "Decision failed";
  }
}

async function dismissCoordinationMessage(message, button) {
  button.disabled = true;
  const status = document.getElementById("coordination-inbox-status");
  try {
    const response = await fetch("/api/coordination/dismiss", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-JENNY-Operator": "dismiss-coordination-message",
      },
      body: JSON.stringify({
        message_id: Number(message.id),
        expected_revision: Number(message.revision),
      }),
    });
    if (!response.ok) throw new Error(`close failed (${response.status})`);
    status.hidden = false;
    status.className = "coordination-inbox-status status-ready";
    status.textContent = "Message closed; originator notified.";
    await poll();
  } catch (problem) {
    status.hidden = false;
    status.className = "coordination-inbox-status status-error";
    status.textContent = problem instanceof Error ? problem.message : "Close failed";
    button.disabled = false;
  }
}

function coordinationReplyEditor(message) {
  const editor = element("div", "coordination-reply-editor");
  editor.dataset.messageId = String(message.id);
  editor.hidden = true;
  const notice = element(
    "div",
    "coordination-authority-note",
    "Reply is informational and grants no authority.",
  );
  const textarea = element("textarea", "coordination-reply-text");
  textarea.maxLength = 2000;
  textarea.rows = 3;
  textarea.setAttribute("aria-label", `Reply to coordination message ${message.id}`);
  const controls = element("div", "coordination-actions");
  const cancel = element("button", "confirmation-button", "Cancel");
  cancel.type = "button";
  cancel.onclick = () => {
    textarea.value = "";
    editor.hidden = true;
  };
  const send = element("button", "confirmation-button confirmation-confirm", "Send reply");
  send.type = "button";
  const error = element("span", "coordination-action-status", "");
  send.onclick = () => submitCoordinationReply(message, textarea, error);
  controls.append(cancel, send, error);
  editor.append(notice, textarea, controls);
  return editor;
}

function hasNewCoordinationChatMessage(messages) {
  const latestOperatorId = messages.reduce(
    (latest, message) => message.sender === "operator"
      ? Math.max(latest, Number(message.id) || 0)
      : latest,
    0,
  );
  return messages.some(
    (message) => message.sender === "midlane"
      && (Number(message.id) || 0) > latestOperatorId
      && (Number(message.id) || 0) > coordinationSeenMidlaneMessageId,
  );
}

function acknowledgeCoordinationMessages() {
  const messages = Array.isArray(lastGood?.coordination_inbox?.chat)
    ? lastGood.coordination_inbox.chat
    : [];
  const latestMidlaneId = messages.reduce(
    (latest, message) => message.sender === "midlane"
      ? Math.max(latest, Number(message.id) || 0)
      : latest,
    0,
  );
  if (latestMidlaneId > 0) writeCoordinationSeenMidlaneMessageId(latestMidlaneId);
  document.getElementById("coordination-message-flag").hidden = true;
}

function renderCoordinationInbox(snapshot) {
  const card = document.getElementById("coordination-inbox-card");
  const target = document.getElementById("coordination-inbox-content");
  const requestFlag = document.getElementById("coordination-request-flag");
  const messageFlag = document.getElementById("coordination-message-flag");
  const draft = captureCoordinationReplyDraft();
  const inbox = snapshot.coordination_inbox || {
    available: false,
    open: [],
    warning: "coordination inbox unavailable",
  };
  const messages = Array.isArray(inbox.open) ? inbox.open : [];
  const chatMessages = Array.isArray(inbox.chat) ? inbox.chat : [];
  requestFlag.hidden = !messages.some(
    (message) => message.status === "OPEN" && message.message_type === "ACTION_REQUEST",
  );
  messageFlag.hidden = !hasNewCoordinationChatMessage(chatMessages);
  if (inbox.available && messages.length === 0) {
    card.hidden = false;
    setChildren(
      target,
      [element("div", "coordination-empty muted", "No open coordination messages")],
    );
    return;
  }
  card.hidden = false;
  if (!inbox.available) {
    setChildren(
      target,
      [element("div", "coordination-warning status-warn", inbox.warning || "Coordination inbox unavailable")],
    );
    return;
  }
  const messageIds = new Set(messages.map((message) => Number(message.id)));
  const childrenByParent = new Map();
  for (const message of messages) {
    const parentId = Number(message.reply_to_id || 0);
    if (!parentId || !messageIds.has(parentId)) continue;
    if (!childrenByParent.has(parentId)) childrenByParent.set(parentId, []);
    childrenByParent.get(parentId).push(message);
  }

  function messageNode(message, nested = false) {
    const row = element("article", "coordination-message");
    if (nested) row.classList.add("coordination-thread-reply");
    const heading = element("div", "coordination-message-heading");
    const type = String(message.message_type || "INFORMATION").replaceAll("_", " ");
    const dismiss = element("button", "coordination-dismiss", "X");
    dismiss.type = "button";
    dismiss.title = "Close this message";
    dismiss.setAttribute("aria-label", `Close coordination message ${message.id}`);
    dismiss.onclick = () => dismissCoordinationMessage(message, dismiss);
    heading.append(
      element("strong", "", type),
      element("span", "muted", message.scope_label || `${message.scope_kind} ${message.scope_ref}`),
      element("span", "muted", displayAge(message.age || "0m 0s")),
      dismiss,
    );
    row.append(heading, element("p", "coordination-body", message.body || ""));
    if (message.requested_action) {
      const action = element("p", "coordination-requested-action");
      action.append(
        element("strong", "", "Requested action: "),
        document.createTextNode(String(message.requested_action)),
      );
      row.append(action);
    }
    if (message.operator_reply) {
      const reply = element("p", "coordination-operator-reply");
      reply.append(
        element("strong", "", "Operator reply: "),
        document.createTextNode(String(message.operator_reply)),
      );
      row.append(reply);
    }
    row.append(
      element(
        "div",
        "coordination-meta muted",
        `Message #${message.id} | Revision ${message.revision} | ${message.status}`,
      ),
    );
    if (message.status === "OPEN") {
      const actions = element("div", "coordination-actions");
      const replyButton = element("button", "confirmation-button", "Reply");
      replyButton.type = "button";
      const editor = coordinationReplyEditor(message);
      replyButton.onclick = () => {
        editor.hidden = !editor.hidden;
        if (!editor.hidden) editor.querySelector("textarea").focus();
      };
      actions.append(replyButton);
      if (message.message_type === "ACTION_REQUEST") {
        const approve = element("button", "confirmation-button confirmation-confirm", "Approve");
        approve.type = "button";
        approve.onclick = () => submitCoordinationDecision(message, "APPROVED");
        const decline = element("button", "confirmation-button", "Decline");
        decline.type = "button";
        decline.onclick = () => submitCoordinationDecision(message, "DECLINED");
        actions.append(approve, decline);
      }
      row.append(actions, editor);
    } else if (message.status === "APPROVED") {
      row.append(
        element("div", "coordination-authority-note", "Approved for one-time Hunter pickup."),
      );
    }
    const replies = childrenByParent.get(Number(message.id)) || [];
    if (replies.length) {
      const thread = element("div", "coordination-thread");
      thread.append(...replies.map((child) => messageNode(child, true)));
      row.append(thread);
    }
    return row;
  }

  const rows = messages
    .filter((message) => {
      const parentId = Number(message.reply_to_id || 0);
      return !parentId || !messageIds.has(parentId);
    })
    .map((message) => messageNode(message));
  setChildren(target, rows);
  restoreCoordinationReplyDraft(draft);
}

function renderCoordinationChat(snapshot) {
  const target = document.getElementById("coordination-chat-history");
  const inbox = snapshot.coordination_inbox || {};
  const messages = Array.isArray(inbox.chat) ? inbox.chat : [];
  const priorScrollTop = target.scrollTop;
  const wasNearBottom =
    target.scrollHeight - target.scrollTop - target.clientHeight <= 24;
  if (!inbox.available) {
    setChildren(target, [element("div", "coordination-warning status-warn", "Midlane chat unavailable")]);
    return;
  }
  if (!messages.length) {
    setChildren(target, [element("div", "coordination-empty muted", "No Midlane chat messages")]);
    return;
  }
  const rows = messages.map((message) => {
    const sender = message.sender === "operator" ? "You" : "Midlane";
    const row = element("article", `coordination-chat-message coordination-chat-${message.sender || "unknown"}`);
    const heading = element("div", "coordination-chat-heading");
    heading.append(
      element("strong", "", sender),
      element("span", "muted", message.context_label || message.context_ref || "WORKFLOW"),
      element("span", "muted", displayAge(message.age || "0m 0s")),
    );
    row.append(heading, element("p", "coordination-chat-body", message.body || ""));
    if (message.sender === "operator" && message.status === "OPEN") {
      row.append(element("div", "coordination-chat-pending muted", "Awaiting Midlane"));
    }
    return row;
  });
  setChildren(target, rows);
  target.scrollTop = wasNearBottom
    ? target.scrollHeight
    : Math.min(priorScrollTop, Math.max(0, target.scrollHeight - target.clientHeight));
}

async function submitCoordinationChat(event) {
  event.preventDefault();
  const input = document.getElementById("coordination-chat-input");
  const send = document.getElementById("coordination-chat-send");
  const status = document.getElementById("coordination-chat-status");
  const body = input.value.trim();
  if (!body) {
    status.textContent = "Enter a message";
    input.focus();
    return;
  }
  send.disabled = true;
  status.textContent = "Sending";
  try {
    const response = await fetch("/api/coordination/chat/send", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-JENNY-Operator": "send-coordination-chat",
      },
      body: JSON.stringify({ body }),
    });
    if (!response.ok) throw new Error(`send failed (${response.status})`);
    input.value = "";
    status.textContent = "Sent";
    await poll();
  } catch (problem) {
    status.textContent = problem instanceof Error ? problem.message : "Send failed";
  } finally {
    send.disabled = false;
  }
}

function alertClass(alert) {
  if (alert.code === "OPERATOR_HELP_REQUEST") return "alert alert-operator";
  if (alert.code === "HUNTER_APPROVAL_REQUEST") return "alert alert-request";
  if (alert.code === "READY_TO_SUBMIT") return "alert alert-ready";
  if (alert.severity === "error") return "alert alert-error";
  return "alert alert-warning";
}

function researchRow(research) {
  return line("Research",
    `${research.complete} complete | ${research.active} active | ` +
    `${research.blocked} blocked | ${research.open_hypotheses} open hypotheses`);
}

function renderHunter(snapshot) {
  const hunter = (snapshot.workers || []).find((worker) => worker.worker === "hunter");
  const research = snapshot.hunt_state;
  if (!hunter) {
    const rows = [line("State", "not observed", "status-muted")];
    if (research) {
      rows.push(researchRow(research));
    }
    card("hunter-card", "Hunter", rows);
    return;
  }
  const state = hunter.stale
    ? "POSSIBLY STALLED"
    : hunter.display_state || hunter.state;
  const rows = [
    line("State", state, stateClass(state)),
    line("Task", hunter.task || "none"),
    line("Detail", hunter.detail || "none"),
    line("Status age", displayAge(hunter.semantic_age || "unknown")),
  ];
  if (hunter.availability_state === "STATUS UNKNOWN") {
    rows.push(line("Availability", "STATUS UNKNOWN", "status-warn"));
  }
  if (hunter.activity_detail) {
    rows.push(line("Live activity", hunter.activity_detail));
    rows.push(line("Live activity age", displayAge(hunter.activity_age || "unknown")));
  }
  if (research) {
    rows.push(researchRow(research));
  }
  card("hunter-card", "Hunter", rows);
}

function midlaneInvestigationView(investigation) {
  const classification = String(investigation?.classification || "UNKNOWN")
    .trim()
    .toUpperCase();
  const status = classification === "WORKING (ACTIVITY VERIFIED)"
    ? "WORKING - ACTIVITY VERIFIED"
    : classification.replaceAll("_", " ");
  let statusClass = "status-muted";
  if (classification === "WORKING (ACTIVITY VERIFIED)" || classification === "LIKELY ACTIVE") {
    statusClass = "status-ok";
  } else if (classification === "LIKELY STALLED") {
    statusClass = "status-error";
  } else if (classification === "WATCH" || classification === "UNKNOWN") {
    statusClass = "status-warn";
  }

  const detail = String(investigation?.detail || "").trim();
  const fieldPattern = /(?:^|;\s*)(File activity|Hunter chat|Uncertainty|Operator action):\s*/gi;
  const matches = [...detail.matchAll(fieldPattern)];
  if (!matches.length) {
    return {
      status,
      statusClass,
      rows: detail ? [{ label: "Assessment", value: detail }] : [],
    };
  }

  const rows = [];
  for (let index = 0; index < matches.length; index += 1) {
    const match = matches[index];
    const next = matches[index + 1];
    const label = match[1].toLowerCase();
    let value = detail.slice(match.index + match[0].length, next?.index ?? detail.length).trim();
    value = value.replace(/;\s*$/, "");
    if (!value) continue;

    if (label === "file activity") {
      const activity = /^(.+?)\s+\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s+\(([^)]+)\)$/.exec(value);
      if (activity) {
        const [age, ...context] = activity[2].split(",").map((part) => part.trim());
        value = `${activity[1]} updated ${age}`;
        if (context.length) value += ` - ${context.join(", ")}`;
      }
      rows.push({ label: "Live evidence", value });
      continue;
    }
    if (label === "hunter chat") {
      rows.push({
        label: "Hunter chat",
        value: /^(?:N\/?A|unavailable)$/i.test(value) ? "Not available" : value,
      });
      continue;
    }
    if (label === "uncertainty") {
      value = value
        .replace(/^semantic check-in stale since\s+/i, "Hunter update overdue since ")
        .replace(
          /\s+but\s+continuous file writes confirm guarded-run active$/i,
          "; live file writes confirm the guarded run is active",
        );
      rows.push({ label: "Assessment", value });
      continue;
    }
    rows.push({
      label: "Action needed",
      value: /^none required$/i.test(value) ? "None" : value,
    });
  }
  return { status, statusClass, rows };
}

function renderMidlane(snapshot) {
  const target = document.getElementById("midlane-card");
  const midlane = snapshot.midlane || { status: "not observed" };
  const worker = (snapshot.workers || []).find(
    (worker) => worker.worker === "midlane",
  ) || {};
  const state = String(worker.state || "").toUpperCase();
  const active = state === "WORKING" || state === "BLOCKED";
  if (!midlane.investigation && !active) {
    target.hidden = true;
    setChildren(target, []);
    return;
  }
  target.hidden = false;
  if (midlane.investigation) {
    const investigation = midlane.investigation;
    const view = midlaneInvestigationView(investigation);
    const checked = displayAge(investigation.age || "unknown");
    const rows = [line("Status", view.status, view.statusClass)];
    rows.push(...view.rows.map((row) => line(row.label, row.value)));
    rows.push(line("Last checked", checked === "unknown" ? checked : `${checked} ago`));
    card("midlane-card", "Midlane", rows);
    return;
  }
  card("midlane-card", "Midlane", [
    line("State", state || "not observed", state ? stateClass(state) : "status-muted"),
    line("Task", worker.task || "none"),
    line("Detail", worker.detail || "No detail recorded"),
    line("Activity age", displayAge(worker.age || "unknown")),
  ]);
}

function renderHost(snapshot) {
  const host = snapshot.host || {};
  const cpu = host.cpu || {};
  const memory = host.memory || {};
  const disk = host.disk || {};
  const docker = host.docker || {};
  const cpuText = Number.isFinite(cpu.percent) ? `${cpu.percent.toFixed(1)}%` : cpu.status || "unknown";
  const memoryText = memory.status === "ok" ? `${memory.percent_used.toFixed(1)}% used` : "unknown";
  const diskText = disk.status === "ok" ? `${disk.free_gib.toFixed(1)} GiB free` : "unknown";
  const dockerText = docker.available ? `available ${docker.version || ""}`.trim() : docker.status || "unknown";
  card("host-card", "Host", [
    line("CPU", cpuText),
    line("Memory", memoryText),
    line("Workspace disk", diskText),
    line("Docker", dockerText, docker.available ? "status-ok" : "status-muted"),
  ]);
}

function renderFinalReviewer(snapshot) {
  const target = document.getElementById("final-reviewer-panel");
  const reviewer = snapshot.final_reviewer;
  if (!reviewer || !["WORKING", "BLOCKED"].includes(reviewer.state)) {
    target.hidden = true;
    setChildren(target, []);
    return;
  }
  const state = reviewer.stale ? "POSSIBLY STALLED" : reviewer.state;
  card("final-reviewer-panel", "Final Reviewer", [
    line("State", state, reviewer.stale ? "status-error" : stateClass(state)),
    line("Package / task", reviewer.task || "none"),
    line("Current step", reviewer.detail || "none"),
    line("Activity age", displayAge(reviewer.age || "unknown")),
  ]);
  target.hidden = false;
}

function terminalCountRank(name) {
  const rank = TERMINAL_COUNT_ORDER.indexOf(name);
  return rank === -1 ? TERMINAL_COUNT_ORDER.length : rank;
}

function orderedTerminalEntries(counts) {
  return Object.entries(counts).sort(([left], [right]) => {
    const rankDifference = terminalCountRank(left) - terminalCountRank(right);
    return rankDifference || left.localeCompare(right);
  });
}

function cell(text, className = "", label = "") {
  const node = element("td", className, text);
  if (label) node.dataset.label = label;
  return node;
}

function candidateReviewView(item) {
  const reviewer = String(item.reviewer || "");
  const disposition = String(item.disposition || "").replaceAll("_", " ");
  const metadata = [];
  if (disposition) metadata.push(disposition);
  metadata.push(reviewer ? `Reviewer: ${reviewer}` : "Unclaimed");
  return {
    candidate: `#${item.id}`,
    product: item.product || item.target_slug || "Unknown product",
    title: item.title || "Untitled candidate",
    version: item.version || "Unknown",
    state: String(item.state || "UNKNOWN").replaceAll("_", " "),
    metadata: metadata.join(" \u00b7 "),
    next: `${item.next_actor || "Unknown"}: ${item.next_action || "No action recorded"}`,
    age: item.age || "unknown",
  };
}

function renderCandidateReviews(snapshot) {
  const panel = document.getElementById("candidate-review-panel");
  const count = document.getElementById("candidate-review-count");
  const target = document.getElementById("candidate-review-rows");
  const items = (Array.isArray(snapshot.candidate_reviews)
    ? snapshot.candidate_reviews
    : []).filter((item) => ["PENDING", "CLAIMED"].includes(item.state));
  if (!items.length) {
    panel.hidden = true;
    panel.open = false;
    count.textContent = "";
    setChildren(target, []);
    return;
  }
  const rows = items.map((item) => {
    const view = candidateReviewView(item);
    const state = cell(view.state, `state ${stateClass(view.state)}`, "State");
    state.append(element("span", "candidate-review-meta", view.metadata));
    const row = element("tr");
    row.append(
      cell(view.candidate, "", "Candidate"),
      cell(view.product, "", "Product"),
      cell(view.title, "candidate-review-title", "Title"),
      cell(view.version, "", "Version"),
      state,
      cell(view.next, "candidate-review-next", "Next"),
      cell(displayAge(view.age), "", "Age"),
    );
    return row;
  });
  count.textContent = `${items.length} active`;
  setChildren(target, rows);
  panel.hidden = false;
}

async function confirmSubmitted(item, button) {
  const packageNumber = item.package_number || item.id;
  const confirmed = await openConfirmationDialog({
    title: `Mark package #${packageNumber} submitted?`,
    summary: item.title || item.package_name || `Package #${packageNumber}`,
    changes: [
      "Revalidates the exact READY package identity and confirms its frozen hash has not drifted.",
      "Moves the unchanged reviewed package into ZDI/_SUBMITTED and normalizes its _SUBMITTED_ folder prefix.",
      "Records the terminal OPERATOR SUBMITTED state and removes the package from the active review inbox.",
    ],
    unchanged: [
      "Does not submit anything to the portal, create a case, or contact ZDI.",
      "Does not edit sealed package contents or infer a case ID, buyer decision, or acceptance.",
    ],
    warning: `Continue only if package #${packageNumber} was actually submitted through the ZDI portal.`,
    confirmLabel: "Mark submitted",
  });
  if (!confirmed) return;

  button.disabled = true;
  try {
    const response = await fetch("/api/mark-submitted", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-JENNY-Operator": "confirm-submitted",
      },
      body: JSON.stringify({ item_id: item.id, confirmed: true }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.detail || payload.error || `HTTP ${response.status}`);
    }
    await poll();
  } catch (error) {
    const detail = error instanceof Error
      ? error.message
      : "The package could not be reconciled safely.";
    showOperatorActionFeedback(
      "error",
      `Package #${packageNumber} could not be reconciled. ` +
      detail,
    );
  } finally {
    button.disabled = false;
  }
}

function submissionButton(item) {
  const button = element("button", "package-action", "Mark submitted");
  button.type = "button";
  button.addEventListener("click", () => confirmSubmitted(item, button));
  return button;
}

function isReadyToSubmit(item) {
  return item.submission_available === true &&
    item.display_state === "READY TO SUBMIT";
}

function renderActive(snapshot) {
  const panel = document.getElementById("active-panel");
  const heading = document.getElementById("active-heading");
  const tableWrap = document.getElementById("active-table-wrap");
  const target = document.getElementById("active-packages");
  const items = snapshot.active_items || [];
  const expandedItems = new Set(
    [...target.querySelectorAll("details.package-detail[open]")]
      .map((details) => details.dataset.itemId),
  );
  if (!items.length) {
    heading.textContent = "NO ACTIVE PACKAGES";
    tableWrap.hidden = true;
    panel.classList.add("empty-active");
    setChildren(target, []);
    return;
  }
  heading.textContent = "ACTIVE PACKAGES";
  tableWrap.hidden = false;
  panel.classList.remove("empty-active");
  const rows = items.flatMap((item) => {
    const row = element("tr");
    const packageText = item.package_number ? `#${item.package_number}` : `item ${item.id}`;
    const state = cell(
      item.display_state,
      `state ${stateClass(item.display_state)}`,
      "State",
    );
    if (item.candidate_challenge_id) {
      const admission = String(
        item.candidate_disposition || item.candidate_state || "PENDING",
      ).replaceAll("_", " ");
      state.append(
        element(
          "span",
          "package-admission",
          `Challenge #${item.candidate_challenge_id} \u00b7 ${admission}`,
        ),
      );
    }
    if (isReadyToSubmit(item)) {
      state.append(submissionButton(item));
    }
    row.append(
      cell(packageText, "", "Package"),
      cell(item.product || item.name, "", "Product"),
      cell(item.title || packageLabel(item.name), "package-title", "Title"),
      cell(item.revision, "", "Rev"),
      state,
      cell(item.active_worker || "\u2014", "working-cell", "Working"),
      cell(displayAge(item.age), "", "Age"),
    );
    const details = element("details", "package-detail");
    details.dataset.itemId = String(item.id);
    details.open = expandedItems.has(String(item.id));
    details.append(element("summary", "", "Package details"));
    const determination = item.final_determination || {};
    const hasDetermination = determination.schema === "jenny.final-review-determination.v1";
    const finalReview = item.final_verdict ? [
      line("Same-product rank", hasDetermination ? determination.same_product_rank : "not recorded"),
      line("Actual vulnerability", hasDetermination ? determination.actual_vulnerability : "not recorded"),
      line("Exploit path", hasDetermination ? determination.exploit_path : "not recorded"),
      line("Threat-actor impact", hasDetermination ? determination.threat_actor_impact : "not recorded"),
      line("Decisive proof", hasDetermination ? determination.decisive_proof : "not recorded"),
      line("CVSS", hasDetermination ? determination.cvss : "not recorded"),
      line("Duplicate posture", hasDetermination ? determination.duplicate_posture : "not recorded"),
      line("Estimated payout", hasDetermination ? determination.estimated_payout : "not recorded"),
      line("Discovery difficulty", hasDetermination ? determination.discovery_difficulty : "not recorded"),
      line("Exact next action", `${item.next_actor || "Unknown"}: ${item.next_action || "Inspect workflow state"}`),
    ] : [];
    details.append(
      ...finalReview,
      ...(item.final_verdict ? [] : [
        line("Next", `${item.next_actor || "Unknown"}: ${item.next_action || "Inspect workflow state"}`),
      ]),
    );
    const detailCell = element("td", "package-detail-cell");
    detailCell.colSpan = 7;
    detailCell.append(details);
    const detailRow = element("tr", "package-detail-row");
    detailRow.append(detailCell);
    return [row, detailRow];
  });
  setChildren(target, rows);
}

function renderTerminal(snapshot) {
  const target = document.getElementById("terminal-packages");
  const summary = document.getElementById("terminal-summary");
  const counts = snapshot.terminal_counts || {};
  summary.textContent = orderedTerminalEntries(counts)
    .map(([name, count]) => `${name.replaceAll("_", " ")} ${count}`)
    .join(" | ");
  const items = snapshot.terminal_items || [];
  if (!items.length) {
    setChildren(target, [element("div", "empty", "No terminal packages")]);
    return;
  }
  const rows = items.map((item) => {
    const row = element("div", "terminal-row");
    if (String(item.state).toUpperCase() === "DEAD") {
      row.classList.add("terminal-dead");
    }
    const stateText = item.accepted_amount
      ? `${item.display_state} \u00b7 ${item.accepted_amount}`
      : item.display_state;
    row.append(
      element("span", "", item.package_number ? `#${item.package_number}` : `item ${item.id}`),
      element("span", "", packageLabel(item.name)),
      element("span", `state ${stateClass(item.display_state)}`, stateText),
      element("span", "muted", displayAge(item.age)),
    );
    return row;
  });
  setChildren(target, rows);
}

function renderEvents(snapshot) {
  const target = document.getElementById("recent-events");
  const events = snapshot.recent_events || [];
  if (!events.length) {
    setChildren(target, [element("div", "empty", "No recent activity")]);
    return;
  }
  const rows = events.map(eventRow);
  setChildren(target, rows);
}

function eventRow(event) {
  const row = element("div", "event-row");
  const eventMain = element("span", "event-main");
  const eventType = String(event.event_type || "").toUpperCase();
  const majorEvent = MAJOR_EVENT_TYPES.has(eventType);
  const packageSuffix = event.package_number ? ` (#${event.package_number})` : "";
  const label = `${eventLabel(event.event_type)}${packageSuffix}`;
  const actor = {
    hunter: "Hunter",
    midlane: "Midlane",
    "final-reviewer": "Final Reviewer",
    operator: "Operator",
  }[String(event.actor || "").toLowerCase()] || String(event.actor || "System");
  eventMain.append(element(majorEvent ? "b" : "span", "", label));
  if (event.detail) {
    eventMain.append(element("span", "event-detail muted", event.detail));
  }
  row.append(
    element("span", "", actor),
    eventMain,
    element("span", "muted", displayAge(event.age)),
  );
  return row;
}

function weeklyProductBase(products, product) {
  const folded = product.toLowerCase();
  return products.find(
    (candidate) =>
      folded === candidate.toLowerCase() ||
      folded.startsWith(`${candidate.toLowerCase()} `),
  );
}

function weeklyOutcomeSummary(summary) {
  const value = String(summary || "").trim();
  const chronologyMarkers = [
    " This legacy package has no recorded submission timestamp",
    " The release followed the recorded submission by ",
    " Submission chronology is unavailable",
  ];
  const cuts = chronologyMarkers
    .map((marker) => value.indexOf(marker))
    .filter((index) => index >= 0);
  return cuts.length ? value.slice(0, Math.min(...cuts)).trim() : value;
}

function weeklyProductClassifications(outcomes) {
  return [...new Set(
    outcomes.map((outcome) => String(outcome.status || "")).filter(Boolean),
  )];
}

function weeklyCount(label, value) {
  const count = Number(value) || 0;
  return element(
    "span",
    `count${count > 0 ? " active" : ""}`,
    `${label} ${count}`,
  );
}

function groupWeeklyAlertsByProduct(alerts) {
  const products = [...new Set(
    alerts.map((alert) => String(alert.product || "Unknown product")),
  )].sort((left, right) => left.length - right.length || left.localeCompare(right));
  const bases = products.filter(
    (product, index) => !weeklyProductBase(products.slice(0, index), product),
  );
  const groups = bases.map((product) => ({ product, alerts: [], outcomes: [] }));

  for (const alert of alerts) {
    const product = String(alert.product || "Unknown product");
    const base = weeklyProductBase(bases, product) || product;
    let group = groups.find((candidate) => candidate.product === base);
    if (!group) {
      group = { product: base, alerts: [], outcomes: [] };
      groups.push(group);
    }
    group.alerts.push(alert);
  }

  for (const group of groups) {
    const byOutcome = new Map();
    for (const alert of group.alerts) {
      const sourceUrls = [...new Set(alert.source_urls || [])].sort();
      const chronology = alert.chronology || {};
      const summary = weeklyOutcomeSummary(alert.summary);
      const key = [
        alert.status || "",
        chronology.public_change_at || "",
        sourceUrls.join("|"),
        summary,
      ].join("\n");
      if (!byOutcome.has(key)) {
        byOutcome.set(key, {
          status: alert.status,
          summary,
          sourceUrls,
          packageNumbers: [],
          chronology: [],
        });
      }
      const outcome = byOutcome.get(key);
      if (alert.package_number) outcome.packageNumbers.push(alert.package_number);
      outcome.chronology.push({
        packageNumber: alert.package_number,
        submissionAt: chronology.submission_at || "",
        publicChangeAt: chronology.public_change_at || "",
      });
    }
    group.outcomes = [...byOutcome.values()];
    for (const outcome of group.outcomes) {
      outcome.packageNumbers.sort((left, right) => left - right);
    }
  }
  return groups;
}

function weeklyInterval(milliseconds) {
  let minutes = Math.max(0, Math.floor(milliseconds / 60000));
  const days = Math.floor(minutes / 1440);
  minutes -= days * 1440;
  const hours = Math.floor(minutes / 60);
  minutes -= hours * 60;
  return [days ? `${days}d` : "", hours ? `${hours}h` : "", `${minutes}m`]
    .filter(Boolean)
    .join(" ");
}

function weeklyChronologySummary(records) {
  const intervals = [];
  let missing = 0;
  for (const record of records) {
    if (!record.submissionAt || !record.publicChangeAt) {
      missing += 1;
      continue;
    }
    const submission = Date.parse(record.submissionAt);
    const publicChange = Date.parse(record.publicChangeAt);
    if (!Number.isFinite(submission) || !Number.isFinite(publicChange)) {
      missing += 1;
      continue;
    }
    intervals.push(publicChange - submission);
  }
  const parts = [];
  if (intervals.length) {
    const minimum = weeklyInterval(Math.min(...intervals));
    const maximum = weeklyInterval(Math.max(...intervals));
    const range = minimum === maximum ? minimum : `${minimum} to ${maximum}`;
    parts.push(
      `Submission-to-release interval: ${range} across ${intervals.length} recorded package${intervals.length === 1 ? "" : "s"}.`,
    );
  }
  if (missing) {
    parts.push(
      `${missing} legacy package${missing === 1 ? "" : "s"} lack${missing === 1 ? "s" : ""} a recorded submission timestamp.`,
    );
  }
  return parts.join(" ");
}

function weeklyDisplayRange(startedAt, completedAt, fallbackDate) {
  const label = (value) => {
    const month = String(value.getMonth() + 1).padStart(2, "0");
    const day = String(value.getDate()).padStart(2, "0");
    const year = String(value.getFullYear()).slice(-2);
    return `${month}/${day}/${year}`;
  };
  const start = new Date(String(startedAt || ""));
  const end = new Date(String(completedAt || startedAt || ""));
  if (!Number.isNaN(start.getTime()) && !Number.isNaN(end.getTime())) {
    const startLabel = label(start);
    const endLabel = label(end);
    const sameDay = startLabel === endLabel;
    return sameDay ? startLabel : `${startLabel} - ${endLabel}`;
  }
  const fallback = new Date(`${String(fallbackDate || "")}T12:00:00`);
  return Number.isNaN(fallback.getTime()) ? "unknown timeframe" : label(fallback);
}

function formatWeeklyCountdown(milliseconds) {
  let remaining = Math.max(0, Math.floor(milliseconds / 1000));
  const days = Math.floor(remaining / 86400);
  remaining %= 86400;
  const hours = Math.floor(remaining / 3600);
  remaining %= 3600;
  const minutes = Math.floor(remaining / 60);
  const seconds = remaining % 60;
  if (minutePrecision) return `${days}d ${hours}h ${minutes}m`;
  return `${days}d ${hours}h ${minutes}m ${seconds}s`;
}

function updateWeeklyCountdown() {
  if (hasActiveTextSelection()) return;
  const target = document.getElementById("weekly-patch-countdown");
  if (!target) return;
  if (!Number.isFinite(weeklyCountdownDeadline) || weeklyCountdownDeadline <= 0) {
    target.textContent = "Next run unavailable";
    return;
  }
  target.textContent =
    `Next run in ${formatWeeklyCountdown(weeklyCountdownDeadline - Date.now())}`;
}

function scheduleWeeklyCountdownTick() {
  if (weeklyCountdownTimer !== null) clearTimeout(weeklyCountdownTimer);
  weeklyCountdownTimer = setTimeout(() => {
    weeklyCountdownTimer = null;
    updateWeeklyCountdown();
    scheduleWeeklyCountdownTick();
  }, minutePrecision ? PARKED_POLL_MS : ACTIVE_POLL_MS);
}

function renderWeeklyPatchWatch(snapshot) {
  const summary = document.getElementById("weekly-patch-summary");
  const target = document.getElementById("weekly-patch-content");
  weeklyCountdownDeadline = Date.parse(
    String(snapshot.weekly_patch_watch_next_run_at || ""),
  );
  updateWeeklyCountdown();
  const expandedProducts = new Set(
    [...target.querySelectorAll("details.weekly-product[open]")]
      .map((product) => product.dataset.product),
  );
  const watch = snapshot.weekly_patch_watch;
  if (!watch) {
    summary.textContent = "Weekly Patch Watch | not run yet";
    setChildren(target, [element("div", "empty", "No weekly submitted-case sweep has completed")]);
    return;
  }

  const report = watch.report;
  const progress = `${watch.completed || 0}/${watch.total || 0} checked`;
  summary.textContent =
    `Weekly Patch Watch | ${weeklyDisplayRange(watch.window_started_at || watch.started_at, watch.window_ended_at || watch.completed_at || report?.generated_at, watch.monday_date)} | ${progress}`;

  const children = [];
  if (!report) {
    children.push(watch.state === "RUNNING"
      ? element("p", "weekly-headline", "Public patch review is in progress.")
      : element(
        "p",
        "weekly-report-missing status-error",
        "Completed report unavailable. Refresh the workflow service or inspect report integrity.",
      ));
    setChildren(target, children);
    return;
  }

  const counts = report.counts || {};
  const countList = element("div", "count-list weekly-counts");
  countList.append(
    weeklyCount("No public change", counts.no_public_change),
    weeklyCount("Likely exact fix", counts.likely_exact_fix),
    weeklyCount("Released after submission", counts.fix_released_after_submission),
    weeklyCount("Public after submission", counts.public_after_submission),
    weeklyCount("Possible match", counts.possible_fix),
    weeklyCount("Public before submission", counts.public_before_submission),
    weeklyCount(
      "Source or record gaps",
      (counts.source_unavailable || 0) + (counts.record_incomplete || 0),
    ),
  );
  children.push(countList);

  const alerts = Array.isArray(report.alerts) ? report.alerts : [];
  if (!alerts.length) {
    children.push(element("div", "empty", "No patch matches or research gaps require attention"));
  } else {
    const list = element("div", "weekly-alerts");
    for (const productGroup of groupWeeklyAlertsByProduct(alerts)) {
      const product = element("details", "weekly-product");
      product.dataset.product = productGroup.product;
      product.open = expandedProducts.has(productGroup.product);
      const productTitle = element("summary", "weekly-product-title");
      const classifications = element("span", "weekly-product-classifications");
      for (const status of weeklyProductClassifications(productGroup.outcomes)) {
        classifications.append(
          element(
            "span",
            `weekly-classification state ${stateClass(status)}`,
            eventLabel(status),
          ),
        );
      }
      productTitle.append(
        element("span", "weekly-product-name", productGroup.product),
        classifications,
      );
      product.append(productTitle);
      for (const outcome of productGroup.outcomes) {
        const row = element("div", "weekly-outcome");
        const packageText = outcome.packageNumbers.length
          ? `Packages ${outcome.packageNumbers.map((number) => `#${number}`).join(", ")}`
          : "Packages unavailable";
        row.append(
          element("p", "weekly-packages muted", packageText),
          element("p", `state ${stateClass(outcome.status)}`, eventLabel(outcome.status)),
          element("p", "weekly-summary", outcome.summary),
        );
        const chronologyText = weeklyChronologySummary(outcome.chronology);
        if (chronologyText) {
          row.append(element("p", "weekly-chronology muted", chronologyText));
        }
        const sources = element("div", "weekly-sources");
        for (const url of outcome.sourceUrls) {
          const source = element("a", "", url);
          source.href = url;
          source.target = "_blank";
          source.rel = "noreferrer";
          sources.append(source);
        }
        if (sources.childNodes.length) row.append(sources);
        product.append(row);
      }
      list.append(product);
    }
    children.push(list);
  }
  setChildren(target, children);
}

function render(snapshot, stale = false, errorMessage = "") {
  if (!snapshot) {
    renderAlerts({ alerts: [] }, true, errorMessage);
    document.getElementById("refresh-status").textContent = "No status received";
    return;
  }
  minutePrecision = Number(snapshot.refresh_seconds) === 60;
  renderProjectIdentity(snapshot);
  renderActiveTarget(snapshot);
  renderFirstRun(snapshot);
  renderWeeklyPatchAcknowledgement(snapshot);
  renderReportIssuesAcknowledgement(snapshot);
  renderDiminishingReturns(snapshot);
  renderPackageOutcomeNotifications(snapshot);
  renderAlerts(snapshot, stale, errorMessage);
  renderCoordinationChat(snapshot);
  renderCoordinationInbox(snapshot);
  renderHunter(snapshot);
  renderMidlane(snapshot);
  renderHost(snapshot);
  renderHuntProfile(snapshot);
  renderFinalReviewer(snapshot);
  renderCandidateReviews(snapshot);
  renderActive(snapshot);
  renderTerminal(snapshot);
  renderEvents(snapshot);
  renderReportIssues(snapshot);
  renderWeeklyPatchWatch(snapshot);
  const refresh = document.getElementById("refresh-status");
  refresh.textContent = stale
    ? `Stale snapshot from ${displayTime(snapshot.display_time || "unknown")}`
    : `Updated ${displayTime(snapshot.display_time || "now")}`;
  refresh.className = stale ? "refresh-status status-error" : "refresh-status";
}

async function poll() {
  if (inFlight) return;
  inFlight = true;
  const controller = new AbortController();
  const fetchTimeout = setTimeout(
    () => controller.abort(),
    STATUS_FETCH_TIMEOUT_MS,
  );
  try {
    const response = await fetch("/api/status", {
      cache: "no-store",
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`status ${response.status}`);
    lastGood = await response.json();
    renderWhenCopySafe(lastGood, false);
  } catch (error) {
    renderWhenCopySafe(
      lastGood,
      true,
      error instanceof Error ? error.message : "status unavailable",
    );
  } finally {
    clearTimeout(fetchTimeout);
    inFlight = false;
  }
}

function pollDelayMs() {
  const refreshSeconds = Number(lastGood && lastGood.refresh_seconds);
  return refreshSeconds === 60 ? PARKED_POLL_MS : ACTIVE_POLL_MS;
}

function scheduleNextPoll() {
  if (pollTimer !== null) clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    pollTimer = null;
    try {
      await poll();
    } finally {
      scheduleNextPoll();
    }
  }, pollDelayMs());
}

async function startPolling() {
  try {
    await poll();
  } finally {
    scheduleNextPoll();
  }
}

document.addEventListener("selectionchange", flushPendingRender);
document.addEventListener("copy", () => {
  setTimeout(() => flushPendingRender(true), 0);
});
document.getElementById("coordination-chat-form").addEventListener("submit", submitCoordinationChat);
document.getElementById("refresh-now").addEventListener("click", async () => {
  await poll();
  scheduleNextPoll();
});
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") poll();
});
const coordinationCard = document.getElementById("coordination-inbox-card");
coordinationCard.addEventListener("click", acknowledgeCoordinationMessages);
coordinationCard.addEventListener("focusin", acknowledgeCoordinationMessages);
scheduleWeeklyCountdownTick();
startPolling();
