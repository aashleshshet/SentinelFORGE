import { useEffect, useState, type MouseEvent } from "react";
import { ArrowRight, ArrowUpRight, ChevronDown } from "lucide-react";
import { GlassButton } from "./components/glass";
import type { View } from "./types";
import "./what-it-is.css";

const repository = "https://github.com/aashleshshet/SentinelFORGE";
const evidenceReport = `${repository}/blob/ab465af/docs/DETECTION_IMPROVEMENT.md`;
const sections = [
  ["purpose", "Purpose & people"],
  ["workflow", "From event to evidence"],
  ["sources", "Supported telemetry"],
  ["detections", "Detection scope"],
  ["modes", "Workspace modes"],
  ["trust", "Trust & limitations"],
  ["start", "Explore the workspace"],
] as const;

const sources = [
  {
    name: "Linux authentication",
    format: "Authentication log records",
    detail:
      "Extract SSH authentication outcomes, source addresses, hosts and users. Repeated failures can contribute to the time-windowed SSH rule.",
    limit:
      "A supported authentication record is required. This adapter does not collect logs from a host or establish whether an attempted login was authorized.",
  },
  {
    name: "Linux auditd",
    format: "Assembled JSON records",
    detail:
      "Inspect supported process and command observations in auditd events, including behavior relevant to privilege and shell detections.",
    limit:
      "Assemble the related audit records before importing. Arbitrary raw audit.log lines are not a substitute for the supported JSON structure.",
  },
  {
    name: "Windows Sysmon",
    format: "JSON · event IDs 1 and 3",
    detail:
      "Use process creation and network connection observations: process images, command lines, parent context and destination addresses when present.",
    limit:
      "Export supported JSON first. Native EVTX/XML ingestion is not included. An executable hash does not establish the contents of a script it launches.",
  },
  {
    name: "Wazuh",
    format: "JSON alert records",
    detail:
      "Map supported Wazuh fields into the common event model while retaining the submitted record for authorized evidence review.",
    limit:
      "Coverage depends on the fields in the alert. Importing a Wazuh record does not make every Wazuh decoder or detection available in SentinelForge.",
  },
  {
    name: "Zeek network",
    format: "conn JSON records",
    detail:
      "Inspect connection metadata such as source and destination addresses and destination ports. These observations support the network rules.",
    limit:
      "Connection metadata is not packet content. Port 443 does not prove HTTPS, an encrypted payload or command-and-control activity.",
  },
  {
    name: "Synthetic JSON",
    format: "Normalized event envelopes",
    detail:
      "Replay bounded, repeatable scenarios through the same normalization, detection and case workflow used by supported imported telemetry.",
    limit:
      "Synthetic events demonstrate behavior under defined inputs. They do not establish detection performance on an organization’s real environment.",
  },
] as const;

const modes = {
  public: {
    name: "Public demo",
    description:
      "Explore a fixed synthetic investigation without an account. This is the portfolio experience, separate from an operator’s local data.",
    facts: [
      ["Data", "Bundled synthetic snapshot; no live feed or private uploads."],
      [
        "Access",
        "No sign-in. Read-only browsing and bundled evidence exports.",
      ],
      [
        "Actions",
        "Case edits, ingestion and response requests are unavailable.",
      ],
      ["Storage", "Isolated, read-only in-memory database."],
    ],
    note: "The demo contains 18 events, seven alerts and two cases. Nine rule definitions describe the current experimental detection scope.",
  },
  local: {
    name: "Local workspace",
    description:
      "Run the editable lab on your own trusted computer. The explicit local runner gives you a shared local administrator identity without asking for a token.",
    facts: [
      ["Data", "Your imported telemetry and synthetic replays."],
      [
        "Access",
        "Loopback only; all local programs share the local trust boundary.",
      ],
      ["Actions", "Import, investigate, annotate and preserve evidence."],
      ["Storage", "Persistent local SQLite database in the default setup."],
    ],
    note: "Start with python scripts/run_local.py after completing repository setup. Keep this mode on loopback; the shared identity cannot supply two different people for approval.",
  },
  authenticated: {
    name: "Authenticated workspace",
    description:
      "Use distinct operator-configured identities to exercise role separation and approval behavior in the lab.",
    facts: [
      [
        "Data",
        "Telemetry held by the configured SQLite or PostgreSQL database.",
      ],
      ["Access", "Viewer, analyst, admin and ingestion-only identities."],
      [
        "Actions",
        "Server-enforced permissions; a different admin approves a simulation.",
      ],
      ["Storage", "Persistent database controlled by the operator."],
    ],
    note: "Bearer tokens are kept only in browser memory. Static tokens have no built-in expiry or MFA; wider deployment needs additional security controls and review.",
  },
} as const;
type Mode = keyof typeof modes;

export default function WhatItIs({
  navigate,
  showGuide,
}: {
  navigate: (view: View) => void;
  showGuide: (event: MouseEvent<HTMLAnchorElement>) => void;
}) {
  useEffect(() => {
    document.getElementById("main-content")?.focus({ preventScroll: true });
    if (window.location.hash) {
      document.getElementById(window.location.hash.slice(1))?.scrollIntoView();
    }
  }, []);
  const [mode, setMode] = useState<Mode>("public");
  const currentMode = modes[mode];

  return (
    <main id="main-content" className="about" tabIndex={-1}>
      <header className="about-hero">
        <div className="about-introduction">
          <h1>What is SentinelForge?</h1>
          <p className="about-definition">
            A security investigation lab that turns supported logs into
            explainable alerts, connected cases and reviewable evidence.
          </p>
          <p>
            Follow the reasoning behind a detection. Inspect the original
            observations. Record what you found before deciding what the signal
            means.
          </p>
          <div className="about-actions">
            <GlassButton
              className="primary"
              onClick={() => navigate("overview")}
            >
              Explore workspace <ArrowRight size={17} />
            </GlassButton>
            <a
              className="about-text-link"
              href="/how-it-works"
              onClick={showGuide}
            >
              Follow the walkthrough <ArrowUpRight size={16} />
            </a>
          </div>
        </div>
        <aside className="about-at-a-glance" aria-label="Product at a glance">
          <h2>Evidence before action.</h2>
          <dl>
            <div>
              <dt>Bring together</dt>
              <dd>Linux, Windows and network observations.</dd>
            </div>
            <div>
              <dt>Understand</dt>
              <dd>The rule, the matched events and the case context.</dd>
            </div>
            <div>
              <dt>Leave a record</dt>
              <dd>Analyst notes, checklists and hashed evidence snapshots.</dd>
            </div>
          </dl>
          <p>
            Experimental software. Public data is synthetic. Response actions
            are simulations.
          </p>
        </aside>
      </header>

      <div className="about-layout">
        <nav className="about-contents" aria-label="On this page">
          <strong>On this page</strong>
          <ol>
            {sections.map(([id, title]) => (
              <li key={id}>
                <a href={`#${id}`}>{title}</a>
              </li>
            ))}
          </ol>
          <a className="about-source-link" href={repository}>
            View source code <ArrowUpRight size={15} />
          </a>
        </nav>

        <div className="about-reading">
          <section id="purpose" aria-labelledby="purpose-title">
            <h2 id="purpose-title">Built to make reasoning visible</h2>
            <p>
              Security logs describe observations; an alert is a rule’s
              interpretation of those observations. SentinelForge keeps that
              distinction visible, so you can trace a signal back to its source
              and explain the decision you make about it.
            </p>
            <dl className="about-role-list">
              <div>
                <dt>SOC analysts & learners</dt>
                <dd>
                  Practice triage, move from an alert into its investigation and
                  document the evidence that supports or contradicts a
                  hypothesis.
                </dd>
              </div>
              <div>
                <dt>Detection engineers</dt>
                <dd>
                  Read rule conditions and telemetry requirements, replay known
                  inputs and examine false positives and coverage gaps.
                </dd>
              </div>
              <div>
                <dt>Technical reviewers</dt>
                <dd>
                  Inspect a working defensive engineering project with explicit
                  boundaries, reproducible evaluations and source code.
                </dd>
              </div>
            </dl>
          </section>

          <section id="workflow" aria-labelledby="workflow-title">
            <h2 id="workflow-title">From event to evidence</h2>
            <p>
              These four objects connect the workflow. Each answers a different
              investigation question.
            </p>
            <ol className="about-evidence-path">
              <li>
                <div>
                  <strong>Event</strong>
                  <span>What was observed?</span>
                </div>
                <p>
                  A source adapter validates supported fields and normalizes
                  timestamps to UTC, retaining source attribution and raw input.
                  Exact replays are deduplicated.
                </p>
              </li>
              <li>
                <div>
                  <strong>Alert</strong>
                  <span>Why did it match?</span>
                </div>
                <p>
                  A matching rule records its rationale, severity, source event
                  references and MITRE ATT&CK mapping. A match is a lead to
                  investigate, not proof of malicious intent.
                </p>
              </li>
              <li>
                <div>
                  <strong>Case</strong>
                  <span>How does it connect?</span>
                </div>
                <p>
                  Related alerts are grouped by shared host or non-generic user
                  within a 15-minute window. Review the timeline, assign the
                  case, update its status and record notes and checklist
                  decisions.
                </p>
              </li>
              <li>
                <div>
                  <strong>Evidence</strong>
                  <span>What can be reviewed?</span>
                </div>
                <p>
                  An authorized analyst can preserve a JSON snapshot and export
                  it with a SHA-256 digest. The digest supports consistency
                  checking against the saved snapshot; it does not establish
                  authorship or an independent chain of custody.
                </p>
              </li>
            </ol>
          </section>

          <section id="sources" aria-labelledby="sources-title">
            <h2 id="sources-title">Supported telemetry</h2>
            <p>
              Six adapters translate supported inputs into a common model.
              Importing is explicit: SentinelForge does not install endpoint
              agents, tail log files or automatically discover your environment.
            </p>
            <div className="about-source-list">
              {sources.map((source) => (
                <details key={source.name}>
                  <summary>
                    <span>
                      <strong>{source.name}</strong>
                      <small>{source.format}</small>
                    </span>
                    <ChevronDown size={18} aria-hidden="true" />
                  </summary>
                  <div className="about-source-detail">
                    <p>{source.detail}</p>
                    <p>
                      <strong>Input boundary.</strong> {source.limit}
                    </p>
                  </div>
                </details>
              ))}
            </div>
            <GlassButton
              className="about-text-link"
              onClick={() => navigate("telemetry")}
            >
              Inspect telemetry <ArrowRight size={16} />
            </GlassButton>
          </section>

          <section id="detections" aria-labelledby="detections-title">
            <h2 id="detections-title">Narrow, explainable detections</h2>
            <p>
              Nine experimental rules cover specific observable behaviors. The
              rule library exposes each condition, required telemetry, known
              false-positive possibilities and validation notes. ATT&CK
              references describe a limited subset, not full technique coverage.
            </p>
            <div className="about-detection-groups">
              <div>
                <h3>Authentication & privilege</h3>
                <p>
                  Repeated SSH failures, a useradd command requesting UID zero
                  and sudo launching a root shell.
                </p>
              </div>
              <div>
                <h3>Execution & persistence</h3>
                <p>
                  Supported encoded or inline PowerShell patterns, shell
                  commands using /dev/tcp/, scheduled task creation and
                  PowerShell file execution with qualifying supporting context.
                </p>
              </div>
              <div>
                <h3>Network observations</h3>
                <p>
                  Public-IP connections on selected uncommon ports, or a bound
                  collector’s port-443 observation associated with an active,
                  versioned offline IP indicator.
                </p>
              </div>
            </div>
            <details className="about-context-detail">
              <summary>
                <span>How context changes a decision</span>
                <ChevronDown size={18} aria-hidden="true" />
              </summary>
              <p>
                Administrator-managed APIs bind configured ingestion identities
                to a source, sensor and host. Versioned indicators carry scope,
                validity windows and provenance. Exact-action approvals can
                suppress the encoded-PowerShell or scheduled-task rule only
                within a bounded window, for the specified user and command
                digest, with one use and an audit record.
              </p>
              <p>
                An event cannot approve itself. These controls express operator
                authorization; they do not cryptographically attest the
                collector or independently verify its observations. No external
                reputation lookup or automatic historical reanalysis runs in the
                background.
              </p>
            </details>
            <div className="about-research-note">
              <h3>Measured limits remain visible</h3>
              <p>
                The current synthetic holdout evaluation does not meet the
                requested detection targets. Its 16 scenarios produced 83.33%
                precision, 62.50% recall, 75.00% accuracy and a 12.50%
                false-positive rate. The small, co-designed corpus is not
                independent operational evidence.
              </p>
              <a href={evidenceReport}>
                Read the evaluation and uncertainty <ArrowUpRight size={16} />
              </a>
            </div>
            <GlassButton
              className="about-text-link"
              onClick={() => navigate("rules")}
            >
              Read detection rules <ArrowRight size={16} />
            </GlassButton>
          </section>

          <section id="modes" aria-labelledby="modes-title">
            <h2 id="modes-title">Choose the right workspace</h2>
            <p>
              The same interface supports three distinct access models. Use this
              comparison to understand where data lives and which actions are
              available; selecting a mode here does not change your workspace.
            </p>
            <div className="about-mode-comparison">
              <label htmlFor="about-mode">Compare workspace mode</label>
              <select
                id="about-mode"
                value={mode}
                onChange={(event) => setMode(event.target.value as Mode)}
                aria-controls="about-mode-details"
              >
                {Object.entries(modes).map(([key, value]) => (
                  <option key={key} value={key}>
                    {value.name}
                  </option>
                ))}
              </select>
              <div
                id="about-mode-details"
                aria-live="polite"
                aria-atomic="true"
              >
                <h3>{currentMode.name}</h3>
                <p>{currentMode.description}</p>
                <dl>
                  {currentMode.facts.map(([label, value]) => (
                    <div key={label}>
                      <dt>{label}</dt>
                      <dd>{value}</dd>
                    </div>
                  ))}
                </dl>
                <p className="about-mode-note">{currentMode.note}</p>
              </div>
            </div>
          </section>

          <section id="trust" aria-labelledby="trust-title">
            <h2 id="trust-title">Know the trust boundary</h2>
            <dl className="about-trust-list">
              <div>
                <dt>An analyst stays in control</dt>
                <dd>
                  There is no AI verdict or autonomous remediation. Response
                  requests are simulations only: they do not isolate a device,
                  terminate a process or execute a host command. In
                  authenticated mode, a different administrator must approve the
                  simulation.
                </dd>
              </div>
              <div>
                <dt>Evidence has a defined limit</dt>
                <dd>
                  Raw evidence and exports require the appropriate server-side
                  role. Snapshots and audit records have no edit/delete API, but
                  a database administrator can alter both stored content and its
                  hash. Signed manifests and tamper-proof storage are not
                  included.
                </dd>
              </div>
              <div>
                <dt>Coverage depends on observation</dt>
                <dd>
                  Unobserved script content, ordinary-looking encrypted
                  channels, missing context and unsupported formats can evade
                  these rules. Legitimate administrative activity can also
                  trigger alerts. Investigate both possibilities.
                </dd>
              </div>
              <div>
                <dt>A lab needs deployment controls</dt>
                <dd>
                  There is no built-in tenant isolation, automatic retention or
                  production service guarantee. Real telemetry may contain
                  sensitive identities and command lines. Broader use requires
                  access controls, retention planning, backups and a deployment
                  security review.
                </dd>
              </div>
            </dl>
            <a
              className="about-text-link"
              href={`${repository}/blob/main/SECURITY.md`}
            >
              Read the security boundary <ArrowUpRight size={16} />
            </a>
          </section>

          <section
            id="start"
            className="about-next"
            aria-labelledby="start-title"
          >
            <h2 id="start-title">See the reasoning for yourself</h2>
            <p>
              Start with the alert queue, open a case and follow its timeline.
              Use the walkthrough when you want a guided path through the whole
              investigation.
            </p>
            <div className="about-actions">
              <GlassButton
                className="primary"
                onClick={() => navigate("alerts")}
              >
                Review alert queue <ArrowRight size={17} />
              </GlassButton>
              <a
                className="about-text-link"
                href="/how-it-works"
                onClick={showGuide}
              >
                How It Works <ArrowUpRight size={16} />
              </a>
            </div>
          </section>
        </div>
      </div>
      <footer className="about-footer">
        <strong>SentinelForge</strong>
        <span>Understand the observation. Explain the decision.</span>
        <a href="#main-content">Back to top</a>
      </footer>
    </main>
  );
}
