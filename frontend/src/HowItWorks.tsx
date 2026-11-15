import { useState, type KeyboardEvent } from "react";
import {
  ArrowRight,
  ArrowUpRight,
  Check,
  ChevronDown,
  Database,
  FileCheck2,
  Fingerprint,
  FolderOpen,
  GitBranch,
  Layers3,
  LockKeyhole,
  Radar,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { GlassButton, GlassPanel } from "./components/glass";
import type { View } from "./types";
import "./guide.css";

const repo = "https://github.com/aashleshshet/SentinelFORGE";
const features = [
  {
    icon: Database,
    title: "Bring the evidence together",
    text: "Normalize Linux authentication, auditd JSON, Sysmon JSON, Wazuh, Zeek and synthetic JSON into a shared event model.",
    view: "telemetry",
  },
  {
    icon: Radar,
    title: "Understand every signal",
    text: "Seven experimental rules identify specific behaviors. Each alert carries its rationale, source events and MITRE ATT&CK references.",
    view: "rules",
  },
  {
    icon: FolderOpen,
    title: "Follow an investigation",
    text: "Related alerts form cases through shared host or user context within a 15-minute window. Inspect the timeline before deciding what to do.",
    view: "cases",
  },
  {
    icon: FileCheck2,
    title: "Preserve your findings",
    text: "Local analysts can add notes, work through checklists and preserve JSON evidence snapshots with SHA-256 integrity digests.",
    view: "cases",
  },
] as const;
const steps: {
  title: string;
  instruction: string;
  local?: string;
  outcome: string;
  tip: string;
  view: View;
  action: string;
  path: string[];
}[] = [
  {
    title: "Choose your workspace",
    instruction:
      "Open the public demo to explore a fixed synthetic dataset. No account or sign-in is needed.",
    local:
      "Follow the repository's local setup, then run python scripts/run_local.py. The token-free workspace binds to your computer's loopback interface.",
    outcome:
      "The overview shows the scope of your dataset and totals for events, alerts, cases and rules.",
    tip: "Public demo controls that change data are intentionally unavailable. Use the local workspace to make changes.",
    view: "overview",
    action: "Open overview",
    path: ["Workspace", "Overview", "Dataset scope"],
  },
  {
    title: "Check the environment",
    instruction:
      "Read the Synthetic demo notice and review the six telemetry sources. This is a fixed snapshot, not a live feed.",
    local:
      "Confirm API connected in the header. Token-free local mode is for loopback use; deployments with authentication use viewer, analyst, admin and ingest identities configured by the operator.",
    outcome:
      "You know which mode you are using, which sources have data, and what actions your role permits.",
    tip: "A connection warning means displayed data may be stale. Check the API process and use Refresh to retry.",
    view: "overview",
    action: "Check source coverage",
    path: ["API connection", "Source counts", "Workspace scope"],
  },
  {
    title: "Inspect or import telemetry",
    instruction:
      "Open Telemetry and filter by source. Expand a record to inspect its normalized fields and permitted raw evidence.",
    local:
      "As an admin, use Import JSON in Telemetry to upload a JSON batch of event envelopes, each with its source, sensor and payload. Start with data/demo.json and review accepted, rejected and duplicate counts. Ingest identities can send batches through the API.",
    outcome:
      "Events retain their source, host and UTC timestamp. Duplicate source records are not ingested twice.",
    tip: "Use JSON exports for Sysmon and assembled auditd records. Native EVTX and arbitrary log formats are not supported. Check each envelope’s source field and the 1 MiB upload limit.",
    view: "telemetry",
    action: "Explore telemetry",
    path: ["Supported log", "Source adapter", "Normalized event"],
  },
  {
    title: "Review detection results",
    instruction:
      "Open Alert queue. Filter by severity, technique or text, then read the detection name and affected host.",
    local:
      "Detection runs during ingestion; there is no separate analysis button. An admin can also use Replay demo to run bundled synthetic events through the same pipeline.",
    outcome:
      "Matching events produce explainable alerts. The seven rules cover narrow behaviors rather than complete ATT&CK techniques.",
    tip: "No alerts can mean no rule matched. Check Telemetry and Detection rules before assuming ingestion failed. A signal alone does not establish malicious intent.",
    view: "alerts",
    action: "Review alert queue",
    path: ["Normalized event", "Rule condition", "Alert + rationale"],
  },
  {
    title: "Investigate the context",
    instruction:
      "Select an alert title to open its case. Read the timeline, related alerts, entities and correlation explanation.",
    local:
      "Assign the case, update its status and record what you observed. Validate the signal against its source evidence before escalating.",
    outcome:
      "A case connects related observations and records analyst decisions in one place.",
    tip: "Correlation is a heuristic. Review the host/user relationship and timestamps; a shared case is not proof that events belong to one attack.",
    view: "cases",
    action: "Open investigations",
    path: ["Alert", "Related activity", "Case timeline"],
  },
  {
    title: "Validate the evidence",
    instruction:
      "Inspect event details and the alert's rule rationale. Use the ATT&CK reference to understand the behavior being mapped.",
    local:
      "Use the case checklist and notes to document your reasoning. IP enrichment checks only the local IOC store; it makes no external reputation requests.",
    outcome:
      "You can trace the finding to observed fields instead of relying on a severity label alone.",
    tip: "Risk is a heuristic score, not a probability. No AI analyst or external threat-intelligence service is connected.",
    view: "rules",
    action: "Read rule logic",
    path: ["Source evidence", "Rule rationale", "Analyst judgment"],
  },
  {
    title: "Preserve and export",
    instruction:
      "Open a case and select Export on its existing evidence snapshot to download JSON with a SHA-256 digest.",
    local:
      "Select Preserve evidence first to capture the current case, alerts, events and notes. Export that snapshot for review outside the workspace.",
    outcome:
      "You have a portable evidence record and a digest for detecting changes to the serialized snapshot.",
    tip: "A digest is not a digital signature or a legal chain-of-custody guarantee. New notes require a new snapshot; previous snapshots remain unchanged.",
    view: "cases",
    action: "Find an evidence export",
    path: ["Case state", "Snapshot + SHA-256", "JSON export"],
  },
  {
    title: "Practice a response",
    instruction:
      "Review the response section in a case to understand the approval workflow. The public demo cannot submit requests.",
    local:
      "An analyst requests a host-isolation simulation with a reason. A different administrator approves it. Review the result and audit trail.",
    outcome:
      "You can practice separation of duties. No endpoint is isolated and no command is executed.",
    tip: "The requester cannot approve their own request. Token-free local mode has one identity; use separate configured identities to complete the two-person exercise.",
    view: "cases",
    action: "Review a case",
    path: ["Analyst request", "Different admin", "Simulation record"],
  },
];
const architecture = [
  {
    icon: Terminal,
    title: "Sources",
    detail:
      "Six adapters accept supported text and JSON records. Inputs are bounded and normalized; the public deployment loads only a bundled synthetic snapshot.",
    code: "Linux auth · auditd · Sysmon · Wazuh · Zeek · JSON",
  },
  {
    icon: Layers3,
    title: "Ingestion",
    detail:
      "FastAPI validates requests and checks the server-side role. Adapters normalize timestamps, hosts, identities and event fields. Fingerprints prevent duplicate ingestion.",
    code: "Request validation → normalization → deduplication",
  },
  {
    icon: Radar,
    title: "Detection",
    detail:
      "Seven Python detection rules evaluate specific event behaviors. YAML metadata supplies severity, limitations and pinned ATT&CK technique references.",
    code: "Event fields → rule condition → alert with evidence",
  },
  {
    icon: GitBranch,
    title: "Investigation",
    detail:
      "A 15-minute correlation window groups alerts through a shared host or non-generic user. SQLAlchemy stores cases, notes, checklists and audit records in SQLite locally or PostgreSQL in Docker.",
    code: "Related alerts → case → analyst decisions",
  },
  {
    icon: Fingerprint,
    title: "Evidence",
    detail:
      "The API creates a serialized case snapshot and SHA-256 digest. React presents the timeline and downloads JSON. The public demo uses an isolated, query-only SQLite database.",
    code: "Case snapshot → integrity digest → JSON download",
  },
];
const faqs = [
  [
    "Is this a live security monitoring service?",
    "No. The public site contains a fixed synthetic dataset. A local instance processes supported logs that you upload or send to the ingestion API. It does not include a deployed endpoint agent or a live managed SOC.",
  ],
  [
    "Why can’t I upload data or change a case here?",
    "The public demo is intentionally read-only. The API rejects mutations even if a client attempts them directly. Run SentinelForge locally to import your own telemetry, add notes and preserve new evidence.",
  ],
  [
    "Does SentinelForge use AI or external reputation services?",
    "No. Detections are explicit rules. IP enrichment uses the local IOC store only. No AI-assisted investigation, VirusTotal or AbuseIPDB integration is implemented.",
  ],
  [
    "Why do two alerts appear in one case?",
    "Correlation looks for a shared host or non-generic user within a 15-minute window. Inspect the correlation explanation and timeline; these relationships are investigative leads, not a verified attack chain.",
  ],
  [
    "Why are my imported events missing?",
    "Check the selected source format and the accepted/rejected counts after import. Repeated source records are deduplicated. Clear search and source filters, then Refresh. Only authorized roles can ingest; native EVTX files are not supported.",
  ],
  [
    "Can SentinelForge isolate a real host?",
    "No. The response workflow records a host-isolation simulation after a different administrator approves it. It performs no endpoint action and executes no shell commands.",
  ],
  [
    "Where is my data stored?",
    "The local runner uses SQLite; the Docker stack uses PostgreSQL. The public demo creates an isolated in-memory SQLite database from bundled synthetic data. There is no implemented automatic retention policy. Operators are responsible for access, backups and deletion.",
  ],
];

export default function HowItWorks({
  navigate,
}: {
  navigate: (view: View) => void;
}) {
  const [step, setStep] = useState(0);
  const [local, setLocal] = useState(false);
  const [node, setNode] = useState<number | null>(0);
  const current = steps[step];
  function selectStep(index: number) {
    setStep(index);
    document.getElementById(`step-${index}`)?.focus();
  }
  function tabKeys(event: KeyboardEvent, index: number) {
    const next =
      event.key === "ArrowRight" || event.key === "ArrowDown"
        ? (index + 1) % steps.length
        : event.key === "ArrowLeft" || event.key === "ArrowUp"
          ? (index + steps.length - 1) % steps.length
          : event.key === "Home"
            ? 0
            : event.key === "End"
              ? steps.length - 1
              : null;
    if (next !== null) {
      event.preventDefault();
      selectStep(next);
    }
  }
  return (
    <main id="main-content" className="guide" tabIndex={-1}>
      <section className="guide-hero" aria-labelledby="guide-title">
        <div className="hero-copy">
          <p className="eyebrow">
            <span /> THE SENTINELFORGE FIELD GUIDE
          </p>
          <h1 id="guide-title">
            Understand SentinelForge. <br />
            <span>Master Your Security Workflow.</span>
          </h1>
          <p className="hero-intro">
            Turn scattered security events into an investigation you can
            explain. Follow the signal, examine the evidence, and document every
            decision.
          </p>
          <div className="guide-actions">
            <GlassButton
              className="primary"
              onClick={() => navigate("overview")}
            >
              Explore the workspace <ArrowRight size={17} />
            </GlassButton>
            <a className="secondary" href="#workflow">
              Walk through the workflow
            </a>
          </div>
          <p className="hero-caption">
            Public demo · Synthetic evidence · No sign-in
          </p>
        </div>
        <div
          className="hero-diagram"
          aria-label="Illustrated workflow: telemetry becomes signals, investigations and evidence. Not live data."
        >
          <div className="diagram-top">
            <span className="eyebrow">FROM SIGNAL TO EVIDENCE</span>
            <span className="diagram-label">WORKFLOW ILLUSTRATION</span>
          </div>
          <div className="diagram-source">
            <Database size={20} />
            <span>
              Security telemetry<small>Six supported source adapters</small>
            </span>
          </div>
          <div className="diagram-connector" />
          <div className="diagram-core">
            <div className="core-symbol">
              <ShieldCheck size={38} strokeWidth={1.3} />
            </div>
            <strong>SentinelForge</strong>
            <span>Normalize. Detect. Investigate.</span>
          </div>
          <div className="diagram-connector" />
          <div className="diagram-output">
            <span>
              <Radar size={18} /> Explainable alerts
            </span>
            <ArrowRight size={16} />
            <span>
              <FileCheck2 size={18} /> Preserved evidence
            </span>
          </div>
          <div className="diagram-bottom">
            <Check size={14} /> Every finding links back to its source.
          </div>
        </div>
      </section>

      <section className="guide-intro" aria-labelledby="purpose-title">
        <div>
          <p className="eyebrow">01 / THE PURPOSE</p>
          <h2 id="purpose-title">
            A clearer path through
            <br />
            security evidence.
          </h2>
        </div>
        <div>
          <p>
            SentinelForge is a defensive engineering lab for analysts, detection
            engineers and learners. It brings supported logs, explainable rules
            and case evidence into one workspace.
          </p>
          <p>
            Use it to practice triage, test narrow detection behaviors and
            record why a finding matters. The public demo lets you inspect the
            whole chain; a local instance lets you work with your own supported
            data.
          </p>
        </div>
      </section>

      <section aria-labelledby="features-title" className="guide-section">
        <div className="section-heading">
          <div>
            <p className="eyebrow">02 / THE TOOLKIT</p>
            <h2 id="features-title">Built around the investigation.</h2>
          </div>
          <span className="section-note">
            Implemented capabilities. Visible evidence.
          </span>
        </div>
        <div className="feature-grid">
          {features.map(({ icon: Icon, title, text, view }) => (
            <GlassPanel className="feature-card" key={title}>
              <Icon size={23} strokeWidth={1.5} />
              <h3>{title}</h3>
              <p>{text}</p>
              <GlassButton
                className="text-button"
                onClick={() => navigate(view)}
              >
                Explore {view === "cases" ? "investigations" : view}{" "}
                <ArrowUpRight size={16} />
              </GlassButton>
            </GlassPanel>
          ))}
        </div>
      </section>

      <section
        id="workflow"
        className="guide-section"
        aria-labelledby="workflow-title"
      >
        <div className="section-heading">
          <div>
            <p className="eyebrow">03 / YOUR FIRST INVESTIGATION</p>
            <h2 id="workflow-title">One workflow. Every step explained.</h2>
          </div>
          <div className="mode-switch" aria-label="Guide workspace mode">
            <GlassButton aria-pressed={!local} onClick={() => setLocal(false)}>
              Public demo
            </GlassButton>
            <GlassButton aria-pressed={local} onClick={() => setLocal(true)}>
              Local workspace
            </GlassButton>
          </div>
        </div>
        <div className="workflow-layout">
          <div
            className="step-tabs"
            role="tablist"
            aria-label="Investigation steps"
            aria-orientation="vertical"
          >
            {steps.map((item, index) => (
              <GlassButton
                key={item.title}
                id={`step-${index}`}
                role="tab"
                aria-selected={step === index}
                aria-controls={`step-panel-${index}`}
                tabIndex={step === index ? 0 : -1}
                onClick={() => setStep(index)}
                onKeyDown={(event) => tabKeys(event, index)}
              >
                <span>{String(index + 1).padStart(2, "0")}</span>
                {item.title}
                <ArrowRight size={15} />
              </GlassButton>
            ))}
          </div>
          <GlassPanel
            key={step}
            className="step-panel"
            role="tabpanel"
            id={`step-panel-${step}`}
            aria-labelledby={`step-${step}`}
            tabIndex={0}
          >
            <span className="step-counter">
              STEP {String(step + 1).padStart(2, "0")} / 08
            </span>
            <h3>{current.title}</h3>
            <p>{local ? current.local : current.instruction}</p>
            <ol className="step-path" aria-label="Step flow">
              {current.path.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ol>
            <div className="expected">
              <Check size={18} />
              <div>
                <h4>What to expect</h4>
                <p>{current.outcome}</p>
              </div>
            </div>
            <details className="guide-tip">
              <summary>
                Helpful to know <ChevronDown size={16} />
              </summary>
              <p>{current.tip}</p>
            </details>
            <div className="step-actions">
              <GlassButton
                className="primary"
                onClick={() => navigate(current.view)}
              >
                {current.action}
                <ArrowUpRight size={16} />
              </GlassButton>
              {step < steps.length - 1 && (
                <GlassButton
                  className="text-button"
                  onClick={() => selectStep(step + 1)}
                >
                  Next step
                  <ArrowRight size={16} />
                </GlassButton>
              )}
            </div>
          </GlassPanel>
        </div>
      </section>

      <section className="guide-section" aria-labelledby="architecture-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">04 / UNDER THE SURFACE</p>
            <h2 id="architecture-title">Trace the system, end to end.</h2>
          </div>
          <p className="section-note">
            Select a stage to see what actually happens.
          </p>
        </div>
        <div className="architecture">
          <ol className="architecture-nodes">
            {architecture.map(({ icon: Icon, title }, index) => (
              <li key={title}>
                <GlassButton
                  aria-expanded={node === index}
                  aria-controls={`architecture-${index}`}
                  onClick={() => setNode(node === index ? null : index)}
                >
                  <span className="architecture-number">0{index + 1}</span>
                  <Icon size={25} strokeWidth={1.4} />
                  <strong>{title}</strong>
                  <ChevronDown size={16} />
                </GlassButton>
              </li>
            ))}
          </ol>
          {architecture.map((item, index) => (
            <div
              key={item.title}
              id={`architecture-${index}`}
              hidden={node !== index}
              className="architecture-detail"
            >
              <span className="eyebrow">{item.title.toUpperCase()}</span>
              <p>{item.detail}</p>
              <p className="mono">{item.code}</p>
            </div>
          ))}
        </div>
      </section>

      <section
        className="guide-section security-section"
        aria-labelledby="privacy-title"
      >
        <div>
          <LockKeyhole size={28} strokeWidth={1.4} />
          <p className="eyebrow">05 / SECURITY & PRIVACY</p>
          <h2 id="privacy-title">
            Know the boundaries
            <br />
            of your workspace.
          </h2>
          <a
            href={`${repo}/blob/main/SECURITY.md`}
            target="_blank"
            rel="noreferrer"
          >
            Read the security model <ArrowUpRight size={15} />
          </a>
        </div>
        <div className="security-facts">
          <article>
            <h3>Public means synthetic and read-only.</h3>
            <p>
              The public API rejects data-changing requests and loads an
              isolated synthetic snapshot. No operator credentials or private
              telemetry are needed.
            </p>
          </article>
          <article>
            <h3>Permissions are enforced by the API.</h3>
            <p>
              Authenticated workspaces separate viewer, analyst, admin and
              ingest roles. Browser bearer tokens remain in memory. Token-free
              local mode is restricted to loopback requests.
            </p>
          </article>
          <article>
            <h3>Evidence integrity has a defined scope.</h3>
            <p>
              Snapshots include SHA-256 digests. Response actions are
              simulations requiring a different administrator. There are no
              compliance certifications or automatic retention guarantees.
            </p>
          </article>
        </div>
      </section>

      <section
        className="guide-section faq-section"
        aria-labelledby="faq-title"
      >
        <div>
          <p className="eyebrow">06 / A FEW MORE ANSWERS</p>
          <h2 id="faq-title">Before you dive in.</h2>
        </div>
        <div className="faq-list">
          {faqs.map(([question, answer]) => (
            <details key={question}>
              <summary>
                {question}
                <ChevronDown size={18} />
              </summary>
              <p>{answer}</p>
            </details>
          ))}
        </div>
      </section>

      <GlassPanel className="guide-cta">
        <div>
          <p className="eyebrow">EVIDENCE BEFORE ACTION.</p>
          <h2>
            Your next investigation
            <br />
            starts with a closer look.
          </h2>
          <p>Explore the synthetic dataset, or run your own local workspace.</p>
        </div>
        <div className="guide-actions">
          <GlassButton className="primary" onClick={() => navigate("overview")}>
            Open SentinelForge
            <ArrowRight size={17} />
          </GlassButton>
          <a
            className="secondary"
            href={`${repo}#run-locally--no-token-or-sign-in`}
            target="_blank"
            rel="noreferrer"
          >
            Run locally
            <ArrowUpRight size={17} />
          </a>
        </div>
      </GlassPanel>
      <footer className="guide-footer">
        <span>SentinelForge · Defensive engineering lab</span>
        <a href={repo} target="_blank" rel="noreferrer">
          View source on GitHub <ArrowUpRight size={14} />
        </a>
      </footer>
    </main>
  );
}
