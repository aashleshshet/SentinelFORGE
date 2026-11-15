import React, {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  BookOpen,
  Check,
  ChevronRight,
  CircleAlert,
  Database,
  FileCheck2,
  FolderOpen,
  LayoutDashboard,
  LogOut,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  ArrowUpRight,
  Network,
  Play,
  RefreshCw,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Upload,
  X,
} from "lucide-react";
import "@fontsource/public-sans/400.css";
import "@fontsource/public-sans/500.css";
import "@fontsource/public-sans/600.css";
import "@fontsource/public-sans/700.css";
import "@fontsource/ibm-plex-mono/400.css";
import "./style.css";
import "./modern.css";
import {
  GlassButton,
  GlassInput,
  GlassNavbar,
  GlassSidebar,
  GlassTable,
  GlassModal,
} from "./components/glass";
const HowItWorks = lazy(() => import("./HowItWorks"));
function initialView(): View {
  const value = new URLSearchParams(window.location.search).get("view");
  return value &&
    ["overview", "alerts", "cases", "telemetry", "rules"].includes(value)
    ? (value as View)
    : "overview";
}
import type {
  Alert,
  CaseDetail,
  Event,
  Incident,
  Page,
  Principal,
  ReplayResult,
  Rule,
  Stats,
  View,
} from "./types";

const labels: Record<View, string> = {
  overview: "Overview",
  alerts: "Alert queue",
  cases: "Investigations",
  telemetry: "Telemetry",
  rules: "Detection rules",
};
const sourceNames: Record<string, string> = {
  linux_auth: "Linux authentication",
  auditd: "Linux auditd",
  sysmon: "Windows Sysmon",
  wazuh: "Wazuh alerts",
  zeek: "Zeek network",
  synthetic: "JSON replay",
};
const icons = {
  overview: LayoutDashboard,
  alerts: CircleAlert,
  cases: FolderOpen,
  telemetry: Database,
  rules: ShieldCheck,
};
const date = (v: string) =>
  new Intl.DateTimeFormat("en-GB", {
    timeZone: "UTC",
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(v));
const short = (id: string) => id.slice(0, 8);
const number = (v: number) => v.toLocaleString("en-GB");
function Mark() {
  return (
    <svg
      width="27"
      height="31"
      viewBox="0 0 27 31"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M3 4 13.5 1 24 4v12c0 6-10.5 13-10.5 13S3 22 3 16V4Z"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <path
        d="m8 11 5.5-3 5.5 3-5.5 3-5.5-3Zm0 5 5.5 3 5.5-3m-11 5 5.5 3 5.5-3"
        stroke="currentColor"
        strokeWidth="1.4"
      />
    </svg>
  );
}
function Severity({ level }: { level: string }) {
  return (
    <span className={`severity ${level}`}>
      <span />
      {level}
    </span>
  );
}
function Empty({ children }: { children: React.ReactNode }) {
  return <p className="empty">{children}</p>;
}
function App() {
  const [token, setToken] = useState("");
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [booting, setBooting] = useState(true);
  useEffect(() => {
    let active = true;
    fetch("/api/me")
      .then(async (response) => {
        if (response.ok && active) setPrincipal(await response.json());
      })
      .catch(() => {})
      .finally(() => {
        if (active) setBooting(false);
      });
    return () => {
      active = false;
    };
  }, []);
  const [view, setView] = useState<View>(initialView);
  const [guide, setGuide] = useState(
    window.location.pathname.replace(/\/$/, "") === "/how-it-works",
  );
  const [collapsed, setCollapsed] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  useEffect(() => {
    const onPop = () => {
      setGuide(window.location.pathname.replace(/\/$/, "") === "/how-it-works");
      setView(initialView());
      setSelectedId(null);
      setDetail(null);
      setQuery("");
      setPage(0);
      setSeverity("");
      setTechnique("");
      setSource("");
      setStatus("");
      setMenuOpen(false);
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);
  useEffect(() => {
    document.title = guide
      ? "How It Works · SentinelForge"
      : `${labels[view]} · SentinelForge`;
    document
      .querySelector('meta[name="description"]')
      ?.setAttribute(
        "content",
        guide
          ? "Learn SentinelForge: security log ingestion, explainable detections, incident investigation and evidence exports. An interactive guide to the real workflow."
          : "SentinelForge security operations and evidence-led investigation",
      );
  }, [guide, view]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [alerts, setAlerts] = useState<Page<Alert>>({ total: 0, items: [] });
  const [cases, setCases] = useState<Page<Incident>>({ total: 0, items: [] });
  const [events, setEvents] = useState<Page<Event>>({ total: 0, items: [] });
  const [rules, setRules] = useState<Rule[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [source, setSource] = useState("");
  const [technique, setTechnique] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const [reason, setReason] = useState("");
  const [ioc, setIoc] = useState("");
  const file = useRef<HTMLInputElement>(null);
  const generation = useRef(0);
  const canEdit = principal?.role !== "viewer";
  const api = useCallback(
    async <T,>(path: string, method = "GET", body?: unknown): Promise<T> => {
      const response = await fetch("/api" + path, {
        method,
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (!response.ok) {
        const result = await response
          .json()
          .catch(() => ({ detail: "Server unavailable" }));
        throw new Error(
          typeof result.detail === "string"
            ? result.detail
            : "The request contains invalid fields. Check your input.",
        );
      }
      return response.json() as Promise<T>;
    },
    [token],
  );
  const refresh = useCallback(async () => {
    const current = ++generation.current;
    const filter = new URLSearchParams({
      limit: "50",
      offset: String(page * 50),
      q: query,
    });
    const af = new URLSearchParams(filter);
    if (severity) af.set("severity", severity);
    if (technique) af.set("technique", technique);
    const ef = new URLSearchParams(filter);
    if (source) ef.set("source", source);
    const cf = new URLSearchParams(filter);
    if (status) cf.set("status", status);
    try {
      const [s, a, c, e, r, d] = await Promise.all([
        api<Stats>("/stats"),
        !selectedId && ["overview", "alerts"].includes(view)
          ? api<Page<Alert>>("/alerts?" + (view === "alerts" ? af : "limit=4"))
          : Promise.resolve(null),
        !selectedId && view === "cases"
          ? api<Page<Incident>>("/cases?" + cf)
          : Promise.resolve(null),
        !selectedId && view === "telemetry"
          ? api<Page<Event>>("/events?" + ef)
          : Promise.resolve(null),
        !selectedId && ["overview", "rules"].includes(view)
          ? api<{ items: Rule[] }>("/rules")
          : Promise.resolve(null),
        selectedId
          ? api<CaseDetail>("/cases/" + selectedId)
          : Promise.resolve(null),
      ]);
      if (generation.current !== current) return;
      setStats(s);
      if (a) setAlerts(a);
      if (c) setCases(c);
      if (e) setEvents(e);
      if (r) setRules(r.items);
      setDetail(d);
      setError("");
    } catch (e) {
      if (generation.current === current)
        setError((e as Error).message + " Use Refresh to retry.");
    }
  }, [api, page, query, severity, technique, source, status, view, selectedId]);
  useEffect(() => {
    if (!principal || guide) return;
    const delay = setTimeout(refresh, 180);
    const poll = principal.demo ? undefined : setInterval(refresh, 10000);
    return () => {
      clearTimeout(delay);
      clearInterval(poll);
      generation.current++;
    };
  }, [principal, refresh, guide]);
  async function action(work: () => Promise<unknown>, success?: string) {
    setBusy(true);
    setError("");
    try {
      await work();
      if (success) setMessage(success);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  function navigate(next: View) {
    window.history.pushState(
      null,
      "",
      next === "overview" ? "/" : `/?view=${next}`,
    );
    setGuide(false);
    setMenuOpen(false);
    window.scrollTo(0, 0);
    requestAnimationFrame(() =>
      document.getElementById("main-content")?.focus(),
    );
    setView(next);
    setSelectedId(null);
    setDetail(null);
    setQuery("");
    setPage(0);
    setTechnique("");
    setSeverity("");
    setSource("");
    setStatus("");
    setMessage("");
  }
  function showGuide(event?: React.MouseEvent<HTMLAnchorElement>) {
    if (
      event &&
      (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey)
    )
      return;
    event?.preventDefault();
    window.history.pushState(null, "", "/how-it-works");
    setGuide(true);
    setMenuOpen(false);
    window.scrollTo(0, 0);
    requestAnimationFrame(() =>
      document.getElementById("main-content")?.focus(),
    );
  }
  function investigate(id: string) {
    setSelectedId(id);
    setDetail(null);
    setIoc("");
    setNote("");
    setReason("");
    setMessage("");
  }
  async function replay() {
    await action(async () => {
      const r = await api<ReplayResult>("/demo", "POST");
      setMessage(
        `Demo replay: ${r.accepted} accepted, ${r.duplicates} duplicates, ${r.rejected} rejected; ${r.alerts_created} new alerts.`,
      );
    });
  }
  async function download(evidenceId: string) {
    const report = await api<unknown>("/evidence/" + evidenceId + "/export");
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelforge-case-${selectedId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }
  const title = selectedId ? "Case investigation" : labels[view];
  const severityTotal = stats
    ? Object.values(stats.severity).reduce((a, b) => a + b, 0)
    : 0;
  const alertTable = (rows: Alert[], compact = false) =>
    rows.length ? (
      <div className="table-scroll">
        <GlassTable className="alert-table">
          <thead>
            <tr>
              <th>Detection / host</th>
              <th>Severity</th>
              {!compact && <th>ATT&CK</th>}
              <th className="numeric">Observed · UTC</th>
              <th>
                <span className="sr-only">Investigation</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id}>
                <td>
                  <GlassButton
                    className="row-title"
                    onClick={() => investigate(a.case_id)}
                  >
                    {a.title}
                  </GlassButton>
                  <small className="cell-sub mono">
                    {a.host}
                    {a.user ? ` · ${a.user}` : ""}
                  </small>
                </td>
                <td>
                  <Severity level={a.severity} />
                </td>
                {!compact && (
                  <td>
                    <span className="mono muted">
                      {a.techniques.join(", ")}
                    </span>
                  </td>
                )}
                <td className="numeric muted">{date(a.timestamp)}</td>
                <td>
                  <GlassButton
                    className="icon-button"
                    title={`Investigate ${a.title}`}
                    aria-label={`Investigate ${a.title}`}
                    onClick={() => investigate(a.case_id)}
                  >
                    <ChevronRight size={17} />
                  </GlassButton>
                </td>
              </tr>
            ))}
          </tbody>
        </GlassTable>
      </div>
    ) : (
      <Empty>
        {query || severity || technique
          ? "No alerts match these filters."
          : "No alerts yet. Ingest telemetry or replay the demo to start."}
      </Empty>
    );

  const guideLink = (
    <a
      className="guide-link secondary"
      href="/how-it-works"
      onClick={showGuide}
      aria-current={guide ? "page" : undefined}
    >
      <BookOpen size={16} />
      How It Works
    </a>
  );
  if (guide)
    return (
      <div className="guide-shell">
        <a className="skip-link" href="#main-content">
          Skip to content
        </a>
        <GlassNavbar className="guide-navbar">
          <a
            className="guide-brand"
            href="/"
            onClick={(event) => {
              if (
                event.metaKey ||
                event.ctrlKey ||
                event.shiftKey ||
                event.altKey
              )
                return;
              event.preventDefault();
              navigate("overview");
            }}
          >
            <Mark />
            <strong>SentinelForge</strong>
          </a>
          <nav aria-label="Main navigation">
            {guideLink}
            <GlassButton
              className="primary"
              onClick={() => navigate("overview")}
            >
              Open workspace
              <ArrowUpRight size={15} />
            </GlassButton>
          </nav>
        </GlassNavbar>
        <Suspense
          fallback={
            <main id="main-content" className="route-loading" aria-busy="true">
              <p>Opening the field guide…</p>
              <div className="skeleton" />
            </main>
          }
        >
          <HowItWorks navigate={navigate} />
        </Suspense>
      </div>
    );

  if (booting)
    return (
      <div className="login-shell">
        <div className="login-brand">
          <Mark />
          <strong>SentinelForge</strong>
        </div>
        <main className="login-panel">
          <p role="status">Opening workspace…</p>
          <div className="skeleton" />
        </main>
      </div>
    );
  if (!principal)
    return (
      <div className="login-shell">
        <div className="login-brand">
          <Mark />
          <strong>SentinelForge</strong>
          <span>Security operations</span>
        </div>
        <main className="login-panel">
          <ShieldCheck size={32} />
          <h1>Your next investigation starts here.</h1>
          <p>
            Connect to your SentinelForge instance with an analyst, viewer, or
            administrator token.
          </p>
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setError("");
              try {
                const me = await api<Principal>("/me");
                setPrincipal(me);
                navigate("overview");
              } catch (e) {
                setError((e as Error).message);
              } finally {
                setBusy(false);
              }
            }}
          >
            <label htmlFor="token">Access token</label>
            <GlassInput
              id="token"
              type="password"
              autoComplete="off"
              required
              minLength={32}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="Paste your access token"
            />
            <GlassButton className="primary" disabled={busy}>
              {busy ? "Connecting…" : "Open workspace"}
              <ArrowRight size={16} />
            </GlassButton>
          </form>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          {guideLink}
          <p className="login-help">
            First run? Generate your local credentials with{" "}
            <code>python scripts/setup.py</code> and open <code>.env</code>.
          </p>
        </main>
        <footer>
          SentinelForge v0.1 <span>Evidence before action.</span>
        </footer>
      </div>
    );

  return (
    <div className={`app-shell ${collapsed ? "sidebar-collapsed" : ""}`}>
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <GlassSidebar className="rail">
        <a
          href="#"
          className="brand-mark"
          title="SentinelForge overview"
          aria-label="SentinelForge overview"
          onClick={(e) => {
            e.preventDefault();
            navigate("overview");
          }}
        >
          <Mark />
          <span className="brand-name">
            SentinelForge<small>SECURITY OPERATIONS</small>
          </span>
        </a>
        <GlassButton
          className="collapse-sidebar icon-button"
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-expanded={!collapsed}
          onClick={() => setCollapsed(!collapsed)}
        >
          {collapsed ? (
            <PanelLeftOpen size={18} />
          ) : (
            <PanelLeftClose size={18} />
          )}
        </GlassButton>
        <span className="nav-caption">WORKSPACE</span>
        <nav aria-label="Main navigation">
          {(Object.keys(labels) as View[]).map((v) => {
            const Icon = icons[v];
            return (
              <GlassButton
                key={v}
                className={view === v && !selectedId ? "nav-active" : ""}
                aria-current={view === v && !selectedId ? "page" : undefined}
                aria-label={labels[v]}
                title={labels[v]}
                onClick={() => navigate(v)}
              >
                <Icon size={19} />
                <span>
                  {
                    {
                      overview: "Overview",
                      alerts: "Alerts",
                      cases: "Cases",
                      telemetry: "Events",
                      rules: "Rules",
                    }[v]
                  }
                </span>
              </GlassButton>
            );
          })}
        </nav>
        <div className="sidebar-guide">
          <BookOpen size={20} />
          <strong>Follow the evidence.</strong>
          <p>A practical guide to your first investigation.</p>
          {guideLink}
        </div>
        {!principal.local && !principal.demo && (
          <GlassButton
            className="signout"
            title="Sign out"
            aria-label="Sign out"
            onClick={() => {
              setPrincipal(null);
              setToken("");
              setStats(null);
              setSelectedId(null);
              setMessage("");
              setError("");
            }}
          >
            <LogOut size={18} />
          </GlassButton>
        )}
      </GlassSidebar>
      <GlassModal
        open={menuOpen}
        onClose={() => setMenuOpen(false)}
        title="Your workspace"
      >
        <nav className="mobile-navigation" aria-label="Mobile navigation">
          {(Object.keys(labels) as View[]).map((v) => {
            const Icon = icons[v];
            return (
              <GlassButton
                key={v}
                aria-current={view === v ? "page" : undefined}
                onClick={() => navigate(v)}
              >
                <Icon size={20} />
                {labels[v]}
              </GlassButton>
            );
          })}
          {guideLink}
        </nav>
      </GlassModal>
      <div className="workspace">
        <GlassNavbar className="topbar">
          <GlassButton
            className="mobile-menu-button icon-button"
            aria-label="Open navigation"
            aria-haspopup="dialog"
            onClick={() => setMenuOpen(true)}
          >
            <Menu size={21} />
          </GlassButton>
          <div className="wordmark">
            SentinelForge <span>/</span>{" "}
            <span className="workspace-name">
              {principal.demo ? "Public demo" : "Local lab"}
            </span>
          </div>
          <div className="topbar-right">
            <span className={`connection ${error ? "offline" : ""}`}>
              <span />
              {error ? "Connection needs attention" : "API connected"}
            </span>
            <div className="top-guide-link">{guideLink}</div>
            {!principal.demo && (
              <span className="identity">
                {principal.local ? "Local analyst" : principal.name}
                <small>{principal.local ? "Local mode" : principal.role}</small>
              </span>
            )}
            {!principal.local && !principal.demo && (
              <GlassButton
                className="mobile-signout icon-button"
                aria-label="Sign out"
                onClick={() => {
                  setPrincipal(null);
                  setToken("");
                  setSelectedId(null);
                  setStats(null);
                }}
              >
                <LogOut size={16} />
              </GlassButton>
            )}
          </div>
        </GlassNavbar>
        <main id="main-content" tabIndex={-1}>
          {principal.demo && (
            <div className="notice demo-notice" role="note">
              <span>
                <strong>Synthetic demo</strong> · Explore the evidence. Run
                locally to import telemetry and manage cases.
              </span>
              <a
                href="https://github.com/aashleshshet/SentinelFORGE#run-locally--no-token-or-sign-in"
                target="_blank"
                rel="noreferrer"
              >
                Run locally <ArrowRight size={14} />
              </a>
            </div>
          )}
          <div className="page-heading">
            <div>
              {selectedId && (
                <GlassButton
                  className="back-button"
                  onClick={() => {
                    setSelectedId(null);
                    setDetail(null);
                  }}
                >
                  <ArrowLeft size={14} /> Back to {labels[view].toLowerCase()}
                </GlassButton>
              )}
              <h1>{title}</h1>
              <p>
                {selectedId
                  ? detail
                    ? `${short(detail.id)} · Evidence-led triage`
                    : "Loading case…"
                  : view === "overview"
                    ? `${stats?.open_cases ?? "—"} open investigations. Every signal has a trail.`
                    : view === "alerts"
                      ? "Review signals, inspect their evidence, and decide what needs attention."
                      : view === "cases"
                        ? "Correlated activity, analyst decisions, and preserved evidence."
                        : view === "telemetry"
                          ? "Normalized events with source attribution and UTC timestamps."
                          : "Experimental rules. Tested behavior, explicit limitations."}
              </p>
            </div>
            <div className="heading-actions">
              <GlassButton
                className="secondary"
                disabled={busy}
                onClick={refresh}
              >
                <RefreshCw size={14} />
                <span>Refresh</span>
              </GlassButton>
              {principal.role === "admin" && !selectedId && (
                <GlassButton
                  className="primary"
                  disabled={busy}
                  onClick={replay}
                >
                  <Play size={14} />
                  {busy ? "Processing…" : "Replay demo"}
                </GlassButton>
              )}
            </div>
          </div>
          {error && (
            <div className="notice error" role="alert">
              <CircleAlert size={16} />
              <span>{error} Displayed data may be stale.</span>
            </div>
          )}
          {message && (
            <div className="notice" role="status">
              <Check size={16} />
              <span>{message}</span>
              <GlassButton
                aria-label="Dismiss message"
                className="icon-button"
                onClick={() => setMessage("")}
              >
                <X size={15} />
              </GlassButton>
            </div>
          )}
          {!stats && !error && (
            <Empty>Loading telemetry and investigations…</Empty>
          )}
          {selectedId ? (
            detail && (
              <>
                <section className="case-banner">
                  <div>
                    <Severity
                      level={
                        detail.risk >= 85
                          ? "critical"
                          : detail.risk >= 65
                            ? "high"
                            : "medium"
                      }
                    />
                    <h2>{detail.title}</h2>
                    <p className="muted">
                      {detail.hosts.join(" · ")}{" "}
                      <span className="separator">/</span>{" "}
                      {detail.users.join(", ") || "No attributed user"}
                    </p>
                  </div>
                  <div className="risk">
                    <span>Case risk</span>
                    <strong className="mono">
                      {detail.risk}
                      <small>/100</small>
                    </strong>
                    <span>Heuristic score</span>
                  </div>
                </section>
                <div className="case-layout">
                  <div className="case-main">
                    <section className="panel">
                      <div className="panel-heading">
                        <h2>Investigation timeline</h2>
                        <span>{detail.timeline.length} evidence events</span>
                      </div>
                      <div className="timeline">
                        {detail.timeline.map((e) => (
                          <article key={e.id}>
                            <div className="timeline-time mono">
                              {date(e.timestamp)}
                              <small>{sourceNames[e.source]}</small>
                            </div>
                            <div className="timeline-content">
                              <div className="timeline-dot" />
                              <strong>
                                {e.kind === "authentication"
                                  ? `SSH authentication · ${e.fields.service ?? e.kind}`
                                  : e.process?.split(/[\\/]/).pop() ||
                                    (e.kind === "network"
                                      ? "Network connection"
                                      : e.kind)}
                              </strong>
                              <p className="mono">
                                {e.command ||
                                  (e.dst_ip
                                    ? `${e.src_ip || "—"} → ${e.dst_ip}:${e.dst_port}`
                                    : `${e.user || "Unknown user"} from ${e.src_ip || "—"}`)}
                              </p>
                              <small>
                                {e.host} · {short(e.id)}
                              </small>
                              {e.dst_ip && (
                                <GlassButton
                                  className="text-button"
                                  onClick={() =>
                                    action(async () => {
                                      const result = await api<{
                                        match: { label: string } | null;
                                        external_requests: number;
                                      }>(
                                        "/iocs/lookup?value=" +
                                          encodeURIComponent(e.dst_ip!),
                                      );
                                      setIoc(
                                        `${e.dst_ip}: ${result.match?.label || "No match in local IOC database"}. No external request sent.`,
                                      );
                                    })
                                  }
                                >
                                  Check local IOC <ArrowRight size={12} />
                                </GlassButton>
                              )}
                            </div>
                          </article>
                        ))}
                      </div>
                      {ioc && (
                        <p className="inline-note" role="status">
                          {ioc}
                        </p>
                      )}
                    </section>
                    <section className="panel">
                      <div className="panel-heading">
                        <h2>Detection rationale</h2>
                        <span>{detail.alerts.length} alerts</span>
                      </div>
                      {detail.alerts.map((a) => (
                        <div className="rationale" key={a.id}>
                          <div className="row-between">
                            <strong>{a.title}</strong>
                            <Severity level={a.severity} />
                          </div>
                          <p>{a.explanation}</p>
                          <small className="muted">
                            {a.techniques.join(", ")} · Confidence{" "}
                            {a.confidence}/100 · {a.correlation_reason}
                          </small>
                        </div>
                      ))}
                    </section>
                    <section className="panel">
                      <div className="panel-heading">
                        <h2>Analyst notes</h2>
                        <span>{detail.notes.length} entries</span>
                      </div>
                      {detail.notes.length ? (
                        detail.notes.map((n) => (
                          <article className="note" key={n.id}>
                            <div>
                              <strong>{n.author}</strong>
                              <time>{date(n.created_at)} UTC</time>
                            </div>
                            <p>{n.text}</p>
                          </article>
                        ))
                      ) : (
                        <Empty>
                          No notes yet. Record the context behind your next
                          decision.
                        </Empty>
                      )}
                      {canEdit && (
                        <form
                          className="note-form"
                          onSubmit={(e) => {
                            e.preventDefault();
                            action(async () => {
                              await api(
                                "/cases/" + detail.id + "/notes",
                                "POST",
                                { text: note },
                              );
                              setNote("");
                            }, "Investigation note saved.");
                          }}
                        >
                          <label htmlFor="note">Investigation note</label>
                          <textarea
                            id="note"
                            maxLength={5000}
                            value={note}
                            onChange={(e) => setNote(e.target.value)}
                            placeholder="What did you observe? What will you check next?"
                          />
                          <GlassButton
                            className="secondary"
                            disabled={busy || !note.trim()}
                          >
                            Add note <ArrowRight size={14} />
                          </GlassButton>
                        </form>
                      )}
                    </section>
                  </div>
                  <aside className="case-aside">
                    <section className="panel">
                      <div className="panel-heading">
                        <h2>Case controls</h2>
                      </div>
                      <label htmlFor="case-status">Status</label>
                      <select
                        id="case-status"
                        value={detail.status}
                        disabled={!canEdit || busy}
                        onChange={(e) =>
                          action(
                            () =>
                              api("/cases/" + detail.id, "PATCH", {
                                status: e.target.value,
                              }),
                            "Case status updated.",
                          )
                        }
                      >
                        <option value="open">Open</option>
                        <option value="investigating">Investigating</option>
                        <option value="escalated">Escalated</option>
                        <option value="closed">Closed</option>
                      </select>
                      <div className="assignment">
                        <span className="muted">Assigned to</span>
                        <strong>{detail.assignee || "Unassigned"}</strong>
                        {canEdit && (
                          <GlassButton
                            className="text-button"
                            disabled={busy}
                            onClick={() =>
                              action(
                                () =>
                                  api("/cases/" + detail.id, "PATCH", {
                                    assignee: principal.name,
                                  }),
                                "Case assigned to you.",
                              )
                            }
                          >
                            Assign to me
                          </GlassButton>
                        )}
                      </div>
                      <p className="muted small">
                        First observed {date(detail.first_seen)} UTC
                      </p>
                    </section>
                    <section className="panel">
                      <div className="panel-heading">
                        <h2>Investigation checklist</h2>
                      </div>
                      {Object.entries({
                        validate_signal: "Validate the signal",
                        scope_hosts: "Scope affected hosts",
                        preserve_evidence: "Preserve evidence",
                        review_response: "Review response options",
                      }).map(([key, label]) => (
                        <label className="checklist-row" key={key}>
                          <GlassInput
                            type="checkbox"
                            checked={!!detail.checklist[key]}
                            disabled={!canEdit || busy}
                            onChange={(e) => {
                              const complete = e.target.checked;
                              setDetail((current) =>
                                current
                                  ? {
                                      ...current,
                                      checklist: {
                                        ...current.checklist,
                                        [key]: complete,
                                      },
                                    }
                                  : current,
                              );
                              action(async () => {
                                try {
                                  await api(
                                    "/cases/" + detail.id + "/checklist",
                                    "PUT",
                                    { key, complete },
                                  );
                                } catch (error) {
                                  setDetail((current) =>
                                    current
                                      ? {
                                          ...current,
                                          checklist: {
                                            ...current.checklist,
                                            [key]: !complete,
                                          },
                                        }
                                      : current,
                                  );
                                  throw error;
                                }
                              });
                            }}
                          />
                          <span>{label}</span>
                        </label>
                      ))}
                    </section>
                    <section className="panel">
                      <div className="panel-heading">
                        <h2>Evidence vault</h2>
                        <FileCheck2 size={16} />
                      </div>
                      <p className="muted">
                        {principal.demo
                          ? "Download a preserved snapshot of this synthetic investigation. Its SHA-256 digest can be verified locally."
                          : "Freeze the case, source events, and notes in a SHA-256-verified snapshot."}
                      </p>
                      {canEdit && (
                        <GlassButton
                          className="secondary full"
                          disabled={busy}
                          onClick={() =>
                            action(
                              () =>
                                api(
                                  "/cases/" + detail.id + "/evidence",
                                  "POST",
                                ),
                              "Evidence snapshot preserved.",
                            )
                          }
                        >
                          <FileCheck2 size={15} />
                          Preserve evidence
                        </GlassButton>
                      )}
                      {detail.evidence.map((e) => (
                        <div className="evidence-row" key={e.id}>
                          <span className="mono">{e.sha256.slice(0, 12)}…</span>
                          {(canEdit || principal.demo) && (
                            <GlassButton
                              className="text-button"
                              disabled={busy}
                              onClick={() => action(() => download(e.id))}
                            >
                              <ArrowDownToLine size={14} />
                              Export
                            </GlassButton>
                          )}
                        </div>
                      ))}
                      <small className="muted">
                        {principal.demo
                          ? "Bundled synthetic evidence · read-only"
                          : "Append-only API · database storage"}
                      </small>
                    </section>
                    <section className="panel">
                      <div className="panel-heading">
                        <h2>Response approval</h2>
                      </div>
                      <p className="muted">
                        Endpoint isolation is simulated. A separate
                        administrator must approve each request.
                      </p>
                      {canEdit && (
                        <form
                          onSubmit={(e) => {
                            e.preventDefault();
                            action(async () => {
                              await api(
                                "/cases/" + detail.id + "/responses",
                                "POST",
                                { action: "simulate_isolation", reason },
                              );
                              setReason("");
                            }, "Simulation requested. A separate administrator can approve it.");
                          }}
                        >
                          <label htmlFor="reason">Reason for simulation</label>
                          <textarea
                            id="reason"
                            value={reason}
                            minLength={10}
                            maxLength={1000}
                            required
                            onChange={(e) => setReason(e.target.value)}
                          />
                          <GlassButton
                            className="secondary full"
                            disabled={busy || reason.trim().length < 10}
                          >
                            Request simulation
                          </GlassButton>
                        </form>
                      )}
                      {detail.responses.map((r) => (
                        <div className="response-row" key={r.id}>
                          <strong>
                            {r.status === "simulated"
                              ? "Isolation simulated"
                              : "Awaiting approval"}
                          </strong>
                          <p>{r.reason}</p>
                          <small>
                            Requested by {r.requested_by}
                            {r.approved_by
                              ? ` · Approved by ${r.approved_by}`
                              : ""}
                          </small>
                          {principal.role === "admin" &&
                            r.status === "pending" &&
                            r.requested_by !== principal.name && (
                              <GlassButton
                                className="secondary full"
                                disabled={busy}
                                onClick={() =>
                                  action(
                                    () =>
                                      api(
                                        "/responses/" + r.id + "/approve",
                                        "POST",
                                      ),
                                    "Simulation completed. No endpoint action was executed.",
                                  )
                                }
                              >
                                Approve simulation
                              </GlassButton>
                            )}
                        </div>
                      ))}
                    </section>
                  </aside>
                </div>
              </>
            )
          ) : (
            <>
              {view === "overview" && stats && (
                <>
                  <section className="metrics" aria-label="Workspace totals">
                    <div>
                      <span>Open investigations</span>
                      <strong className="lead-number mono">
                        {number(stats.open_cases)}
                      </strong>
                      <small>Awaiting an analyst decision</small>
                    </div>
                    <div>
                      <span>Detection alerts</span>
                      <strong className="mono">{number(stats.alerts)}</strong>
                      <small>
                        {stats.severity.critical} critical ·{" "}
                        {stats.severity.high} high
                      </small>
                    </div>
                    <div>
                      <span>Normalized events</span>
                      <strong className="mono">{number(stats.events)}</strong>
                      <small>
                        Across {stats.sources.filter((s) => s.count > 0).length}{" "}
                        telemetry sources
                      </small>
                    </div>
                    <div>
                      <span>Active detection rules</span>
                      <strong className="mono">{number(stats.rules)}</strong>
                      <small>Validated on synthetic fixtures</small>
                    </div>
                  </section>
                  <div className="overview-grid">
                    <section className="panel queue-panel">
                      <div className="panel-heading">
                        <h2>Signals to investigate</h2>
                        <GlassButton
                          className="text-button"
                          onClick={() => navigate("alerts")}
                        >
                          View queue <ArrowRight size={14} />
                        </GlassButton>
                      </div>
                      {alertTable(alerts.items, true)}
                      <div className="panel-foot">
                        <span>
                          {Math.min(alerts.items.length, 4)} highest-priority
                          alerts · all severities
                        </span>
                        <span>Observed time, UTC</span>
                      </div>
                    </section>
                    <section className="panel sources-panel">
                      <div className="panel-heading">
                        <h2>
                          {principal.demo
                            ? "Demo telemetry"
                            : "Ingestion status"}
                        </h2>
                        <Activity size={16} />
                      </div>
                      {stats.sources.map((s) => {
                        const recent =
                          !!s.last_received &&
                          Date.now() - new Date(s.last_received).getTime() <
                            300000;
                        return (
                          <div className="source-row" key={s.source}>
                            <span
                              className={`status-dot ${recent ? "active" : ""}`}
                              title={
                                recent
                                  ? "Received in the last five minutes"
                                  : "No recent telemetry"
                              }
                            />
                            <div>
                              <strong>{sourceNames[s.source]}</strong>
                              <small>
                                {s.last_received
                                  ? `Last received ${date(s.last_received)} UTC`
                                  : "Waiting for telemetry"}
                              </small>
                            </div>
                            <span className="mono numeric">
                              {number(s.count)}
                            </span>
                          </div>
                        );
                      })}
                      <div className="panel-foot">
                        <span>
                          {principal.demo
                            ? "Fixed synthetic dataset"
                            : "Activity window: 5 min"}
                        </span>
                        <span>
                          {principal.demo
                            ? "18 sample events"
                            : "Polls every 10s"}
                        </span>
                      </div>
                    </section>
                  </div>
                  <section className="panel attack-panel">
                    <div className="panel-heading">
                      <div>
                        <h2>ATT&CK signal map</h2>
                        <p>
                          Observed alerts per mapped technique. Signals do not
                          prove a complete technique.
                        </p>
                      </div>
                      <span>
                        {stats.techniques.filter((t) => t.alerts > 0).length} /{" "}
                        {stats.techniques.length} mapped techniques observed
                      </span>
                    </div>
                    <div className="technique-grid">
                      {stats.techniques.map((t) => (
                        <GlassButton
                          className={
                            t.alerts ? "technique has-alert" : "technique"
                          }
                          key={t.id}
                          onClick={() => {
                            navigate("alerts");
                            setTechnique(t.id);
                          }}
                        >
                          <div>
                            <span className="mono">{t.id}</span>
                            <strong className="mono">{t.alerts}</strong>
                          </div>
                          <span>{t.name}</span>
                          <small>
                            {t.tactics?.[0]?.replaceAll("-", " ") ||
                              "Unclassified"}
                          </small>
                          <div className="heat-track">
                            <span
                              style={{
                                width: `${t.alerts ? Math.max(10, (t.alerts / Math.max(...stats.techniques.map((t) => t.alerts))) * 100) : 0}%`,
                              }}
                            />
                          </div>
                        </GlassButton>
                      ))}
                    </div>
                  </section>
                  <div className="bottom-grid">
                    <section className="panel">
                      <div className="panel-heading">
                        <h2>Severity distribution</h2>
                        <SlidersHorizontal size={16} />
                      </div>
                      <div className="distribution">
                        {Object.entries(stats.severity).map(
                          ([level, count]) => (
                            <GlassButton
                              key={level}
                              className="distribution-row"
                              onClick={() => {
                                navigate("alerts");
                                setSeverity(level);
                              }}
                            >
                              <Severity level={level} />
                              <div className="bar-track">
                                <span
                                  className={level}
                                  style={{
                                    width: `${severityTotal ? (count / severityTotal) * 100 : 0}%`,
                                  }}
                                />
                              </div>
                              <strong className="mono">{count}</strong>
                            </GlassButton>
                          ),
                        )}
                      </div>
                    </section>
                    <section className="panel">
                      <div className="panel-heading">
                        <h2>Host activity</h2>
                        <Network size={16} />
                      </div>
                      <div className="host-heading">
                        <span>Host</span>
                        <span>Events / alerts</span>
                      </div>
                      {stats.hosts.slice(0, 4).map((h) => (
                        <GlassButton
                          className="host-row"
                          key={h.host}
                          onClick={() => {
                            navigate("telemetry");
                            setQuery(h.host);
                          }}
                        >
                          <span className="mono">{h.host}</span>
                          <span className="mono">
                            {h.events}{" "}
                            <span className="muted">/ {h.alerts}</span>
                          </span>
                        </GlassButton>
                      ))}
                      {!stats.hosts.length && <Empty>No hosts observed.</Empty>}
                    </section>
                    <section className="panel">
                      <div className="panel-heading">
                        <h2>Rule activity</h2>
                        <GlassButton
                          className="text-button"
                          onClick={() => navigate("rules")}
                        >
                          All rules <ArrowRight size={13} />
                        </GlassButton>
                      </div>
                      {[...rules]
                        .sort((a, b) => b.alert_count - a.alert_count)
                        .slice(0, 4)
                        .map((r) => (
                          <div className="rule-summary" key={r.id}>
                            <span>{r.title}</span>
                            <span className="mono">{r.alert_count}</span>
                          </div>
                        ))}
                      <small className="muted">
                        Observed alert counts · validation in Evaluation docs
                      </small>
                    </section>
                  </div>
                </>
              )}
              {view === "alerts" && (
                <>
                  <div className="filter-bar">
                    <label className="search-field">
                      <Search size={15} />
                      <GlassInput
                        aria-label="Search alerts"
                        placeholder="Search detection, host, or user"
                        value={query}
                        onChange={(e) => {
                          setQuery(e.target.value);
                          setPage(0);
                        }}
                      />
                    </label>
                    <select
                      aria-label="Filter severity"
                      value={severity}
                      onChange={(e) => {
                        setSeverity(e.target.value);
                        setPage(0);
                      }}
                    >
                      <option value="">All severities</option>
                      {["critical", "high", "medium", "low"].map((s) => (
                        <option key={s}>{s}</option>
                      ))}
                    </select>
                    <select
                      aria-label="Filter ATT&CK technique"
                      value={technique}
                      onChange={(e) => {
                        setTechnique(e.target.value);
                        setPage(0);
                      }}
                    >
                      <option value="">All ATT&CK techniques</option>
                      {stats?.techniques.map((t) => (
                        <option key={t.id} value={t.id}>
                          {t.id} · {t.name}
                        </option>
                      ))}
                    </select>
                    <span className="result-count">{alerts.total} alerts</span>
                  </div>
                  <section className="panel">
                    {alertTable(alerts.items)}
                  </section>
                </>
              )}
              {view === "cases" && (
                <>
                  <div className="filter-bar">
                    <label className="search-field">
                      <Search size={15} />
                      <GlassInput
                        aria-label="Search investigations"
                        placeholder="Search case title or host"
                        value={query}
                        onChange={(e) => {
                          setQuery(e.target.value);
                          setPage(0);
                        }}
                      />
                    </label>
                    <select
                      aria-label="Filter case status"
                      value={status}
                      onChange={(e) => {
                        setStatus(e.target.value);
                        setPage(0);
                      }}
                    >
                      <option value="">All statuses</option>
                      {["open", "investigating", "escalated", "closed"].map(
                        (s) => (
                          <option key={s}>{s}</option>
                        ),
                      )}
                    </select>
                    <span className="result-count">
                      {cases.total} investigations
                    </span>
                  </div>
                  <section className="panel">
                    <div className="table-scroll">
                      <GlassTable>
                        <thead>
                          <tr>
                            <th>Investigation</th>
                            <th>Status</th>
                            <th>Assignee</th>
                            <th className="numeric">Risk</th>
                            <th />
                          </tr>
                        </thead>
                        <tbody>
                          {cases.items.map((c) => (
                            <tr key={c.id}>
                              <td>
                                <GlassButton
                                  className="row-title"
                                  onClick={() => investigate(c.id)}
                                >
                                  {c.title}
                                </GlassButton>
                                <small className="cell-sub mono">
                                  {short(c.id)} · {c.hosts.length} hosts
                                </small>
                              </td>
                              <td>
                                <span className="case-status">{c.status}</span>
                              </td>
                              <td className="muted">
                                {c.assignee || "Unassigned"}
                              </td>
                              <td className="numeric mono">
                                {c.risk}
                                <span className="muted">/100</span>
                              </td>
                              <td>
                                <GlassButton
                                  className="icon-button"
                                  aria-label={`Open case ${short(c.id)}`}
                                  onClick={() => investigate(c.id)}
                                >
                                  <ChevronRight size={16} />
                                </GlassButton>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </GlassTable>
                    </div>
                    {!cases.items.length && (
                      <Empty>No investigations match this view.</Empty>
                    )}
                  </section>
                </>
              )}
              {view === "telemetry" && (
                <>
                  <div className="filter-bar">
                    <label className="search-field">
                      <Search size={15} />
                      <GlassInput
                        aria-label="Search telemetry"
                        placeholder="Search host, user, or event kind"
                        value={query}
                        onChange={(e) => {
                          setQuery(e.target.value);
                          setPage(0);
                        }}
                      />
                    </label>
                    <select
                      aria-label="Filter telemetry source"
                      value={source}
                      onChange={(e) => {
                        setSource(e.target.value);
                        setPage(0);
                      }}
                    >
                      <option value="">All sources</option>
                      {Object.entries(sourceNames).map(([k, v]) => (
                        <option value={k} key={k}>
                          {v}
                        </option>
                      ))}
                    </select>
                    <span className="result-count">{events.total} events</span>
                    {principal.role === "admin" && (
                      <>
                        <GlassInput
                          ref={file}
                          type="file"
                          className="sr-only"
                          accept="application/json,.json"
                          aria-label="Upload JSON telemetry"
                          onChange={(e) => {
                            const f = e.target.files?.[0];
                            if (!f) return;
                            action(async () => {
                              if (f.size > 1048576)
                                throw new Error(
                                  "Choose a JSON file smaller than 1 MiB.",
                                );
                              const data = JSON.parse(await f.text());
                              const r = await api<ReplayResult>(
                                "/ingest",
                                "POST",
                                Array.isArray(data) ? { events: data } : data,
                              );
                              setMessage(
                                `Import: ${r.accepted} accepted, ${r.duplicates} duplicates, ${r.rejected} rejected. Use the API for per-event rejection details.`,
                              );
                            });
                            e.target.value = "";
                          }}
                        />
                        <GlassButton
                          className="secondary"
                          disabled={busy}
                          onClick={() => file.current?.click()}
                        >
                          <Upload size={14} />
                          Import JSON
                        </GlassButton>
                      </>
                    )}
                  </div>
                  <section className="panel event-list">
                    {events.items.map((e) => (
                      <details key={e.id}>
                        <summary>
                          <span className="event-kind">{e.kind}</span>
                          <span>
                            <strong className="mono">{e.host}</strong>
                            <small>
                              {sourceNames[e.source]} ·{" "}
                              {e.user || "No user attribution"}
                            </small>
                          </span>
                          <time className="mono">{date(e.timestamp)} UTC</time>
                          <ChevronRight size={15} />
                        </summary>
                        <pre>{JSON.stringify(e, null, 2)}</pre>
                      </details>
                    ))}
                    {!events.items.length && (
                      <Empty>No telemetry matches these filters.</Empty>
                    )}
                  </section>
                </>
              )}
              {view === "rules" && (
                <>
                  <div className="rule-info">
                    <BookOpen size={18} />
                    <span>
                      Nine experimental rules · Sigma dictionary selections and
                      boolean conditions · Confidence is a heuristic, not a
                      probability.
                    </span>
                  </div>
                  <div className="rules-list">
                    {rules.map((r) => (
                      <details className="panel rule-card" key={r.id}>
                        <summary>
                          <div>
                            <strong>{r.title}</strong>
                            <small>
                              {r.techniques
                                .map((t) => `${t.id} · ${t.name}`)
                                .join(", ")}
                            </small>
                          </div>
                          <Severity level={r.level} />
                          <span className="fixture-state">
                            <Check size={14} />
                            Synthetic fixtures
                          </span>
                          <span className="mono numeric">
                            {r.alert_count} alerts
                          </span>
                          <ChevronRight size={16} />
                        </summary>
                        <div className="rule-body">
                          <p>{r["x-sentinelforge"].explanation}</p>
                          <p>
                            <strong>Required telemetry:</strong>{" "}
                            {r["x-sentinelforge"].required_telemetry.join(", ")}
                          </p>
                          <p>
                            <strong>False positives:</strong>{" "}
                            {r.falsepositives.join("; ")}
                          </p>
                          <p>
                            <strong>Status:</strong> {r.status} · Confidence{" "}
                            {r["x-sentinelforge"].confidence}/100
                          </p>
                          <pre>{JSON.stringify(r.detection, null, 2)}</pre>
                        </div>
                      </details>
                    ))}
                  </div>
                </>
              )}
              {["alerts", "cases", "telemetry"].includes(view) && (
                <div className="pagination">
                  <span>
                    {(view === "alerts"
                      ? alerts
                      : view === "cases"
                        ? cases
                        : events
                    ).total
                      ? page * 50 + 1
                      : 0}
                    –
                    {Math.min(
                      (page + 1) * 50,
                      (view === "alerts"
                        ? alerts
                        : view === "cases"
                          ? cases
                          : events
                      ).total,
                    )}{" "}
                    of{" "}
                    {
                      (view === "alerts"
                        ? alerts
                        : view === "cases"
                          ? cases
                          : events
                      ).total
                    }
                  </span>
                  <GlassButton
                    className="secondary"
                    disabled={page === 0}
                    onClick={() => setPage((p) => p - 1)}
                  >
                    Previous
                  </GlassButton>
                  <GlassButton
                    className="secondary"
                    disabled={
                      (page + 1) * 50 >=
                      (view === "alerts"
                        ? alerts
                        : view === "cases"
                          ? cases
                          : events
                      ).total
                    }
                    onClick={() => setPage((p) => p + 1)}
                  >
                    Next
                  </GlassButton>
                </div>
              )}
            </>
          )}
          <footer className="workspace-footer">
            <span>
              SentinelForge{" "}
              <span className="muted">v0.1 · Defensive engineering lab</span>
            </span>
            <span>
              {stats?.scope || "All retained telemetry"} ·{" "}
              {stats ? `Updated ${date(stats.updated_at)} UTC` : "Connecting…"}
            </span>
          </footer>
        </main>
      </div>
    </div>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
