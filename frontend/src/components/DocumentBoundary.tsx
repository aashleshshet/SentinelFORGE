import { Component, type ReactNode } from "react";

// A deployment or interrupted connection can make a lazy route unavailable.
// Keep the workspace reachable without resetting its memory-only session.
export class DocumentBoundary extends Component<
  { children: ReactNode; onWorkspace: () => void },
  { failed: boolean }
> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <main id="main-content" className="route-loading" tabIndex={-1}>
        <h1>This page could not load.</h1>
        <p role="alert">
          Check your connection, then reload the page. Reloading an
          authenticated workspace requires signing in again.
        </p>
        <div className="learn-links">
          <button className="primary" onClick={() => window.location.reload()}>
            Reload page
          </button>
          <button className="secondary" onClick={this.props.onWorkspace}>
            Return to workspace
          </button>
        </div>
      </main>
    );
  }
}
