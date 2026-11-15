import {
  useEffect,
  useId,
  useRef,
  type ComponentProps,
  type ReactNode,
} from "react";
import { X } from "lucide-react";

// Native elements retain form, focus, and assistive-technology behavior.
export function GlassButton({
  className = "",
  ...props
}: ComponentProps<"button">) {
  return <button className={`glass-button ${className}`} {...props} />;
}
export function GlassInput({
  className = "",
  ...props
}: ComponentProps<"input">) {
  return <input className={`glass-input ${className}`} {...props} />;
}
export function GlassPanel({
  className = "",
  ...props
}: ComponentProps<"section">) {
  return <section className={`glass-panel ${className}`} {...props} />;
}
export function GlassNavbar({
  className = "",
  ...props
}: ComponentProps<"header">) {
  return <header className={`glass-material ${className}`} {...props} />;
}
export function GlassSidebar({
  className = "",
  ...props
}: ComponentProps<"aside">) {
  return <aside className={`glass-material ${className}`} {...props} />;
}
export function GlassTable(props: ComponentProps<"table">) {
  return <table {...props} />;
}
export function GlassModal({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const node = dialog.current;
    if (!node) return;
    if (open && !node.open) node.showModal();
    else if (!open && node.open) node.close();
  }, [open]);
  return (
    <dialog
      ref={dialog}
      className="glass-modal glass-material"
      aria-labelledby={titleId}
      onCancel={onClose}
      onClose={onClose}
      onKeyDown={(event) => {
        if (event.key !== "Tab") return;
        const items = Array.from(
          event.currentTarget.querySelectorAll<HTMLElement>(
            'button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex="0"]',
          ),
        ).filter((item) => item.getClientRects().length > 0);
        const first = items[0];
        const last = items[items.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="modal-content">
        <div className="modal-heading">
          <h2 id={titleId}>{title}</h2>
          <GlassButton
            type="button"
            className="icon-button"
            aria-label="Close navigation"
            onClick={onClose}
          >
            <X size={20} />
          </GlassButton>
        </div>
        {children}
      </div>
    </dialog>
  );
}
