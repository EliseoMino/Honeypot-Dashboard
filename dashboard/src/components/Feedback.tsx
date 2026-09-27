import type { ReactNode } from "react";

export function Loading({ label = "Cargando" }: { label?: string }): ReactNode {
  return (
    <p className="state state--loading" role="status">
      {label}…
    </p>
  );
}

export function ErrorBanner({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}): ReactNode {
  return (
    <div className="state state--error" role="alert">
      <span>{message}</span>
      {onRetry ? (
        <button type="button" className="button" onClick={onRetry}>
          Reintentar
        </button>
      ) : null}
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }): ReactNode {
  return <p className="state state--empty">{children}</p>;
}
