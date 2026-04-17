import { useEffect, useRef } from "react";
import { useT } from "../i18n";

interface LogsScreenProps {
  logLines: string[];
}

export function LogsScreen({ logLines }: LogsScreenProps) {
  const t = useT();
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = logRef.current;
    if (el) {
      const isAtBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 30;
      if (isAtBottom) el.scrollTop = el.scrollHeight;
    }
  }, [logLines]);

  return (
    <div
      ref={logRef}
      style={{
        flex: 1,
        overflowY: "auto",
        padding: "8px 12px",
        background: "var(--color-titlebar)",
      }}
    >
      {logLines.length === 0 ? (
        <div
          style={{
            height: "100%",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <span style={{ fontSize: "10px", color: "var(--color-text-dim)" }}>
            {t("logs.empty")}
          </span>
        </div>
      ) : (
        logLines.map((line, i) => (
          <div
            key={i}
            style={{
              fontSize: "9px",
              lineHeight: "1.5",
              fontFamily: "var(--font-mono)",
              color: /ERROR|FATAL/i.test(line) || line.startsWith("[terminated]")
                ? "var(--color-error-text)"
                : /WARN/i.test(line)
                ? "var(--color-warn-text)"
                : "var(--color-text-muted)",
              wordBreak: "break-all",
            }}
          >
            {line}
          </div>
        ))
      )}
    </div>
  );
}
