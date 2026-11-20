import { useLayoutEffect, useRef, useState } from "react";
import { useT } from "../i18n";

export interface LogLine {
  id: number;
  text: string;
}

interface LogsScreenProps {
  logLines: LogLine[];
  active: boolean;
}

export function LogsScreen({ logLines, active }: LogsScreenProps) {
  const t = useT();
  const logRef = useRef<HTMLDivElement>(null);
  const followingBottom = useRef(true);
  const [autoScroll, setAutoScroll] = useState(true);

  useLayoutEffect(() => {
    const el = logRef.current;
    if (el && active && autoScroll && followingBottom.current) {
      el.scrollTop = el.scrollHeight;
    }
  }, [logLines, active, autoScroll]);

  return (
    <div
      style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
        background: "var(--color-titlebar)",
      }}
    >
      <label style={{ padding: "8px 12px", color: "var(--color-text-muted)", fontSize: "10px" }}>
        <input
          type="checkbox"
          checked={autoScroll}
          onChange={(event) => {
            const enabled = event.currentTarget.checked;
            if (enabled) followingBottom.current = true;
            setAutoScroll(enabled);
          }}
        />{" "}
        {t("logs.auto_scroll")}
      </label>
      <div
        ref={logRef}
        onScroll={(event) => {
          const el = event.currentTarget;
          followingBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 30;
        }}
        style={{
          flex: 1,
          overflowY: "auto",
          padding: "8px 12px",
          userSelect: "text",
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
        logLines.map(({ id, text: line }) => (
          <div
            key={id}
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
    </div>
  );
}
