import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "./ui/button";

// Business feedback composed with the existing shadcn Button and Lucide icons.
export function CopyButton({ value, label, copiedLabel = "已复制" }: {
  value: string;
  label: string;
  copiedLabel?: string;
}) {
  const [state, setState] = useState<"idle" | "pending" | "copied" | "failed">("idle");
  const mounted = useRef(false);
  const pending = useRef(false);
  const reset = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      clearTimeout(reset.current);
    };
  }, []);

  async function copy() {
    if (pending.current) return;
    pending.current = true;
    clearTimeout(reset.current);
    setState("pending");
    try {
      await navigator.clipboard.writeText(value);
      if (mounted.current) {
        setState("copied");
        reset.current = setTimeout(() => setState("idle"), 1800);
      }
    } catch {
      if (mounted.current) {
        setState("failed");
        reset.current = setTimeout(() => setState("idle"), 4000);
      }
    } finally {
      pending.current = false;
    }
  }

  return (
    <span className="copy-control">
      <Button type="button" variant="plain" size="icon" data-copy-state={state}
        aria-label={state === "copied" ? copiedLabel : label}
        aria-busy={state === "pending"} disabled={state === "pending"}
        title={state === "copied" ? copiedLabel : label} onClick={copy}>
        <span className="feedback-icon" aria-hidden="true" data-copied={state === "copied"}>
          <Copy className="feedback-copy" size={17} />
          <Check className="feedback-check" size={17} />
        </span>
      </Button>
      <span role="status" className={state === "failed" ? "copy-error" : "sr-only"}>
        {state === "copied" ? copiedLabel : state === "failed" ? "复制失败，请手动复制" : ""}
      </span>
    </span>
  );
}
