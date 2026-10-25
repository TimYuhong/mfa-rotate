import { CheckCircle2, CircleAlert } from "lucide-react";
import { useRef } from "react";
import { DialogGlass } from "./dialog-glass";
import { AlertDialog, AlertDialogCancel, AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "./ui/alert-dialog";

export function FeedbackDialog({ open, message, error, onClose }: {
  open: boolean; message: string; error: boolean; onClose: () => void;
}) {
  const returnFocus = useRef<HTMLElement | null>(null);
  return <AlertDialog open={open} onOpenChange={value => { if (!value) onClose(); }}>
    <AlertDialogContent data-feedback-dialog className="glass-dialog feedback-dialog max-w-[min(28rem,calc(100vw-2rem))]"
      onOpenAutoFocus={() => { returnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; }}
      onCloseAutoFocus={event => { event.preventDefault(); if (returnFocus.current?.isConnected) returnFocus.current.focus({ preventScroll: true }); }}>
      <DialogGlass />
      <AlertDialogHeader>
        <AlertDialogTitle className="feedback-heading">
          {error ? <CircleAlert size={20} className="feedback-error" aria-hidden="true" /> : <CheckCircle2 size={20} className="feedback-success" aria-hidden="true" />}
          {error ? "操作未完成" : "提示"}
        </AlertDialogTitle>
        <AlertDialogDescription className="glass-description">{message}</AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter>
        <AlertDialogCancel aria-label={error ? "关闭错误提示" : "关闭提示"}>知道了</AlertDialogCancel>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>;
}
