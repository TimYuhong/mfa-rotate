import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "./ui/alert-dialog";
import { DialogGlass } from "./dialog-glass";

export function Confirm({ open, onOpenChange, onConfirm, onReturnFocus }: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void;
  onReturnFocus?: () => void;
}) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="glass-dialog max-w-[min(32rem,calc(100vw-2rem))] rounded-xl"
        onCloseAutoFocus={event => { if (onReturnFocus) { event.preventDefault(); onReturnFocus(); } }}>
        <DialogGlass />
        <AlertDialogHeader>
          <AlertDialogTitle>更换所选账号的 2FA 密钥？</AlertDialogTitle>
          <AlertDialogDescription className="glass-description">
            旧密钥将失效，中断可能无法恢复。请保持页面在线，完成后导出新密钥。
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter className="gap-2">
          <AlertDialogCancel className="h-11" data-glass-cancel>返回检查</AlertDialogCancel>
          <AlertDialogAction className="h-11" onClick={onConfirm}>确认并开始</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export function ClearResultConfirm({ open, onOpenChange, onConfirm, onReturnFocus, all = false, disabled = false }: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void;
  onReturnFocus?: () => void;
  all?: boolean;
  disabled?: boolean;
}) {
  return <AlertDialog open={open} onOpenChange={onOpenChange}>
    <AlertDialogContent className="glass-dialog max-w-[min(32rem,calc(100vw-2rem))] rounded-xl"
      onCloseAutoFocus={event => { if (onReturnFocus) { event.preventDefault(); onReturnFocus(); } }}>
      <DialogGlass />
      <AlertDialogHeader>
        <AlertDialogTitle>{all ? "清空本浏览器的全部结果？" : "清除这条保存结果？"}</AlertDialogTitle>
        <AlertDialogDescription className="glass-description">
          {all ? "请先导出，并结束其他标签页任务。清空后无法恢复，不会更改账号密钥。" : "请先复制或导出新密钥，清除后无法恢复。"}
        </AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter className="gap-2">
        <AlertDialogCancel className="h-11" data-glass-cancel>取消</AlertDialogCancel>
        <AlertDialogAction disabled={disabled} className="h-11 bg-destructive text-destructive-foreground hover:bg-destructive/90" onClick={onConfirm}>{all ? "确认清空" : "确认清除"}</AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>;
}
