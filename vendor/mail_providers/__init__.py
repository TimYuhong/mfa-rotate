"""Type-only compatibility shim. This service never accesses mailboxes."""
class MailProvider:
    def wait_for_otp(self, *args, **kwargs):
        raise RuntimeError("email_verification_required")
