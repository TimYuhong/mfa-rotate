import { describe, it, expect } from "vitest";
import { parseLines, parseSingle, validate } from "./parser";
const secret = "JBSWY3DPEHPK3PXP";
describe("credential import", () => {
  it("accepts a single three-hyphen credential", () =>
    expect(parseSingle(`user@example.com---p--word!---${secret}`).credential).toEqual({email:"user@example.com",password:"p--word!",totp_secret:secret}));
  it("does not mistake a double hyphen in the email domain for a separator", () =>
    expect(parseSingle(`user@xn--example.com---p---${secret}`).credential?.email).toBe("user@xn--example.com"));
  it("single import rejects multiple accounts", () =>
    expect(parseSingle(`a@example.com---p---${secret}\nb@example.com---p---${secret}`).error).toBeTruthy());
  it("does not silently split a password containing the delimiter", () =>
    expect(parseSingle(`a@example.com---p---word---${secret}`).error).toBeTruthy());
  it("parses canonical form", () =>
    expect(
      parseLines(`user@example.com----p--word----${secret}`)[0].credential
        ?.password,
    ).toBe("p--word"));
  it("accepts explicit legacy format", () =>
    expect(
      parseLines(`user@example.com--password---${secret}`)[0].credential
        ?.totp_secret,
    ).toBe(secret));
  it("never guesses an ambiguous password", () =>
    expect(
      parseLines(`user@example.com----p----word----${secret}`)[0].error,
    ).toBeTruthy());
  it("preserves password whitespace", () =>
    expect(
      parseLines(`user@example.com\t password \t${secret}`)[0].credential
        ?.password,
    ).toBe(" password "));
  it("flags duplicates", () =>
    expect(
      parseLines(
        `a@example.com----p----${secret}\na@example.com----p----${secret}`,
      )[1].error,
    ).toBeTruthy());
  it("rejects OTP instead of secret", () =>
    expect(
      validate({
        email: "a@example.com",
        password: "p",
        totp_secret: "123456",
      }),
    ).toBeTruthy());
  it("caps batch count", () =>
    expect(
      parseLines(
        Array(51).fill(`a@example.com----p----${secret}`).join("\n"),
      )[0].error,
    ).toContain("50"));
  it("handles BOM and CRLF", () =>
    expect(parseLines(`\uFEFFa@example.com----p----${secret}\r\n`).length).toBe(
      1,
    ));
});
