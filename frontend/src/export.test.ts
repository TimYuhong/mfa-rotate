import {describe, it, expect} from "vitest";
import {credentialText} from "./export";
import {parseSingle} from "./parser";
import type {ResultRecord} from "./vault";
const result:ResultRecord={id:"fixture",email:"a@example.com",new_secret:"JBSWY3DPEHPK3PXP",factor_id:"factor",state:"verified",created_at:"fixture"};
describe("credential text export",()=>{
  it("exports account, unchanged password and new key using three hyphens",()=>{
    const text=credentialText([result],()=>" pass--word! ");
    expect(text).toBe("a@example.com--- pass--word! ---JBSWY3DPEHPK3PXP\r\n");
    expect(parseSingle(text).credential?.password).toBe(" pass--word! ");
  });
  it("exports only verified results",()=>expect(credentialText([result,{...result,id:"pending",state:"enrollment_pending"}],()=>"p").split("\r\n").filter(Boolean)).toHaveLength(1));
  it("never substitutes an empty or unknown password",()=>expect(()=>credentialText([result],()=>undefined)).toThrow("粘贴"));
  it("exports the saved password after the original page memory is gone",()=>{
    const restored=JSON.parse(JSON.stringify({...result,password:" saved-password! "}));
    expect(credentialText([restored])).toBe("a@example.com--- saved-password! ---JBSWY3DPEHPK3PXP\r\n");
  });
  it("does not label incomplete changes successful",()=>expect(()=>credentialText([{...result,state:"enabled_unverified"}],()=>"p")).toThrow("暂无"));
  it("rejects a newline in a password instead of corrupting result rows",()=>expect(()=>credentialText([result],()=>"p\nword")).toThrow("换行"));
});
