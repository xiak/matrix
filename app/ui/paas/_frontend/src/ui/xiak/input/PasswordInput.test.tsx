import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PasswordInput } from "./PasswordInput";

afterEach(cleanup);
describe("PasswordInput", () => {
  it("reveals and hides a password without submitting the surrounding form", async () => {
    const user = userEvent.setup();
    const submit = vi.fn();
    render(<form onSubmit={submit}><label htmlFor="secret">Password</label>
      <PasswordInput autoComplete="current-password" capsLockLabel="Caps Lock on" hideLabel="Hide" id="secret"
        showLabel="Show" /></form>);
    const field = screen.getByLabelText("Password") as HTMLInputElement;
    await user.type(field, "Only-a-test-secret-49!");
    expect(field.type).toBe("password");
    await user.click(screen.getByRole("button", { name: "Show" }));
    expect(field.type).toBe("text");
    expect(field.value).toBe("Only-a-test-secret-49!");
    expect(screen.getByRole("button", { name: "Hide" }).getAttribute("aria-pressed")).toBe("true");
    await user.click(screen.getByRole("button", { name: "Hide" }));
    expect(field.type).toBe("password");
    expect(field.autocomplete).toBe("current-password");
    expect(submit).not.toHaveBeenCalled();
  });
  it("announces Caps Lock and preserves caller descriptions", () => {
    render(<PasswordInput aria-label="Password" aria-describedby="policy" capsLockLabel="Caps Lock on" hideLabel="Hide" showLabel="Show" />);
    const input = screen.getByLabelText("Password");
    fireEvent.keyUp(input, { key: "A", modifierCapsLock: true });
    const warning = screen.getByRole("status");
    expect(input.getAttribute("aria-describedby")).toBe(`policy ${warning.id}`);
    fireEvent.blur(input);
    expect(screen.queryByRole("status")).toBeNull();
    expect(input.getAttribute("aria-describedby")).toBe("policy");
  });
});
