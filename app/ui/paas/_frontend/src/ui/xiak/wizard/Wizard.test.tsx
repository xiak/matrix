import { useState } from "react";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { Button, Wizard } from "../index";

afterEach(cleanup);

it("focuses the current heading, permits completed steps only and uses the form submit action", async () => {
  const submitted = vi.fn();
  function Example() {
    const [step, setStep] = useState(0);
    const steps = [{ id: "identity", label: "Identity" }, { id: "review", label: "Review" }];
    return <Wizard label="Create identity" steps={steps} currentStep={step} onStepChange={setStep} title={steps[step]!.label} onSubmit={(event) => { event.preventDefault(); submitted(); setStep(1); }} actions={<Button type="submit">Next</Button>}><input aria-label="Name" /></Wizard>;
  }
  const user = userEvent.setup();
  render(<Example />);
  expect(document.activeElement).toBe(screen.getByRole("heading", { name: "Identity" }));
  expect((screen.getByRole("button", { name: "Review" }) as HTMLButtonElement).disabled).toBe(true);
  await user.type(screen.getByLabelText("Name"), "Example{Enter}");
  expect(submitted).toHaveBeenCalledTimes(1);
  expect(document.activeElement).toBe(screen.getByRole("heading", { name: "Review" }));
  await user.click(screen.getByRole("button", { name: "Identity" }));
  expect(document.activeElement).toBe(screen.getByRole("heading", { name: "Identity" }));
  expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("Example");
});

it("disables step navigation and form fields while saving", () => {
  render(<Wizard label="Create" steps={[{ id: "one", label: "First" }, { id: "two", label: "Second" }]} currentStep={1} title="Second" onStepChange={vi.fn()} busy onSubmit={vi.fn()} actions={<Button disabled>Saving</Button>}><input aria-label="Name" /></Wizard>);
  expect((screen.getByRole("button", { name: "First" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByLabelText("Name").closest("fieldset")?.disabled).toBe(true);
});
