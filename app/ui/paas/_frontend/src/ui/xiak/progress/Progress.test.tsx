import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Progress } from "./Progress";

afterEach(cleanup);

describe("Progress", () => {
  it("announces unknown progress without inventing a percentage", () => {
    render(<Progress aria-label="Opening users" />);
    const progress = screen.getByRole("progressbar", { name: "Opening users" });
    expect(progress.hasAttribute("aria-valuenow")).toBe(false);
    expect(progress.hasAttribute("value")).toBe(false);
  });

  it("retains native determinate progress for real task values, including zero", () => {
    const view = render(<Progress aria-label="Deployment" value={0} max={10} />);
    const progress = screen.getByRole("progressbar", { name: "Deployment" }) as HTMLProgressElement;
    expect(progress.value).toBe(0);
    expect(progress.max).toBe(10);
    view.rerender(<Progress aria-label="Deployment" value={7} max={10} />);
    expect(progress.value).toBe(7);
  });
});
