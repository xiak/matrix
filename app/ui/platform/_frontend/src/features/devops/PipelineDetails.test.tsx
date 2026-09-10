import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, expect, it, vi } from "vitest";
import type { Pipeline, RepositoryBinding, SourceConnection } from "@/api/devopsContract";
import { ApiError } from "@/api/client";
import messages from "@/i18n/messages/en.json";
import { UnsavedChangesProvider } from "@ui/xiak";
import { PipelineDetails } from "./PipelineDetails";

const session = vi.hoisted(() => ({ api: { canMutate: true, read: vi.fn(), fetch: vi.fn(), command: vi.fn() } }));
vi.mock("./DevopsApi", () => ({ useDevopsApi: () => session.api, pipelineDraft: (repositoryBindingId: string) => ({ repositoryBindingId }) }));
afterEach(() => { cleanup(); vi.clearAllMocks(); vi.useRealTimers(); });

function fixtures() {
  const observedAt = new Date().toISOString();
  const metadata = { id: "pipeline-a", name: "Pipeline A", resourceVersion: 1, scope: { tenantId: "organization-a" }, createdAt: observedAt, updatedAt: observedAt };
  const value: Pipeline = { apiVersion: "devops.matrix.xiak.com/v1", kind: "Pipeline", metadata, projectId: "project-a", draft: { contentDigest: "sha256:" + "a".repeat(64), spec: { repositoryBindingId: "binding-a", dependencyEgress: "NONE", reporterPolicy: "CHANGE_CHECK_V1", triggerPolicy: "CHANGE", verificationProfile: "GO_1_26_OFFLINE_V1" } } };
  const binding: RepositoryBinding = { apiVersion: value.apiVersion, kind: "RepositoryBinding", metadata: { ...metadata, id: "binding-a" }, contentDigest: value.draft.contentDigest, projectId: value.projectId, spec: { sourceConnectionId: "connection-a", externalRepositoryId: "repository-a", repositoryPath: "matrix/platform", trustedDefaultBranch: "main" }, status: { observedAt, health: "READY", reason: "OBSERVED" } };
  const connection: SourceConnection = { apiVersion: value.apiVersion, kind: "SourceConnection", metadata: { ...metadata, id: "connection-a" }, spec: { adapterId: "source-adapter-gitea-v1", endpointOrigin: "https://git.example", fetchCredentialRef: "fetch-a", reportCredentialRef: "report-a", webhookSecretRef: "webhook-a" }, status: { observedAt, health: "READY", reason: "OBSERVED" } };
  session.api.read.mockImplementation(async (kind: string) => kind === "RepositoryBinding" ? binding : connection);
  return value;
}
const view = (value: Pipeline) => <NextIntlClientProvider locale="en" messages={messages}><UnsavedChangesProvider><PipelineDetails value={value} update={() => {}} /></UnsavedChangesProvider></NextIntlClientProvider>;

it("invalidates previous healthy evidence immediately when a dependency reread fails", async () => {
  const value = fixtures();
  const page = render(view(value));
  await waitFor(() => expect((screen.getByRole("button", { name: messages.Devops.activate }) as HTMLButtonElement).disabled).toBe(false));
  session.api.read.mockRejectedValue(new ApiError("DENIED"));
  page.rerender(view({ ...value, metadata: { ...value.metadata, resourceVersion: 2 } }));
  expect((screen.getByRole("button", { name: messages.Devops.activate }) as HTMLButtonElement).disabled).toBe(true);
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect((screen.getByRole("button", { name: messages.Devops.activate }) as HTMLButtonElement).disabled).toBe(true);
});

it("expires the local source evidence without polling or rerendering the shell", async () => {
  vi.useFakeTimers();
  const value = fixtures();
  render(view(value));
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect((screen.getByRole("button", { name: messages.Devops.activate }) as HTMLButtonElement).disabled).toBe(false);
  await act(async () => { vi.advanceTimersByTime(120001); });
  expect((screen.getByRole("button", { name: messages.Devops.activate }) as HTMLButtonElement).disabled).toBe(true);
  expect(session.api.read).toHaveBeenCalledTimes(2);
});
