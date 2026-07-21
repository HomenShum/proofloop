import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { verifyEaseProof } from "../src/easeProof";
import { verifyProofReceiptEnvelopeFile } from "../src/proofReceipt";

const roots: string[] = [];
afterEach(() => roots.splice(0).forEach((root) => rmSync(root, { recursive: true, force: true })));
const sha256 = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const writeJson = (path: string, value: unknown) => { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`); };

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "proofloop-ease-"));
  roots.push(root);
  const evidence = join(root, "proof", "ease", "latest");
  const png = Buffer.from("png-evidence");
  const candidate = Buffer.from("candidate-archive");
  const commit = "a".repeat(40);
  const hash = "b".repeat(64);
  const screenshotPath = join(evidence, "browser", "screenshots", "arrival.png");
  mkdirSync(dirname(screenshotPath), { recursive: true });
  writeFileSync(screenshotPath, png);
  writeFileSync(join(evidence, "candidate.tar.gz"), candidate);
  const browser: Record<string, unknown> = {
    schemaVersion: "nodekit.browser-certification/v1",
    certified: false,
    missingStates: ["fresh_human"],
    screenshots: [{
      path: "browser/screenshots/arrival.png",
      pngSha256: sha256(png),
      generatedCandidateCommit: commit,
      applicationHash: hash,
      configHash: hash,
      nodekitSourceHash: hash,
      consoleErrors: 0,
      failedRequests: 0,
      horizontalOverflowPx: 0,
      mojibakeDetected: false,
    }],
  };
  browser.manifestSha256 = sha256(JSON.stringify(browser));
  writeJson(join(evidence, "browser", "screenshot-manifest.json"), browser);
  const manifest: Record<string, unknown> = {
    schemaVersion: "nodekit.ease-proof-run/v1",
    runId: "ease_test",
    startedAt: "2026-07-21T00:00:00.000Z",
    generatedAt: "2026-07-21T00:00:01.000Z",
    durationMs: 1000,
    nodekitSourceHash: hash,
    base: { applicationHash: hash, configHash: hash, candidateCommit: commit, browserManifestDigest: browser.manifestSha256, phases: [{ name: "scaffold", durationMs: 10, exitCode: 0 }] },
    submissionReady: false,
    submissionBlockers: ["freshHumanUsability"],
  };
  manifest.receiptDigest = sha256(JSON.stringify(manifest));
  writeJson(join(evidence, "manifest.json"), manifest);
  return { evidence, root, screenshotPath };
}

describe("NodeKit EaseProof verifier", () => {
  it("verifies local evidence integrity while keeping ease certification blocked", () => {
    const { root } = fixture();
    const output = join(root, "proof", "ease", "latest", "proofloop-receipt.json");
    const result = verifyEaseProof({ root, manifestPath: "proof/ease/latest/manifest.json", outputPath: output });
    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.easeCertified).toBe(false);
    expect(result.warnings).toContain("Evidence integrity may pass, but NodeKit Ease is not certified and submission remains blocked.");
    expect(verifyProofReceiptEnvelopeFile({ root, filePath: output }).ok).toBe(true);
  });

  it("fails after screenshot bytes are changed", () => {
    const { root, screenshotPath } = fixture();
    writeFileSync(screenshotPath, "tampered");
    const result = verifyEaseProof({ root, manifestPath: "proof/ease/latest/manifest.json" });
    expect(result.ok).toBe(false);
    expect(result.errors).toContain("screenshot digest mismatch: browser/screenshots/arrival.png");
  });
});
