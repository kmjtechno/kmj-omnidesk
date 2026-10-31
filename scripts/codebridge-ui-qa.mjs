// Explicit opt-in, project-scoped CodeBridge visual QA runner.
// Does not fetch/upload screenshots, change system settings, or accept arbitrary
// executable/script names. Requires an interactive Windows desktop for capture.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const evidence = path.join(root, "artifacts", "native-ui");
const approvedReference = path.join(root, "docs", "design", "locked-main-app-1419x611.png");
const referenceSha =
  "281f0b5921b69e68ee16a7a6f52a02f5d9b3a9588e54378cc477f20d151a1948";
const commands = Object.freeze({
  capture: "windows_native_visual_smoke.ps1",
  compare: "windows_visual_compare.ps1",
  accessibility: "windows_accessibility_smoke.ps1",
});

function refusal(code, explanation) {
  process.stderr.write(JSON.stringify({ status: "BLOCKED", code, explanation }) + "\n");
  process.exitCode = 1;
}

const variant = process.argv[2];
if (process.argv.length !== 3 || !Object.hasOwn(commands, variant)) {
  refusal("UNAPPROVED_VARIANT", "Use capture, compare or accessibility with no other arguments.");
} else if (process.platform !== "win32") {
  refusal("WINDOWS_REQUIRED", "Live desktop QA must run on an authorized Windows workstation.");
} else {
  const script = path.join(root, "scripts", commands[variant]);
  const executable = path.join(root, "target", "release", "omnidesk-desktop.exe");
  if (!fs.existsSync(script)) {
    refusal("SCRIPT_MISSING", "The approved UI QA implementation does not exist in this checkout.");
  } else if (variant !== "compare" && !fs.existsSync(executable)) {
    refusal("DESKTOP_BINARY_MISSING", "Build the native release executable before running live QA.");
  } else if (variant === "compare" && !fs.existsSync(approvedReference)) {
    refusal(
      "LOCKED_REFERENCE_MISSING",
      "Place the exact approved 1419x611 image in docs/design/locked-main-app-1419x611.png.",
    );
  } else if (
    variant === "compare" &&
    createHash("sha256").update(fs.readFileSync(approvedReference)).digest("hex") !== referenceSha
  ) {
    refusal("LOCKED_REFERENCE_HASH_MISMATCH", "Only the owner-approved reference is allowed.");
  } else {
    fs.mkdirSync(evidence, { recursive: true });
    // Commands and arguments are hardcoded; no network or arbitrary shell input.
    const args = ["-NoProfile", "-NonInteractive", "-File", script];
    if (variant === "capture") {
      args.push("-BinaryPath", executable, "-OutputDirectory", evidence);
    } else if (variant === "compare") {
      args.push(
        "-ReferencePath", approvedReference,
        "-CandidatePath", path.join(root, "artifacts", "locked-dashboard.png"),
        "-OutputPath", path.join(evidence, "visual-comparison.json"),
      );
    } else {
      args.push("-BinaryPath", executable, "-OutputPath", path.join(evidence, "accessibility.json"));
    }
    const run = spawnSync("powershell.exe", args, {
      cwd: root,
      shell: false,
      timeout: 120_000,
      maxBuffer: 1024 * 1024,
      encoding: "utf8",
      windowsHide: true,
    });
    let verificationIssue = null;
    if (variant === "capture" && run.status === 0) {
      const receiptPath = path.join(evidence, "native-ui-smoke.json");
      try {
        const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8").replace(/^\uFEFF/, ""));
        if (
          receipt.evidence_type !== "real_windows_native_window" ||
          !receipt.process_started ||
          !receipt.title_verified ||
          receipt.screenshot_state !== "CAPTURED_FROM_RUNNING_APP"
        ) {
          verificationIssue = "CAPTURE_NOT_VERIFIED";
        }
      } catch {
        verificationIssue = "CAPTURE_RECEIPT_MISSING";
      }
    }
    if (run.error || run.status !== 0 || verificationIssue) {
      refusal(
        verificationIssue ?? "VISUAL_QA_FAILED",
        run.error ? run.error.code : "Windows QA did not produce independently verified local evidence.",
      );
    } else {
      process.stdout.write(
        JSON.stringify({
          status: "COMPLETED",
          variant,
          evidenceDirectory: "artifacts/native-ui",
          localOnly: true,
          designApproved: false,
          liveRemoteSessionVerified: false,
        }) + "\n",
      );
    }
  }
}
