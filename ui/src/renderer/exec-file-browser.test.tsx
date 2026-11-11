import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { DockerFileDialog, type DockerFileApi } from "./DockerFileDialog";
import { ExecFileBrowser, modeFlags, sizeText, visibleName } from "./ExecFileBrowser";
import { PodFileDialog } from "./PodFileDialog";

describe("what the file browser shows about an entry", () => {
  it("makes control characters visible, so one name cannot pass for two rows", () => {
    expect(visibleName("plain.conf")).toBe("plain.conf");
    expect(visibleName("two\nlines")).toBe("two\\nlines");
    expect(visibleName("tab\there")).toBe("tab\\there");
    expect(visibleName("bell\u0007")).toBe("bell\\x07");
    expect(visibleName("中文名")).toBe("中文名");
  });

  it("marks bits worth a second look and nothing else", () => {
    expect(modeFlags({ mode: "644", kind: "file" })).toBeNull();
    expect(modeFlags({ mode: "4755", kind: "file" })).toContain("setuid");
    expect(modeFlags({ mode: "2755", kind: "file" })).toContain("setgid");
    expect(modeFlags({ mode: "666", kind: "file" })).toContain("所有人可写");
    // /tmp is world-writable by design; the sticky bit is what makes that safe.
    expect(modeFlags({ mode: "1777", kind: "directory" })).toBeNull();
    expect(modeFlags({ mode: "777", kind: "directory" })).toContain("所有人可写");
    // A link's own bits mean nothing.
    expect(modeFlags({ mode: "777", kind: "symlink" })).toBeNull();
    expect(modeFlags({ mode: null, kind: "file" })).toBeNull();
  });

  it("writes sizes the way people read them, and an unknown as a dash", () => {
    expect(sizeText(null)).toBe("—");
    expect(sizeText(512)).toBe("512 B");
    expect(sizeText(2_048)).toBe("2.0 KiB");
    expect(sizeText(50 * 1024 * 1024)).toBe("50 MiB");
  });
});

describe("the browser before its first listing arrives", () => {
  it("offers the places a responder looks first, and says it is listing", () => {
    const html = renderToStaticMarkup(
      <ExecFileBrowser list={vi.fn(async () => ({}))} fileActions={[]} initialPath="/etc" />,
    );
    for (const place of ["/etc", "/tmp", "/var/tmp", "/dev/shm", "/root", "/var/log"]) {
      expect(html).toContain(`>${place}</button>`);
    }
    expect(html).toContain("正在列出 /etc");
    expect(html).toContain('data-testid="exec-browser-path"');
    expect(html).toContain("最近修改在前");
  });

  it("drops a listing that answers after the operator moved on", () => {
    const source = readFileSync(new URL("./ExecFileBrowser.tsx", import.meta.url), "utf8");
    expect(source).toContain("if (request !== requestRef.current) return;");
    expect(source).not.toContain("dangerouslySetInnerHTML");
  });

  it("renders directory actions on openable directories and the current-directory action in the path bar", () => {
    const source = readFileSync(new URL("./ExecFileBrowser.tsx", import.meta.url), "utf8");
    expect(source).toContain("entry.kind === \"directory\" && entry.openable ? directoryActions.map");
    expect(source).toContain("currentDirectoryAction.testId");
    // Directory actions default to none: existing callers change nothing.
    expect(source).toContain("directoryActions = []");
  });

  it("uses only theme tokens for colour", () => {
    const css = readFileSync(new URL("./exec-file-browser.css", import.meta.url), "utf8");
    expect(css).not.toMatch(/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/iu);
    expect((css.match(/var\(--[a-z0-9-]+\)/gu) ?? []).length).toBeGreaterThan(20);
  });
});

describe("the dialogs that hold it", () => {
  const dockerApi: DockerFileApi = {
    readDockerContainerFile: vi.fn(async () => ({})),
    planDockerFileWrite: vi.fn(async () => ({})),
    planDockerFileCopy: vi.fn(async () => ({})),
    confirmDockerContainerAction: vi.fn(async () => ({})),
    executeDockerContainerAction: vi.fn(async () => ({})),
    cancelDockerContainerAction: vi.fn(async () => ({})),
    listDockerContainerDirectory: vi.fn(async () => ({})),
  };

  it("opens the container's files on browsing, with editing and copying a tab away", () => {
    const html = renderToStaticMarkup(
      <DockerFileDialog api={dockerApi} bindingHandle="b" snapshotHandle="s" containerHandle="c"
        containerName="web" onClose={() => undefined} />,
    );
    expect(html).toContain('data-testid="exec-file-browser"');
    expect(html).toMatch(/data-testid="docker-file-mode-browse"[^>]*>浏览</u);
    expect(html).toContain("编辑文件");
    expect(html).toContain("复制文件");
    expect(html).not.toContain("handle");
  });

  it("offers 取回扫描 on the current directory only when the api carries localScan", () => {
    const withScan = renderToStaticMarkup(
      <DockerFileDialog api={{ ...dockerApi, localScan: vi.fn(async () => null) }}
        bindingHandle="b" snapshotHandle="s" containerHandle="c"
        containerName="web" onClose={() => undefined} />,
    );
    expect(withScan).toContain('data-testid="docker-browser-scan-current"');
    expect(withScan).toContain("取回此目录扫描");
    const without = renderToStaticMarkup(
      <DockerFileDialog api={dockerApi} bindingHandle="b" snapshotHandle="s" containerHandle="c"
        containerName="web" onClose={() => undefined} />,
    );
    expect(without).not.toContain("取回此目录扫描");
  });

  it("keeps the docker dialog inert while the nested scan dialog is open and passes handles, not a program", () => {
    const source = readFileSync(new URL("./DockerFileDialog.tsx", import.meta.url), "utf8");
    // The nested dialog swallows Escape: the file dialog must not close under it.
    expect(source).toContain('|| scan !== null) return;');
    expect(source).toContain("discard.dialog !== null || scan !== null ? true : undefined");
    // The container stays a handle triple; the fetched path is inside it.
    expect(source).toContain("containerScanTransport(api as LocalScanApi, bindingHandle, snapshotHandle, containerHandle, scan.path)");
    expect(source).toContain('originLabel: `容器：${containerName}`');
    // File and directory rows both get the scan action; a directory row keeps entering too.
    expect(source).toContain('testId: "docker-browser-scan"');
    expect(source).toContain('testId: "docker-browser-scan-directory"');
  });

  it("opens a pod's files read-only, and says why it is read-only", () => {
    const html = renderToStaticMarkup(
      <PodFileDialog api={{ listKubernetesPodDirectory: vi.fn(async () => ({})), readKubernetesPodFile: vi.fn(async () => ({})), podFileEvidence: vi.fn(async () => null) }}
        bindingHandle="b" snapshotHandle="s" rowHandle="r" podName="payments/ledger-1" container={null} onClose={() => undefined} />,
    );
    expect(html).toContain("payments/ledger-1");
    expect(html).toContain('data-testid="exec-file-browser"');
    expect(html).toContain("只读");
    expect(html).toContain("Pod 默认容器");
    expect(html).toContain("部署清单");
    // Nothing is written into the pod; keeping a file as evidence copies it out.
    expect(html).not.toMatch(/写入|上传|编辑/u);
    expect(html).toContain("留证");
    // A chosen container is named where the files come from.
    const sidecar = renderToStaticMarkup(
      <PodFileDialog api={{ listKubernetesPodDirectory: vi.fn(async () => ({})), readKubernetesPodFile: vi.fn(async () => ({})), podFileEvidence: vi.fn(async () => null) }}
        bindingHandle="b" snapshotHandle="s" rowHandle="r" podName="payments/ledger-1" container="sidecar" onClose={() => undefined} />,
    );
    expect(sidecar).toContain("payments/ledger-1 · 容器 sidecar");
    expect(sidecar).toContain("容器 sidecar 里的文件");
    expect(sidecar).not.toContain("Pod 默认容器");
  });
});
