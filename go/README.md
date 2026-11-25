# LovelyHawk Go 迁移：离线证据复验

当前 Rust/Tauri 桌面端仍是正式入口。本目录是第一批 Go 迁移：用独立 CLI 核对现有桌面端导出的留证包，不改写 Rust 实现、导出格式或案件库。需要 Go 1.25 或更新版本，仅依赖标准库。

```sh
cd go
go test ./...
go build ./cmd/lovelyhawk-evidence
./lovelyhawk-evidence verify "/path/to/LovelyHawk-evidence-UUID"
```

Windows 使用同样的 Go 命令，运行时将程序名换成 `lovelyhawk-evidence.exe`。

CLI 读取 `lovelyres-file-evidence/v1` 的 `manifest.json`，支持普通文件、PCAP 和 Pod 文件。它流式核对本地样本的字节数与 SHA-256：一致时输出 JSON 并退出 0；不一致退出 1；无清单、格式不支持或读取失败退出 2。原始样本不会被输出、执行或改写，也不连接任何目标。

请对已完成采集、不会被并发修改的本地副本执行。摘要一致只说明当前字节与清单一致，不证明清单真实性、远端状态或证据来源。此阶段不替代桌面端，并未迁移采集链路。后续可先把案件报告、时间线等离线能力分批迁移，依次记录与现有导出格式的兼容性和验证结果。
