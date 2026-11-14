# LovelyHawk 长期产品与验证进度

## 2026-11-13 day5 运维 writeup 对照与进程活动监视规划

材料：`day5运维wp.pdf`（公网 Linux 主机被入侵后的加固与后门清理，8 个检查点；题目约束：不改 root 口令与公钥、不改 SSH/Web 端口、不用防火墙拦 SSH/Web、部分 Web 在 Docker 中、**配置文件里的持久化命令必须删除而不是注释**）。材料不入库。以下状态均为对照现有代码的结论，未在该题环境实测（NOT_RUN）。

### 逐项对照

| 检查点 | 检测 | 处置 | 缺口 |
| --- | --- | --- | --- |
| 1 `/etc/crontab` 后门行与 `/root/.cr` | 已有（Cron 页、`persistence-chain`） | 已有（行级删除） | `/etc/crontab` 与 spool 单行已可行级删除（一次性容器实验核对）；`/root/.cr` 不在放行清单内，仍无处置入口 |
| 2 `lsmod` 可见的恶意模块 | 已有（内核模块页、`system-lkm`） | 部分（复活点行级删除：profile/init.d/cron.d/systemd Exec/modprobe.d/`/etc/modules*`；`rmmod` 待决策） | `system-module-revival-points` 已汇总全部复活位置并给出重启复核提示；已加载模块仍无卸载动作（待决策） |
| 3 自隐藏模块 | 已有（`/sys/module` 与 `/proc/modules` 差集、kallsyms 标签） | 部分（删复活点后重启，条目汇总与开机时间复核） | 隐藏模块仍无法按名卸载；重启后需人工重跑条目复核（条目含本次开机时间），不做自动复核 |
| 4 `/etc/profile`、`/etc/init.d/cron` 中的 `insmod` | 已有（启动钩子判定） | 已有（行级删除，init.d 写后 `sh -n`） | `/etc/profile` 与 `/etc/init.d/*` 的单行/范围已可删除（容器实验核对）；整脚本移出启动序列的连带问题仍在 |
| 5 `/etc/init.d/ssh` 中的恶意代码段 | 已有（特征词扫描 + 软件包摘要比对） | 已有（连续行范围删除） | `startup-init-package-verify` 对 dpkg（conffiles 优先、md5sums 兜底）、apk（`apk audit --full`）与 rpm（`rpm -qf`/`rpm -Vf`）均已核对（Debian/Alpine/Rocky 一次性容器）；比对依赖目标上包数据库，数据库被改写时结果不可信，未记录摘要的脚本只能“无法判断” |
| 6 `/root/.vimrc` 的 `set modeline` | 已有（`persistence-editor-config`，需关注级） | 已有（行级删除放行 `.vimrc`/`.exrc`/`.nanorc`/`.emacs` 与 `/etc/vim*`） | `~/.vim/plugin` 等子树文件不在行级删除放行内（走权限隔离）；modeline 判定为需关注而非已入侵 |
| 7 xinetd `server = /bin/bash`（10005 端口） | 已有（inetd/xinetd 采集与 shell 服务判定） | 已有（隔离 `/etc/xinetd.d/<服务>` + 重载 + 端口复核 + 撤销，容器端到端 33/33 与桌面 13/13） | systemd reload 分支容器内不可达未实测；`/etc/inetd.conf` 行可删但 inetd 重载未实现，需人工重载 |
| 8 SUID 后门文件 | 已有（包归属、GTFOBins） | 已有 | 无（移除 SUID 位、权限隔离） |

### 待补能力（按优先级）

1. **行级删除（留证后删除，不是注释）**。现有唯一的行级动作是“注释此行”，题目与真实清理都可能要求彻底移除。
   - 范围：`/etc/crontab`、`/etc/cron.d/*`、cron spool、`/etc/profile`、`/etc/profile.d/*.sh`、`/etc/bash.bashrc`、`/etc/bashrc`、各用户 `.bashrc`/`.profile`/`.bash_profile`、`/etc/rc.local`、`/etc/init.d/*`。
   - 做法：计划绑定文件摘要、行号与该行原文；执行前重读一致才写；整文件先备份；写后独立回读确认该行不存在且其余内容逐字节不变；可撤销（放回备份前核对文件未再变化）。init.d 与 rc.local 写后做 `sh -n` 语法检查，失败自动放回。
   - 多行代码段（检查点 5）：允许选择连续行范围，预览显示将删除的全部内容；不做自动识别“恶意函数边界”。
   - 界面同时保留“注释此行”，并说明两者区别（注释保留痕迹便于回看，删除才满足“彻底清除”）。
2. **编辑器配置持久化检测**（唯一的检测盲区）。新增工作台条目：`/root` 与各用户主目录下 `.vimrc`、`.vim/`（`plugin/`、`autoload/`、`after/`）、`.exrc`、`.config/nvim/`、`/etc/vim/vimrc*`、`.emacs`、`.emacs.d/init.el`、`.nanorc`；标注 `set modeline`/`modelines=`、`autocmd`、`:!`/`system(`/`:py`、`exrc` 开启，以及指向可写目录的 `source`。说明：`modeline` 本身是合法选项，是否可利用取决于 vim 版本，判定为“需关注”而不是“已被入侵”。处置走上面的行级删除。
3. **xinetd/inetd 服务处置**。移除（实为隔离到备份位置）`/etc/xinetd.d/<服务>` 或把 `disable = no` 改为 `yes`；随后重新加载 xinetd，并以监听表回读确认端口不再监听；撤销放回原文件并再次加载。xinetd 未运行时只改文件并明确说明“未加载，无需重载”。
4. **init 脚本与软件包原件比对**。对 `/etc/init.d/*` 逐个取包归属与包内摘要（`dpkg --verify`/`rpm -V`，conffile 单独说明可能被管理员合法修改）；不归属任何包、或与包内不一致的脚本标出，并在可取得原件时显示差异行。用于补特征词扫描覆盖不到的任意代码段。
5. **已加载内核模块的卸载**（待决策）。`rmmod` 对正常可见的模块可行，但卸载正在挂钩内核的模块可能直接导致崩溃，自隐藏模块则根本无法按名卸载。默认决策：先不提供一键卸载；改为提供“模块清理清单”——列出所有复活点（启动文件、init 脚本、`modules-load.d`、`/etc/modules`、cron、systemd unit）及其处置状态，全部清完后提示可以重启，重启后自动复核 `/sys/module` 差集与 kallsyms。若后续决定做卸载，必须单独确认、说明崩溃风险、卸载后复核，不进批量操作。
6. **反取证提示**。`dmesg -c` 清空内核环形缓冲区、日志文件被截断为 0 字节、`history -c` 与 `HISTFILE=/dev/null` 等，在日志类条目中给出“日志可能已被清理，缺失不代表没有发生”的提示。
7. **题目类约束的提醒**（小项）。处置对话框在涉及 SSH/Web 端口、防火墙拦截 SSH/Web、root 口令与 `authorized_keys` 时，已有的影响说明里补一句“可能影响远程接入或对外业务”；不做针对比赛的专用模式。

### 实施进度（2026-11-13 起）

- 行级删除（留证后删除，不是注释）：core `line_delete.rs` 放行清单限 `/etc/crontab`、`/etc/cron.d/*`、cron spool、`/etc/profile`、`/etc/profile.d/*.sh`、`/etc/bash.bashrc`、`/etc/bashrc`、`/root` 与各用户主目录 `.bashrc`/`.profile`/`.bash_profile`、`/etc/rc.local`、`/etc/init.d/*`；逐字节范围删除支持 CRLF、无尾换行、非 UTF-8 与首尾行，单次至多 200 行，预览净化控制字符并按行截断。计划绑定路径、原文件 SHA-256、行号范围与原文，预览后文件变化按 `line-stale` 拒绝；整份文件先备份到同目录 `.lovelyres-backups/`，`AtomicWriteIfMatch` 原子写入保留权限与属主，写后独立回读文件摘要验证（既证明该行不存在、也证明其余字节不变）；撤销仅在文件仍为删除后内容时放回备份，放回后再回读比对原摘要。init.d 与 rc.local 写后 `sh -n`：原文件通过而写后不通过则自动放回，原文件本就不通过或目标无 sh 时在计划与回执中注明“未做语法检查”。backend 新增 `emergency-command.path.lines`（有界预览，摘要留在后端不发给页面）与 `emergency-command.path.plan-lines`（计划列出将被删除的全部行），复用既有确认/执行/取消/撤销链路；`path.plan` 与 `path.batch.plan` 对该动作明确拒绝；path DTO 增加 `lineEditable`，位置/类型/大小/范围/过期分别按 `emergency-path-line-*` 码拒绝。主机全景 shell 配置行新增“删除此行”（`shell.delete-line`），与“注释此行”并存，计划文案区分两者。
- 界面：应急命令路径菜单在放行路径上显示“删除指定行…”，`EmergencyPathLinesDialog` 提供行列表（单击单行、Shift 选连续范围、行号直输、截断提示、纯键盘可达），计划页列出将被删除的全部行且默认焦点不在危险按钮，回执带 10 分钟内一次撤销。
- 验证：core `line_delete` 12 项、`shell_line` 2 项；backend `emergency_` 43 项（含拒绝映射、delete-lines 往返、绑定/窗口隔离）与 `system_info` 15 项；desktop 桥白名单 5 项；backend/desktop `clippy -D warnings` 干净；`pnpm ui:check` 151 个测试文件 1301 项全过，UI 构建通过（过程中修正：预览句柄在返回选行时被清导致无法重新生成计划、六处契约/夹具未跟上新字段）。Debian 一次性容器端到端 66/66（`tools/lab/probe-emergency-path-lines.mjs`，输出 `tmp/lab_day5_line_delete.txt`，证据 `target/desktop-debug/line-delete-*/report.json`）：单行与 6 行块删除后独立回读逐字节一致；预览后、计划后被改分别按码拒绝且文件不动；已用计划不可再执行；撤销恢复原始 SHA-256、文件再被改时撤销被拒且不覆盖；删 `fi` 触发 `sh -n` 失败并自动逐字节放回；原文件本就不通过时按计划与回执“未做语法检查”放行；放行外路径、`cron.d` 点文件、软链接、越界范围分别按 `line-location`/`line-kind`/`line-range` 拒绝；非 root 属主 0640 文件删除后权限与属主不变；`path.plan`/`path.batch.plan` 对 delete-lines 按 `emergency-path-batch-action` 拒绝。调试构建桌面端到端 13/13（`tools/lab/probe-ui-path-lines.mjs`，输出 `tmp/lab_day5_line_delete_ui.txt`，证据 `target/desktop-debug/ui-line-delete-*/report.json` 与 5 张截图）：命令工作台 → 关键文件权限 → `/etc/crontab` 右键菜单“删除指定行…” → 纯键盘选中末行 → 生成计划 → 确认删除 → 容器内独立 sha256 核对行已删 → 撤销后逐字节还原，无渲染异常与控制台错误。
- NOT_RUN：`probe-system-info-mutations.mjs` 已补 `shell.delete-line` 用例（删除而非注释、行数少一、其余字节不动、权限不变），但该探针需 WSL `lab-*` 靶机，本机无 Ubuntu 发行版，未能运行；目录拒绝与软链接同走“非普通文件”检查（`line-kind`），工作台输出不提供目录路径句柄，仅单测覆盖；`/etc/rc.local` 与 `/etc/rc.d/rc.local` 未在实验中驱动（语法门与 init.d 同一分支）；`sudo -n` 路径、VM/实机验证待补。
- 只读检测缺口（待补能力 2、4、6、7）与一处修正：新增目录条目 `persistence-editor-config`（/etc/passwd 各主目录 ≤200 个的 `.vimrc`/`.exrc`/`.nanorc`/`.emacs`/`.emacs.d/init.el`/`.config/nvim/init.*` 与 `.vim/{plugin,autoload,after,ftplugin}` 子树 ≤200 文件/层深 3，加 `/etc/vim*`、`/etc/virc`、`/etc/nanorc`；头部打印属主/权限/时间，匹配行 `路径:行号` ≤50 行/文件；全部缺失时明示“未发现编辑器配置文件”）配 `editor_config_hook` 行规则（注释与引号内文本不标记；`modeline`/`exrc`/`autocmd`/`:!`/解释器调用/指向可写目录的 source-include 标“需关注”，文案注明 modeline 是合法选项）；`startup-init-package-verify`（dpkg：conffiles 摘要优先、md5sums 兜底，不一致且缓存有同版本 `.deb` 时流式 `dpkg-deb|tar|diff` 输出 `路径:当前行号:+内容` ≤40 行；apk：`apk info -W` 归属 + `apk audit --full`；rpm：`rpm -qf` + `rpm -Vf` 标记位；区分“一致/不一致/不属于任何软件包/无法判断”，文案注明数据库被改写则不可信）配 `init_script_package_mismatch` 行规则；`history_evasion` 行规则并入启动文件条目（`startup_hook_or_history_evasion`，覆盖 profile/rc/motd/user-rc 四个条目，`HISTCONTROL=ignorespace` 不标记）；`log-tamper-signs`（常见日志大小与 mtime-早于开机启发式、历史文件符号链接与“登录过却为空”、dmesg 最早记录 vs 开机 120 秒、journald 首条；凡标记行均以“日志可能已被清理，缺失不代表没有发生”结尾，发行版差异的不存在不标记）配 `log_tamper_sign` 行规则。处置侧：行级删除放行清单扩至 `/root` 与 `/home/<用户>` 的 `.vimrc`/`.exrc`/`.nanorc`/`.emacs` 及 `/etc/vim*`。影响说明（待补能力 7）：按类型化事实补固定句——出方向封禁 SSH 会话对端、断开本地 22 端口或 sshd 进程的 TCP 连接、停止/重启/禁用 `sshd`/`ssh` 单元补“可能影响远程接入或对外业务，请确认仍有其他接入方式。”；断开 80/443 端口或 Web 进程连接、停止/重启/禁用 `nginx`/`apache2`/`httpd`/`caddy`/`tomcat*` 单元补“可能影响对外业务。”；root 或当前 SSH 登录账户改口令补远程接入句。修正：行级删除写后 `sh -n` 因通道/执行错误（非退出码失败）无法运行时，同样先尽力放回原文件，再分别报“已放回/未能核实放回”的语法类拒绝，不再让已删文件留在原地。
- 验证：core `command_` 123 项、 `line_delete` 12 项、`system_info` 71 项、`account_password` 4 项、`firewall` 8 项；backend `emergency_` 41+25+25 项、`system_info` 15 项；目录条目经 `command_workbench::lab` 在 debian:12-slim、alpine:3.20 与 rockylinux:9-minimal 一次性容器各 24 例全过（`tmp/lab_day5_wave2.txt`）：`.vimrc` 的 `set modeline`/`autocmd`/`.vim/plugin` 命中，`nomodeline`/注释不标记；cron conffile 改行后报“不一致”且缓存 `.deb` 下按当前文件行号输出 `+` 差异行（独立 `grep -n` 复核 93/94 行一致），无归属脚本与未改脚本分别正确判定，alpine `apk audit --full` 报 `U` 不一致，Rocky 上 `/etc/init.d` 为指向 `rc.d/init.d` 的符号链接时解析实目录后比对，改动的包内脚本报“不一致”（`S.5....T.` 标记位）、植入脚本报“不属于任何软件包”；`/etc/profile` 的 `HISTFILE=/dev/null`/`unset HISTFILE` 标记、`ignorespace` 不标记；截断的 auth.log、wtmp 与符号链接 `.bash_history` 命中，`/var/log/secure` 不存在不标记。实验过程中修正：rockylinux:9-minimal 无 findutils/initscripts（lab 在每族容器先装 find、fixture 自装 initscripts）；`rpm -qf` 的“not owned”打到 stdout 导致 `perm-suid-ownership` 与 `persistence-unit-owner` 把无归属文件当已归属，已修正；`process-exe-path` 夹具改用 `sh` 副本以兼容 busybox applet 名与 Rocky coreutils 转接；podman 虚拟机辅助进程在容器内被 `process-hidden` 如实命中，该例在 redhat 族豁免“无线索”断言。端到端：`probe-emergency-path-lines.mjs` 扩出 `/root/.vimrc` 段落后 72/72（`tmp/lab_day5_wave2_probe.txt`，证据 `target/desktop-debug/line-delete-e3835796-*/report.json`）——编辑器条目给出 `lineEditable` 句柄，删 `set modeline` 独立回读逐字节核对。
- NOT_RUN：rpm 分支仅在 rockylinux:9-minimal 一次性容器核对（补齐 find/initscripts 后），Alma/openEuler 等其他 RPM 发行版与完整 RHEL 系 VM 未覆盖；`sh -n` 因通道/执行错误放回原文件的分支无法在无 SSH/SFTP 会话的单测中模拟，覆盖方式为代码走查 + `OPERATION_FAILURE_ADVICE` 文案断言，未做端到端注入；dmesg_restrict 与 journald 首条分支在 slim 容器内不可得（容器共享宿主内核、无 systemd 日志）；目录拒绝仍无工作台句柄可达；VM/实机与 `sudo -n` 路径未测。
- xinetd 服务处置与模块复活点清单（待补能力 3、5）与三处修正：core 新增 `xinetd_service.rs`——`/etc/xinetd.d/<安全名>`（名字含点号或以 `~` 结尾的按 xinetd 自身规则拒绝为“本就不加载”，符号链接按类型拒绝）、仅普通文件且 ≤ 托管上限；计划一次性探测文件摘要与属主、服务块（多 service 块、`disable`/`port`/`socket_type`/`protocol`/`server`/`server_args`/`type`/`user`）、端口缺失时 `getent services` 回退、xinetd 进程身份（comm+exe+启动时间）、冻结重载方式（systemd 管理→`systemctl reload`；否则向已核对身份的 PID 发 SIGHUP；未运行→“无需重载”）与监听表（`ss`→`netstat`→`/proc/net` 三级，均不可用记缺口）；执行复核文件摘要与守护进程身份（任一变化即拒绝且文件不动）、移入 `/etc/xinetd.d/.lovelyres-backups/`（目录名含点号，xinetd 自身跳过，备份不会被读回，计划与回执都写明）、重载后按端口轮询至多 5 秒；复核只认“端口不再被监听”，监听表不可读或端口仍被占用时 `passed=false`、文件保持隔离不自动放回、回执点名占用者（comm+pid）且仍可撤销——`PathOperation::restores_on_failed_verification()` 默认 true、本动作为 false，这是“验证失败不回放”语义的实现点；撤销仅在原路径仍空且备份摘要一致时放回并重载（守护进程换实例时按当前实例发 SIGHUP 并明说）。backend：`EmergencyPathAction::DisableXinetdService`（`disable-xinetd-service`）走 SSH 臂，不进批量与通用 SFTP 路径；位置/类型/忽略/权限/工具分别映射 `emergency-path-xinetd-*` 公开码；path DTO 增 `xinetdService`。界面：菜单“停用此 xinetd 服务…”只对 xinetd 实际加载的名字出现；计划写服务名、端口、重载方式、备份位置与“已建立的连接可能保留到其自行退出”；意图说明“复核未通过时文件仍保持隔离，可再撤销放回”；失败但已隔离的回执照常提供撤销；新增错误码均有中文翻译。配套：`/etc/inetd.conf` 入行级删除放行（inetd 重载未实现，计划与回执注明“inetd 需重新加载后才生效，本工具尚不执行重载”）；新目录条目 `system-module-revival-points`（启动文件/cron/init.d/systemd Exec 行/xinetd.d 中含 insmod·modprobe·kmod load·finit_module 的行；`/etc/modules` 与 `modules-load.d` 全部非注释行——可解析名只列不标、modinfo 与 `/lib/modules` 清单都不可用时列“未校验”不标、解析不出才标；modprobe.d 中执行命令的 install/softdep 行；标准模块目录外 `.ko` 限深 5 上限 200；末尾给出内核版本、隐藏模块计数（复用 `system-modules` 的差集逻辑）与本次开机时间；汇总“复活点 N 处”或“未发现”，凡有读取缺口不打印“未发现”）配 `module_revival_point` 行规则；行级删除放行 `/etc/modules` 与 `/etc/modules-load.d/<安全名>.conf`。修正：采集器不再把注释行当复活点命中；`xinetd process changed` 纳入“写入前拒绝”集合并有中文提示（此前只落到泛化的“操作未能完成”）；重载后守护进程已退出或被替换时回执追加说明（容器实测 xinetd 2.3.15.4 的 SIGHUP 重配置有概率令守护进程退出，撤销如实报“配置已放回但未被加载”）。
- 验证：core `xinetd` 8 项、`line_delete` 12 项、`command_` 全过（含 `module_revival_point` 规则与放行表）；backend `emergency_` 全过；core/backend `clippy -D warnings` 干净；`pnpm ui:check` 全过（含新错误码翻译断言）。目录条目经 `command_workbench::lab` 在 debian:12-slim、alpine:3.20、rockylinux:9-minimal 各 27 例全过（`tmp/lab_day5_wave3.txt`）：`/etc/profile`、init.d、cron.d 中的加载模块行与 modprobe.d 执行行、标准目录外 `.ko` 全部命中；`# insmod` 注释与 `options` 行不标记；无 modinfo 的 Debian/Rocky 如实列“未校验”不标记并记缺口，有 modinfo 的 Alpine 标“无法解析”；汇总按缺口如实给出。Debian 一次性容器端到端 33/33（`tools/lab/probe-emergency-path-xinetd.mjs`，输出 `tmp/lab_day5_xinetd.txt`，证据 `target/desktop-debug/xinetd-*/report.json`）：停用后独立连接被拒、备份落在 `.lovelyres-backups` 且摘要一致、撤销后端口恢复连接；计划后改文件、计划后重启 xinetd 分别按“未动”拒绝；`nc` 预先占用同一端口时回执点名 `nc(pid)`、文件保持隔离、撤销可用；xinetd 未运行时文件隔离且计划/回执注明无需重载；`svc.bak` 按 ignored、软链接按 kind、批量入口按 batch-action 拒绝；已用计划不可再执行。调试构建桌面端到端 13/13（`tools/lab/probe-ui-path-xinetd.mjs`，输出 `tmp/lab_day5_xinetd_ui.txt`，证据 `target/desktop-debug/ui-xinetd-*/report.json` 与 4 张截图）：`.bak` 名字不出现在菜单；菜单“停用此 xinetd 服务…”；计划写端口与 SIGHUP 重载；确认后独立连接被拒；撤销→确认→服务恢复连接。该次运行 SIGHUP 后守护进程退出，撤销如实报“配置已放回但未被加载”，重启守护进程后端口恢复（探针对两种结局都核对）。
- NOT_RUN：systemd 管理 xinetd 的 `systemctl reload` 分支在容器内不可达（容器无 systemd），仅代码与单测；`sudo -n` 路径未测；“端口仍被 xinetd 自身占用”与“另一进程占用”共用同一复核分支，实验驱动的是后者；`/etc/inetd.conf` 行删除后 inetd 重载未实现，需人工 `kill -HUP` 或服务重开；`rmmod` 一键卸载维持待决策，不提供；重启后的模块复核为人工重跑条目（条目打印本次开机时间供判断是否已重启），不做自动复核；VM/实机验证未做；`probe-system-info-mutations.mjs` 仍因本机无 WSL `lab-*` 靶机 NOT_RUN。
- 进程活动监视阶段 A（无上传方式）：core `process_watch.rs` 提供探测（`/proc` 可读、`hidepid`、容器内、无小数 sleep、已有监视在运行，各自作为采集缺口返回）与固定的 POSIX sh 轮询程序（只带入校验过的标记、时长、间隔三个值；先取基线，再按 200/500/1000 毫秒报告新出现的“PID + 启动时间”，命令行十六进制过线；到目标侧时限自行退出，收到中断也退出），事件上限 20000 条或 4 MiB 输出，到上限标记“已截断”并停止；停止后按 PID、启动时间与标记核对进程确已不在，不按名字结束进程。分析为纯函数：命令归一化、重复分组与周期判定（至少 3 次且间隔在中位数 ±20% 内）、摘要。backend `process-watch.probe/start/poll/stop/summary`（句柄化；每个连接同时只允许一个监视，重复开始按 `process-watch-already-running` 拒绝；连接关闭时停止并回收；命令行不写日志）；命令工作台新增可见按钮“进程活动监视”，面板说明方式与固有限制、逐条显示采集缺口、时长 1–30 分钟，运行中显示进度与数量并可取消，结束后给出结论句、时间线（搜索、按用户筛选、“本工具产生”与“开始时已在运行”默认折叠、复制命令与原始行、分页）和重复命令视图（点分组筛选时间线）。有缺口、截断或中断时结论句明确说明结果不完整。
- 验证：core `process_watch` 12 项、backend `process_watch` 7 项、`emergency_` 46 项、core `xinetd` 8 项、desktop 53 项；backend/desktop `clippy -D warnings` 干净；`pnpm ui:check` 153 个测试文件 1322 项。后端端到端 40/40（`tools/lab/probe-process-watch.mjs`，输出 `tmp/lab_day5_process_watch.txt`，证据 `target/desktop-debug/process-watch-03b765a8-*/report.json`），debian:12-slim 与 alpine:3.20 一次性容器：150 秒监视抓到每分钟一次的 cron 夹具 6 行、每 10 秒一次的标记进程 30 行并判为周期性（约 10.08 秒）；取消后回执“已核对停止”且容器内独立检查无监视进程；运行中重复开始被拒；切断连接后监视进程 0.9 秒内自行退出（时限 60 秒），重连后可再次监视；60 KB 参数的进程把输出推到 4 MiB 上限后状态为“已截断”且远端循环已停；普通账号在 `hidepid=0` 下能看到 root 的命令行；alpine/BusyBox 下抓到 crond 夹具与周期标记。监视进程自身开销在 debian 上 61 秒内约占单核 0.59%（含已回收的子进程，空闲容器，仅此一次测量）。桌面端到端 22/22（`tools/lab/probe-ui-process-watch.mjs`，输出 `tmp/lab_day5_process_watch_ui.txt`，证据 `target/desktop-debug/ui-process-watch-1d29ffa4-*/report.json` 与 6 张截图）：说明与容器缺口可见、打开不自动开始、连点只启动一次、进度更新、取消后独立检查无残留、结论句、周期性分组、分组筛选、搜索、折叠开关、关闭后焦点返回、无控制台错误。
- 实验中发现并修正的缺陷：轮询程序在关闭通配后遍历 `/proc/[0-9]*`，一个进程都采不到；读取 `Uid:` 时清空了分隔符，所有进程的用户都成了未知；停止后只核对一次，偶发把正在退出的进程报成未停止（改为最多 8 次、间隔 0.5 秒）；页面校验把正常的探测结果判为无效，面板无法打开；取消后页面停在“正在停止…”不再刷新。前四项单测都未覆盖，已补页面契约测试 7 项；后两项界面缺陷由桌面探针覆盖。
- NOT_RUN 与未做：容器内只能看到本容器进程，宿主机上的效果需 VM/实机；`hidepid=2` 缺口因非特权容器不能重新挂载 `/proc` 未驱动，仅单测；300 毫秒级的进程在 500 毫秒间隔下只抓到约六成（一次运行 30 次中 18 次），属该方式固有限制；监视运行中关闭再打开面板的重新接续、离开页面与切换目标时的停止未由探针驱动；alpine 上未测开销；arm64 等架构未测。阶段 B–D 见下。
- 进程活动监视阶段 B（上传 pspy 运行）：core `process_watch_upload.rs`、backend `process_watch_api/upload.rs`。程序不进安装包，用户经宿主文件对话框选择；宿主读取后只把大小、架构、SHA-256 和识别结果交给页面，本机路径不进页面。内置上游 v1.2.1 四个发布文件（`pspy32`/`pspy32s`/`pspy64`/`pspy64s`）的摘要表，一致时显示版本；不一致时标为“不是已知的 pspy 发布文件”，需额外勾选确认才能继续。非普通文件、非 Linux 程序、超过 16 MiB、与目标架构不符分别按各自的码拒绝。计划只读探测：依次检查 `$XDG_RUNTIME_DIR`、`/dev/shm`、`/tmp`、`/var/tmp`、主目录，跳过 `noexec` 与空间不足的目录，给出落点、账号、时长、摘要与缺口，不向目标写入；计划 5 分钟内有效、只能用一次。执行在权限为 0700 的私有目录 `.lovelyhawk-watch-<16 位十六进制>` 落地、回读摘要一致后以当前 SSH 账号运行，不安装到系统目录；目标侧到时限自行结束，到时与取消后删除文件和目录并独立回读“进程不在、目录不存在”。断连时目标侧自行停止进程但文件留在原处，下一次连接按目录名与内容列出残留，经一次确认清除并回读；伪造的残留句柄不触碰任何东西，句柄只能用一次。可选的文件访问事件只覆盖 `/etc`、`/tmp`、`/var/tmp`、`/dev/shm`、`/var/spool/cron` 和 `/var/www`，界面写明范围与“此时别处的短命进程更容易漏掉”。操作记录写入摘要、落点与清理结果，不写命令行。界面在确认前写明：会在目标上留下文件、新进程和访问时间变化；防护软件可能告警或删除；只能看到命令行，看不到输出；没有观察到不代表没有发生。
- 进程活动监视阶段 C（来源归类与检查动作推断）：core `process_watch_analysis.rs`，纯函数。按父进程链把事件归为计划任务、SSH 登录、系统服务、其他；只读取一次计划任务文件，把计划任务来源的命令对应到具体文件（如 `/etc/cron.d/<名字>`），界面写明这是推断。命令按固定表对应到命令工作台条目，对应不上的逐条列在“未对应”里，不丢弃，并写明对应表不完整；每个对应项有“前往该检查项”按钮。命令行里的地址、域名、URL 汇总为线索并标注保留地址。
- 进程活动监视阶段 D（已有记录的只读接入）：core `process_watch_sources.rs`，backend `process-watch.sources` 与 `process-watch.accounting.read`。探测四种来源并分别给出“正在记录且可读 / 有记录但当前账号不可读 / 已安装未记录 / 没有”：进程记账、审计 execve 规则、execsnoop、bpftrace。只有进程记账可以读取（`dump-acct`，最近 1–120 分钟，至多 20000 条），按程序名分组并判定周期；界面写明记账只有程序名没有参数、运行中的进程结束后才出现、本工具自己的命令也会被记进去且无法区分。记账按整秒记录，间隔不足 2 秒的不判为周期性。不开启记账、不安装工具、不提权。审计规则、execsnoop、bpftrace 只做探测和说明，记录不读取、程序不调用，状态为未适配。
- 阶段 B–D 验证：core `process_watch` 31 项、backend `process_watch` 12 项、desktop 53 项；core/backend/desktop `clippy -D warnings` 干净；桌面源码门禁通过；`pnpm ui:check` 153 个测试文件 1335 项。上传方式后端端到端 55/55（`tools/lab/probe-process-watch-upload.mjs`，输出 `tmp/lab_day5_process_watch_upload.txt`，证据 `target/desktop-debug/process-watch-upload-07a7d7f2-*/report.json`），debian:12-slim 一次性容器，`/tmp` 与 `/var/tmp` 为 `noexec`、`/dev/shm` 仅 1 MiB：计划跳过三者落在主目录；计划不写目标；目标上的文件与所选文件逐字节一致；到时、取消后独立回读无进程无目录；断连后 2 秒内进程自行停止，残留恰为落地目录，重连后列出并清除；已用计划、运行中再次开始、伪造残留句柄均被拒绝；只有 `noexec` 目录的账号按自己的码拒绝且未写入；普通账号在自己主目录运行并看到 root 的短命进程；cron 夹具归到计划任务及其所在文件，10 秒标记不被称为计划任务；夹具检查脚本的 4 步对应到工作台条目，1 步列为未对应；命令行里的 `203.0.113.9` 成为线索；`/etc` 下的写入出现为文件事件并单独计数；操作记录含摘要与清理结果、不含命令行。上传方式桌面端到端 22/22（`tools/lab/probe-ui-process-watch-upload.mjs`，证据 `target/desktop-debug/ui-process-watch-upload-7514de2e-*/report.json`）：默认不上传；未选文件不能生成计划；选文件不写目标；焦点落在计划标题而非确认按钮；返回不写目标；运行与清理独立回读；来源视图注明推断；“前往该检查项”选中对应条目；无控制台错误。已有记录后端端到端 26/26（`tools/lab/probe-process-watch-sources.mjs`，输出 `tmp/lab_day5_process_watch_sources.txt`，证据 `target/desktop-debug/process-watch-sources-043a290d-*/report.json`），debian:12-slim（为让探针自己开启记账加了 `CAP_SYS_PACCT`，非特权）与 alpine:3.20：未安装时四种来源均为“没有”且读取按 `process-watch-accounting-unavailable` 拒绝而不是返回空；安装未开启时报“已安装未记录”，询问后记账文件仍为空；开启后每 5 秒一次的夹具 9 条与目标自身 `lastcomm` 一致、判为周期约 5 秒，参数未进入结果，读取后文件属主、权限、inode 不变；普通账号报“不可读”且读取被拒；alpine/BusyBox 四种均为“没有”。已有记录桌面端到端 17/17（`tools/lab/probe-ui-process-watch-sources.mjs`，证据 `target/desktop-debug/ui-process-watch-sources-1b1899fe-*/report.json`）。阶段 A 两个探针在最终代码上重跑 40/40 与 22/22。
- 阶段 B–D 实验中发现并修正的缺陷：取消监视时，目标已报告但尚未被读取的行会随通道关闭丢失（未轮询 30 秒后取消只剩 63 行，修正后同一场景 465 行），现在取消前先取完；一次读取被条数上限截断时游标直接跳到末尾，超出的行被跳过（超过 500 个进程的主机首屏就会丢行），现在游标停在实际返回的最后一行，未读完前不报告结束；普通账号的 `PATH` 不含 `/usr/sbin` 时，不可读的记账文件被报成“已安装未记录”；同一秒内的一串记账记录被判为“约每 0 秒一次”的周期；新增的参数结构插在抓包参数结构之间，破坏了抓包接口的源码约束测试，已移开。
- 阶段 B–D NOT_RUN 与未做：只在 x86_64 容器上跑过，aarch64 等架构没有摘要表也没有实验，架构不符只有单测；宿主机进程可见性、`hidepid=2`、`sudo -n`、防护软件拦截 pspy 的失败路径、VM/实机均未驱动；空间不足的拒绝只有单测；审计规则在非特权容器里无法加载，探测只有单测，记录未接入；execsnoop/bpftrace 只按名字探测，未调用；RPM 系的记账（`psacct`、`/var/account/pacct`）未驱动；超过 20000 条的记账文件只有单测；记账“不可读”在桌面端未驱动，只有后端探针；容器的 1 号进程不回收子进程，被结束的 pspy 在夹具里以僵尸进程留在基线中，真实主机由 init 回收，未在实机核对；本工具清理与核对时的个别子进程（如 `readlink`）在其父进程已退出时无法识别为本工具产生，会留在普通活动和“未对应”里；监视结果导出到本机未实现。本机启用了系统代理（127.0.0.1:7890），core `ai`/`net_guard` 与 backend `ai_assist` 共 4–8 项依赖回环 HTTP 的单测因代理对回环目标返回 502 而失败，失败项随代理环境变量变化，相关文件不在本次改动内，未在无代理环境复核。

### 进程活动监视（上传 pspy 运行并采集）

**目标。** 现有采集都是某一时刻的快照，看不到“每分钟跑一下就退出”的进程。上传 [pspy](https://github.com/DominicBreuker/pspy) 运行一段时间，可在不需要 root 的情况下记录这段时间内出现过的命令行与（可选的）文件访问。两个用途：

- 应急：发现短命的 cron 任务、后门复活、是谁在不断改回某个文件、Web 进程派生的命令。
- 验收/竞赛：看到自动检查程序实际执行了哪些命令、读了哪些文件，从而知道它在核对什么，反推还有哪些项没处理。

**与现有规范的关系。** 这会改变此前“不向目标上传静态工具”的默认决策（见下方 2026-11-10 节“可信工具”与“本轮保留的决策”，已同步改写）。AGENTS 禁止的是“为运行检测而**静默**安装目标工具”；本功能必须是用户主动发起、逐次确认、不提权、不常驻、用完清理，并留操作记录。它只解决“看到短命进程”，不解决“目标上的 `ps`/`ls` 被替换后结果不可信”，后者仍为待决策。

**开工前要定的事。**

| 事项 | 默认决策（可改） |
| --- | --- |
| 程序从哪来 | 不把 pspy 打进安装包。用户通过宿主文件对话框选择本机上的 pspy 文件，宿主计算 SHA-256；与内置的“已知上游发布版本摘要表”一致时显示版本号，不一致时明确说明“未识别的文件”并要求再次确认。摘要表的数值在实现时从上游发布页取得并注明出处，不凭记忆填写 |
| 许可证 | 上游标注为 GPL-3.0，实现前需核对。不随包分发则不进第三方清单；若日后改为内置，必须先过许可证与 SBOM 门禁 |
| 架构 | 上游只发布 x86 的 32/64 位静态程序。按 `uname -m` 选择；arm64、loongarch、mips 等没有官方程序，记为“未适配”，走下面的无上传方式 |
| 是否需要 root | 不需要，也不提权。以当前 SSH 账号运行 |
| 运行时长 | 默认 3 分钟，可选 1–30 分钟；到时自动停止。观察每分钟一次的任务至少需要 2 分钟以上，界面说明这一点 |

**先探测再选择实现。** 发起后先做一次只读探测，再决定走哪条路并在计划里写明：

1. 目标已有等价来源时优先用它，不上传：auditd 已启用 execve 规则（读 `ausearch`）、已安装 `execsnoop`/`bpftrace`、已启用进程记账（`lastcomm`）。只读取，不替用户开启。
2. 可上传运行 pspy：架构受支持；存在可写且未以 `noexec` 挂载的目录（依次检查 `$XDG_RUNTIME_DIR`、`/dev/shm`、`/tmp`、`/var/tmp`、用户主目录）；剩余空间足够；`sha256sum` 与 `timeout`（或可替代的写法）可用。
3. 都不行时使用无上传方式：固定的 POSIX sh 循环按间隔扫描 `/proc/[0-9]*/cmdline` 并输出新出现的进程。界面明确说明“两次扫描之间启动并退出的进程会漏掉”。
4. 探测同时报告会降低结果完整度的条件：`/proc` 以 `hidepid` 挂载（非 root 只能看到自己的进程）、处于容器内（看不到宿主与其他容器的进程）、inotify 配额不足（`max_user_watches`/`max_user_instances`）、已有同名监视在运行。这些作为“采集缺口”随结果显示，不能显示成“这段时间没有活动”。

**执行链路（core `process_watch.rs`）。**

1. 计划：绑定目标身份与会话、探测结果、所选方式、程序摘要与大小、落地路径、运行参数、时长。计划不可变；目标或探测结果变化后重新规划。
2. 确认对话框写明：将向哪台主机的哪个目录写入一个多大的文件、以哪个账号运行多久、会留下什么痕迹（磁盘写入、一个新进程、inotify 监视）、结束后会删除什么。真实环境逐次确认，一次确认只对应这一次运行。
3. 上传：在所选目录下新建仅属主可访问（0700）的随机名子目录，文件 0700；走既有 SFTP 通道（无 SFTP 时用已有的 SCP 回退）；上传后在目标上重新计算 SHA-256 并与本机一致才继续，不一致即删除并报错。
4. 运行：固定参数，不接受用户自由输入的参数串。关闭彩色输出；默认只记录进程事件；“同时记录文件访问”为可选项且默认只监视有限目录（`/etc`、`/tmp`、`/var/tmp`、`/dev/shm`、cron 与 Web 根），因为全盘文件事件量极大。具体参数名以所选版本的 `--help` 输出为准，实现时核对，不照抄记忆。由目标侧的时限包裹运行，保证连接断开后程序也会到时自行退出，不留常驻进程。
5. 采集：输出流式回传，行数与总字节有上限，到上限后明确标记“已截断”并停止；界面显示已运行时间、已收到的事件数，可随时取消。
6. 结束与清理（到时、取消、出错、断连重连后都要走）：按“PID + 启动时间 + 程序路径”核对后停止进程，不按名字杀；删除文件与目录；独立回读确认进程不在、路径不存在。清理失败时明确告知残留位置和手动清理方法。断连后无法清理的情况，在下次连接同一目标时凭本机记录的路径与摘要提示“上次监视可能有残留”，由用户确认后清理。
7. 记录：操作日志写入上传的文件摘要、落地路径、运行账号、起止时间、清理结果。原始输出可保存到本机并导出。

**解析与分析。**

- 逐行解析为事件：时间、类型（进程/文件）、UID、PID、（可取得时）父 PID、命令行或文件路径。无法解析的行保留原文并计数，不丢弃。
- 自身噪声剔除：本次监视自己的进程、LovelyHawk 当前 SSH 会话派生的命令单独归为“本工具产生”，默认折叠而不是删除。
- 视图一（时间线）：按时间排列，可按 UID、命令、路径筛选与搜索，复制原始行。
- 视图二（重复出现的命令）：按“归一化后的命令行”分组，给出次数与间隔；间隔稳定的标为“周期性”，并尝试与已采集的 cron/timer 条目对应，对应不上的标为“来源未知的周期任务”。
- 视图三（会话与来源）：把事件按父进程链归到“cron 派生”“某次 SSH 登录派生（来源地址取自已有登录记录）”“Web/数据库服务派生”“其他”。
- 视图四（检查动作推断）：把观察到的只读类命令映射到工作台已有的排查项，例如读取 `/etc/crontab` → 计划任务、`lsmod`/读取 `/sys/module` → 内核模块、`find -perm` → SUID、连接某端口 → 该监听服务、读取 `/etc/profile` 或 init 脚本 → 启动项；每条给出“前往对应条目”的入口，并显示该条目当前是否仍有未处理的命中。明确标注这是根据命令推断的，不代表对方的全部检查内容，也不代表对应项已通过。
- 命令行里出现的地址、域名、URL 进入已有的线索汇总。
- 新手看到的是结论句（“这 3 分钟里有 2 个每分钟执行一次的任务，其中 1 个找不到对应的计划任务”）加下一步建议；专家可直接看原始输出与全部事件。

**接线。** core `process_watch.rs`（探测、计划、执行、清理、解析）→ backend 方法（发起探测、生成计划、确认执行、取消、取结果、清理残留；句柄化，落地路径与摘要不由页面传入）→ shared DTO 与请求/响应校验 → 宿主：选择本机程序文件属于带本机路径的操作，只能是专用宿主命令，页面只拿到不透明句柄、文件名与摘要 → `ui/src/host` 桥 → 命令工作台新增“进程活动监视”入口（可见按钮，不藏在右键里）。离开页面、切换目标、关闭窗口时先停止并清理再放行；迟到的输出不得写入新目标的结果。

**分阶段。**

| 阶段 | 内容 | 完成标准 |
| --- | --- | --- |
| A | 无上传方式（`/proc` 轮询）+ 事件模型 + 时间线与重复命令视图 + 取消/时限/截断 | 不写目标磁盘即可用；容器靶机上能抓到每分钟一次的 cron 夹具。已实现，debian/alpine 容器已验证，见上方实施进度；VM/实机 NOT_RUN |
| B | 探测、计划确认、上传 pspy、运行、清理、残留回收、操作记录 | 上传前后摘要一致；到时/取消后目标上无进程与文件残留，断连后进程自行停止、文件由下次连接确认清除。已实现，debian 容器已验证；其他架构与 VM/实机 NOT_RUN |
| C | 会话与来源归类、检查动作推断、与工作台条目互相跳转、线索汇总 | 夹具“检查脚本”执行的每条命令都能在视图四中对应到条目或明确列为未对应。已实现，debian 容器已验证 |
| D | 已有等价来源（auditd/execsnoop/记账）的只读接入；其他架构的处理方式 | 各来源分别有靶机证据；无证据的保持“未适配”。进程记账已接入并在 debian 容器验证；auditd、execsnoop、bpftrace 只探测不读取，保持未适配；其他架构按“架构不符”拒绝，无实验 |

**验证计划。**

- core 单测：输出解析（含超长行、控制字符、非 UTF-8 字节、恶意构造的命令行）、周期判定、噪声归类、落地路径与参数的拒绝测试。
- 一次性容器靶机（debian、alpine/BusyBox、无 `timeout` 的精简镜像）：夹具为每分钟执行的短命 cron 与一个模拟检查脚本；分别驱动 `/tmp` 为 `noexec`、非 root 账号、`hidepid=2`、inotify 配额很小、磁盘已满、上传中途断连、运行中途断连、重复点击开始、运行中切换目标。
- 桌面端到端探针（`tools/lab/probe-ui-process-watch.mjs`）：确认对话框内容、进度与取消、清理后的独立回读、焦点与键盘。
- 容器内运行只能看到本容器进程；宿主上的效果必须在 VM/实机验证，未验证前记 NOT_RUN。arm64 等架构记“未适配”。

**风险与边界（需要写进界面说明）。**

- 会在目标上留下痕迹：写入一个文件、出现一个新进程、目录访问时间可能变化。取证要求严格的现场应先完成磁盘/内存留证再使用。
- 攻击者或对方的检查程序同样可能看到这个进程和文件；终端防护软件可能把 pspy 识别为黑客工具并告警或删除，此时按“运行失败”如实报告。
- 看到的是命令行，不是命令的输出或判定逻辑；没观察到不代表没有检查，时长之外、进程内完成的检查（如直接读文件、远程连端口）看不到或只看到一部分。
- 命令行里可能带有口令等敏感内容；原始输出按敏感数据处理，导出前提示，不进入 AI 分析的默认上下文。
- 仅在已获授权的主机上使用；竞赛场景下是否允许观察检查程序由规则决定，工具不做判断。

## 2026-11-10 外部应急材料对照的待补能力清单

对照本机外部材料逐项核对现有代码后确认以下缺口。材料来源：运维竞赛 writeup（运维1.5、运维2、运维3）、培训课件与笔记（Day1/Day2/课件1/课件2）、`sec_baseline_check.sh`（约 2580 行的基线与后门狩猎脚本）、LinuxIR 整合包（LinuxCheck_plus + unhide 三件套 + rkhunter 1.4.6）、D 盾（闭源 Windows 工具，仅参考使用方式）与 `tunnel_key.sh`；材料在本机 `tmp/` 下，不入库。基础排查面（进程、网络、账号、cron、systemd、init.d/rc 文件、`ld.so.preload`、authorized_keys、SUID 白名单判定、高危 capability 判定、挖矿、反弹 shell、iptables 只读、SSH 爆破统计、直接读取 cron spool、账号锁定/删除、容器内排查与文件编辑）已由 `detection.rs`、`command_workbench.rs`、`command_findings.rs`、`system_info.rs`、`file_analysis.rs` 覆盖，不在此重复；包完整性与隐藏进程只有基础实现，深度缺口见下文。清单按建议优先级排列，不代表全覆盖；每项实施时仍按 core → backend → DTO → 宿主 → UI 链路补拒绝测试与真实环境验证。

### 实施进度（2026-11-10 起，更新至 2026-11-13）

逐项进度同步到 GitHub issue #1–#11（n1majne3/LovelyHawk）。以下已实现并通过所列验证；“不纳入范围”外的其余条目继续按优先级推进。

- 数据库账号口令修改（PostgreSQL）：core 计划/执行/独立登录复核/限时恢复与已存口令放回，桌面数据库页“修改口令”对话框，见 [设计与边界](DATABASE_PASSWORD_CHANGE.md)。PostgreSQL 16 一次性容器实验 6/6（scram 自改并放回、超级用户改他人、非超级用户不可恢复、md5、nologin 拒绝、`log_statement=all` 日志无明文）；调试构建桌面端到端 21/21（`tools/lab/probe-ui-postgresql-password.mjs`：修改并复核、已存口令同步、容器内 psql 独立核对、界面放回、非超级用户不可恢复、焦点与键盘、日志与便携数据无口令），过程中修正计划视图字段命名、格式名与确认步骤立即过期三处缺陷。
- 数据库账号口令修改（MySQL/MariaDB）：自研原生协议 `mysql_wire.rs`（握手、能力协商、mysql_native_password/caching_sha2_password/sha256_password 令牌、有界查询）与会话层 `mysql_native.rs`（TLS 验证或字面回环下的 SSH 保护两种模式）；`mysql_password.rs` 编排（Inspect 独立通道核实账号/插件/版本/`log_raw`/锁定态，冻结 MySQL `ALTER USER 'u'@'h' IDENTIFIED WITH … AS` 与 MariaDB `IDENTIFIED VIA … USING` 语句进计划，Apply 后新口令独立登录复核，恢复令牌单用 10 分钟、恢复后重捕认证串常量时间比对）；backend `mysql.runtime`（连接配置 list/save/删除 + 口令计划/执行/恢复，句柄化、作用域校验）；桌面 MySQL 页提供连接管理与改口令对话框。MySQL 8.0.46 与 MariaDB 11.8.9 一次性容器端到端 54/54（`tools/lab/probe-mysql-password.mjs`：修改后新口令独立 TCP 登录通过、旧口令明确 1045、恢复后互换、已用计划/恢复令牌 stale、弱口令/含账号名/未知账号按码拒绝、服务端日志与本地存储无口令明文）。实验发现并修正三处缺陷：MariaDB 无 `@@log_raw` 变量且 `mysql.user` 无 `account_locked` 列（改为 SHOW VARIABLES 容忍探测 + `mysql.global_priv` JSON 取锁状态）、MariaDB `SHOW CREATE USER` 输出 `IDENTIFIED BY PASSWORD` 不带插件名（回退为目录插件）、共享口令策略错误前缀误标 PostgreSQL。验证：core mysql 相关 46 项、fmt/clippy 干净、UI 1217 项测试。未覆盖：verify-full TLS、连接账号的已存口令更新、第二网络位置复核。
- 打包链：PowerShell 7.6.9 已装，`pnpm release:package` 全链通过（源码门禁、两个 exe 的静态 CRT/PE 导入校验、445 crates + 7 UI 包第三方清单、便携 zip 校验），产物 `artifacts\LovelyHawk-0.0.4-windows-x64.zip`；llvm-objdump 经 gnu 工具链 rustlib 提供。
- 判定规则（命令工作台）：shell 启动文件与 init 脚本中的 `insmod`/`modprobe`、可写目录 `nohup`、xinetd shell 服务与 TCP wrappers `spawn`/`twist`；init.d 内容扫描；alias/同名函数/`trap` 劫持；Web 根内任意压缩包、依赖/认证清单、`.git`/`.svn`（不下钻）、云与集群凭据文件；Web 根隐藏脚本。
- 包校验：Debian 无 debsums 时用 `dpkg --verify` 校验关键软件包，并先以 `dpkg.md5sums` 核对 dpkg 自身；命令备份残留（`.bak`/`.orig`/`.old`/`~`/同目录点号副本/`psd`/`lsd` 等）。
- Rootkit：`/sys/module` 与 `/proc/modules`、`/proc/kallsyms` 模块标签比对；隐藏进程改为两次目录列表 + 直接探测（上限 65536，排除自身子进程与瞬时进程）。
- 后门：sshd 软链接后门（argv0、指向 sshd 的软链接、配置外监听端口）、`pam_exec.so` 与 `pam_unix.so` 包校验、新增 Python `.pth` 与 Git 钩子两个条目（目录 149 项）。
- 溯源：日志分析“爆破后成功登录”（同一来源失败 ≥5 次后首次成功，威胁等级至少为高）。
- 基线（只检查，不提供写入）：新增 7 项。SSH 弱算法（按 sshd -T 生效值；OpenSSH 默认 MAC 含 umac-64/hmac-sha1，未显式配置的主机通常判为不合规）、SFTP 子系统、AllowUsers/AllowGroups、TMOUT 空闲超时、口令历史 remember、su 的 pam_wheel 限制、90 天未登录的可登录账号；目录 120 项。sshd -T 不可读、文件或 lastlog 缺失时显示无法判断。debian/alpine 一次性容器以真实采集脚本核对默认值与夹具值（alpine 无 /etc/pam.d/su 与 lastlog，正确显示无法判断）。结果值中的英文短标记（如 `within-900`、`absent`、`ge-5`）已由界面按组件+建议值组合映射为中文（`baselineObservedLabel`/`baselineRecommendationLabel`），其余真实取值原样显示。
- 移除文件能力（setcap 修复，处置闭环第二项）：core `capability_strip.rs` 经 SSH 探测（getcap/setcap/sha256sum 在位、普通文件、root 或免密 sudo、当前能力集与文件摘要）后生成计划；执行前重核摘要与能力集，文件被改过即拒绝且不做任何写；`setcap -r` 移除后独立 `getcap` 复核，撤销把原能力集写回一次；缺工具、非普通文件、权限不足、无能力分别给出拒绝码。工作台“文件 Capabilities”条目命中的路径在菜单提供“移除文件能力”。验证：core 探测解析单测、backend 句柄/拒绝映射测试、Debian 一次性容器端到端 25/25（`tools/lab/probe-emergency-path-capability.mjs`：夹具独立 getcap 核对移除/写回、已用计划不可再执行、计划后文件被改拒绝且原内容保留、能力被清空与变成符号链接分别按码拒绝），过程中修正 getcap 按位序输出与内核写入即清能力两个夹具假设。`sudo -n` 路径未经真实目标驱动。
- 封禁 IP（处置闭环第一项）：core `firewall_block.rs`，按 firewalld → iptables（含 DOCKER-USER）→ nftables（自有 `inet lovelyhawk` 表）选择后端，ufw 活动时拒绝；只加运行时规则并明确说明重启或重载后失效；入方向封禁当前 SSH 来源地址时拒绝；内网地址给出提示；规则带 `lovelyhawk-block-<8位>` 标记，执行后回读，可单独撤销且只删除本次规则。后端 `system-info.firewall`，恢复标识只在后端内存、页面只拿不透明句柄；主机全景的防火墙/网络详情/外连排查标签提供“封禁地址…”，连接行提供“封禁…”。验证：core 单元 8 项与 debian（iptables-nft）、alpine（nftables）NET_ADMIN 一次性容器实验（规则回读、计数器命中、连接被拒、撤销后为 0；修正 nft 撤销取错链名、规则缺少计数器两处缺陷），backend 3 项，UI 契约与对话框测试；firewalld/ufw 仅单元测试，iptables-legacy 在实验内核中不可用。调试构建桌面端到端 14/14（`tools/lab/probe-ui-firewall-block.mjs`：从防火墙标签封禁并经容器内 iptables 独立核对、撤销后核对已删除、封禁当前 SSH 来源被拒且不加规则、焦点与 Escape），过程中修正撤销时对不存在的 DOCKER-USER 链也发删除命令、导致规则已删却报失败的缺陷。
- 系统账号口令修改（处置闭环第三项）：core `account_password.rs`。明文在计划时即由 core 计算成 SHA-512 crypt（`sha-crypt` crate）后丢弃，计划只存要写入的散列字段（Zeroizing）；优先 `chpasswd -e` 经敏感通道 stdin 写入（命令行与审计都不出现散列），`usermod -p` 为兜底。锁定账户的 `!` 前缀原样保留（改口令不会悄悄解锁），`*`/`x` 等拒绝登录标记拒绝改写；需要 root 或免密 sudo，缺工具、弱口令、域账号/读不到记录分别给出拒绝码。执行前重读字段一致才写，执行后回读精确匹配加账号身份复核为验证，失败自动写回原字段。主机全景用户标签行操作提供“修改口令”，先输入新口令（两次确认、本地校验）再生成计划。验证：core 单测 4 项、backend 行操作测试、Debian 一次性容器端到端 21/21（`tools/lab/probe-account-password.mjs`：独立 openssl/crypt 复算证明新口令可认证、旧口令不再匹配、锁定账户散列替换后仍锁定、`*` 字段与弱口令按码拒绝、计划后字段被改拒绝且原值保留、已用计划不可再执行、明文不出现在本地数据存储）。`sudo -n` 路径与验证失败自动放回未经真实目标强制驱动。
- 按原命令行重启业务进程（处置闭环第四项）：core `process_restart.rs`。计划经单次受限探测捕获 PID、启动时钟、argv 与工作目录（`od` 十六进制过线，奇异字符不损失）、uid/用户与权限事实，并拒绝不能走此通道的进程：本会话进程链（停掉会切断执行通道）、PID 1/内核线程、systemd 托管（应走服务操作）、读不到原工作目录、缺 setsid、无法以原用户拉起或无权停止，分别给出拒绝码。执行前重核进程身份（PID 复用或已退出即拒写且不动它），SIGTERM 8 秒未退出再 SIGKILL，然后 `setsid` 脱离会话按原用户（本用户直通/root 用 su/免密 sudo -u）、原目录、原 argv 拉起；验证扫 `/proc` 找携带同一 argv 字节、uid、cwd 的新 PID 并确认原 PID 已退出或为僵尸；验证失败且原进程确已退出时再拉起一次（原进程还在则拒绝恢复以免双实例），回执保留原命令行供手动恢复。主机全景进程标签行操作提供“按原命令行重启”。验证：core 单测 4 项（argv/cwd 十六进制编解码、探测解析、逐参数引号）、backend 行操作测试、Debian 一次性容器端到端 18/18（`tools/lab/probe-process-restart.mjs`：以 labapp 用户在 /opt/appdir 手工拉起 `sleep 31337` 后经 RPC 计划、确认、执行，独立 /proc 回读证明新 PID 同 argv 字节、同 uid、同目录且原 PID 已退出；计划后外部 kill 掉的进程拒绝执行且不产生重复实例；PID 1 按码拒绝；已用计划不可再执行）。实验发现并修正扫描端 cwd 十六进制编码与计划端不一致导致验证必然失败的真实缺陷。限制：RootSu 路径为主（容器 root 登录），Direct/SudoUser 拉起路径未驱动；无 systemd 容器无法驱动 managed 拒绝；拉起失败重试未强制。
- 验证：core `command_` 96、`log_analysis` 13、`database_password` 12、`account_password` 4，backend `postgresql_runtime`/`emergency_`/`log_analysis`/`system_info`，`pnpm ui:check` 1196+；WSL 夹具 38/38；debian:12-slim 与 alpine:3.20 一次性容器 7 项后门/rootkit 用例全部通过，单项 0.4–0.8 s（`command_workbench::lab`，过程中修正 pam_exec 未命中、Git 钩子未标记、隐藏进程自身子进程误报、`[bpf]` 伪模块误报）。容器不能伪造隐藏模块/进程，这两项的真实命中仍需 VM/实机验证。

### 处置闭环（最高）

- ~~封禁 IP 的防火墙写入~~（已完成，见上方进度区；core `firewall_block.rs`，`probe-ui-firewall-block.mjs`）。
- ~~capability 修复（`setcap`）~~（已完成，见上方进度区；core `capability_strip.rs`，`probe-emergency-path-capability.mjs`）。
- ~~系统命令还原一条龙~~：留证 → 按备份残留还原 → 包校验复核 → 功能验证。还原链路已接通：紧急命令路径操作新增“按残留还原”（core `command_restore.rs`、后端 `restore-residue`、页面确认对话框），经绑定 SSH 探测 `.bak`/`.orig`/`.old`/`~`/点号副本/`.dpkg-old`/`.dpkg-new`/`.dpkg-bak`/`*dpkgbak` 及 `psd`/`lsd` 等已知变体，唯一安全来源才放行，先留证再就地写回并复核摘要与功能，结果记操作日志、可撤销；包校验与功能检查只作观察，不宣称主机干净。检测脚本（`command_workbench.rs` `file-binary-changed`）已补 `.dpkg-*`/`*dpkgbak` 残留发现。恢复后丢 `security.capability` 的配套由上方 `setcap` 项提供；真实容器证据已有（`probe-command-restore.mjs` 等）。包校验与功能检查仍只作观察，不宣称主机干净。
- ~~包校验在 Debian/Ubuntu 上的回退~~：已实现（无 debsums 时用 `dpkg --verify`，并先以 `dpkg.md5sums` 核对 dpkg 自身，不经可能已被替换的 dpkg 二进制）。
- ~~账号口令修改~~（已完成，见上方进度区）。仍缺的配套：只检查用户录入的连接口令强度，不对目标做字典尝试（锁定风险且越过只读默认）。删除账号依赖目标 `userdel`，被替换时（运维2）复核能报告失败，但不提示命令可能被替换、也不提供替代路径。
- ~~普通业务进程按原样重启~~（已完成，见上方进度区）。环境变量与已打开文件/网络连接不还原，systemd 托管进程仍走服务操作。

### Rootkit 检测深度

- ~~rootkit 签名库~~：第一批已实现（`command_workbench.rs` `file-rootkit-signatures` + 内置 `cmd_sig_lines.inc` 文件/目录特征、`cmd_port_lines.inc` 后门端口映射）。剩余缺口：覆盖面仍小于 rkhunter 全量家族库，真实 rootkit 命中矩阵未跑（NOT_RUN）。
- ~~隐藏端口检测~~：已实现（`network-hidden-ports`/`network-bind-probe`，逐端口 `bind()` 探测与监听表对比，opt-in 不随组合运行）。
- ~~LKM 专项~~：已实现（`system-lkm` + `cmd_ksym_lines.inc`：`/proc/kallsyms` 已知 rootkit 符号、标准模块目录外 `.ko`、dmesg/journalctl 模块加载痕迹）。决策（默认，用户可改）：不做 Diamorphine 的 kill -63/-64 信号探测——发送信号会改变攻击者状态，检测改经 kallsyms 与 `/sys/module` 差集。
- ~~自隐藏模块~~：已实现（`system-modules` 增加 `/sys/module` 与 `/proc/modules` 差集、`/proc/kallsyms` 模块标签比对，并提示已加载模块残留需重启才消失）。
- ~~模块复活点~~：已实现（shell 启动文件与 init 脚本中的 `insmod`/`modprobe` 由判定规则标出；dmesg/journalctl 加载痕迹经 `system-lkm`）。
- ~~隐藏进程深度~~：已实现（两次 `/proc` 目录列表 + 按 PID 直接探测，上限 65536，排除自身子进程与瞬时进程）。容器不能伪造隐藏进程，真实命中仍需 VM/实机（NOT_RUN）。
- ~~系统命令依赖库注入~~：已实现（`perm-dt-needed` 批量核对系统命令 `DT_NEEDED`）。
- 命令被替换的旁证：与同目录其他命令修改时间不一致、`strings` 中出现 curl/socket/`/bin/sh` 等网络或回连特征，未实现。
- 可信工具（待决策）：工作台全部依赖目标上的 `ps`/`ls`/`find`/`dpkg`，命令被替换时结果整体不可信。LinuxIR 用自带静态 unhide 绕开；是否提供“确认后上传静态工具到临时目录执行、用完清理”的路线，与“默认不在目标上安装工具”的规范冲突，需产品决定。决策更新（2026-11-13）：仅对“进程活动监视”放开“逐次确认后上传 pspy、限时运行、用完清理”，规划见上方 2026-11-13 节（不上传的 `/proc` 轮询方式已实现，上传 pspy 尚未实现）；用自带静态工具替代目标上可能被替换的 `ps`/`ls`/`find` 仍为 待决策。

### 持久化与后门判定深度

- ~~持久化链条跟踪~~：已实现第一版（`persistence-chain`：cron/init 条目引用的脚本再追一层）。剩余缺口：链深与间接引用仍有限，跨用户引用可能漏。
- ~~xinetd 后门~~：已实现（判定规则加入 `server = /bin/bash` 类 shell 服务与 `spawn`/`twist` 特征）。
- ~~alias / 同名函数 / trap~~：已实现（判定规则覆盖 `sudo()`/`ssh()` 同名函数、`trap DEBUG` 与执行即落盘的 alias 劫持）。
- ~~SSH 软链接后门~~：已实现（argv0 非 sshd 的 sshd 进程、配置外端口仍监听的 sshd、可写目录指向 sshd 的软链接与 `pam_rootok` 提示）。
- ~~其他隐蔽持久化点~~：已实现（Python `.pth`、`.git/hooks`、`hosts.allow`/`hosts.deny` 的 `spawn`/`twist`、`pam_exec.so` 与 `pam_unix.so` 包校验均已覆盖）。
- ~~可疑进程规则~~：已实现（Web/数据库账号派生 shell、伪装内核线程名却有磁盘程序文件的进程）。

### 溯源

- ~~爆破后登录成功关联~~：已实现（同一来源失败 ≥5 次后首次成功记为高威胁线索）。
- ~~IOC 自动提取~~：已实现（`ioc_extract.rs` 从排查结果提取 IP/域名/URL 汇总为工作台「线索汇总」，支持明文与 defanged 复制；`probe-command-iocs.mjs`）。决策（默认，用户可改）：IOC 与本机扫描结果不绑定案件记录——案件页已移除。

### 数据库应急（入侵排查视角，非配置基线）

- ~~MySQL/MariaDB 运行实例在线检查与日志溯源~~：已实现 `mysql_instance.rs` 只读实例审查 + backend `mysql.runtime` `inspect` 动作——账号目录复核（匿名账号、`root@'%'` 类远程 root、空口令、`File_priv`/SUPER/GRANT、锁定态，MySQL `mysql.user` 与 MariaDB `mysql.global_priv` 双 schema）、`mysql.func` UDF 行、风险相关全局变量（`general_log`/`general_log_file`/`log_output`/`local_infile`/`secure_file_priv`），以及 general_log 有界尾部溯源（`Access denied` 来源统计、`INTO OUTFILE`/`CREATE FUNCTION` 写马语句命中）；所有结论分级为线索而非定性，变量缺失/非 FILE 日志/日志不可读以缺口明示。MySQL 8.0.46 与 MariaDB 11.8.9 一次性容器端到端验证（探针夹具覆盖全部发现类别，64/64）。
- ~~数据库账号口令修改~~（已完成，见上方进度区：PostgreSQL `ALTER ROLE` 与 MySQL/MariaDB `ALTER USER` 固定语句、执行后独立登录复核、限时恢复与已存口令放回）。
- ~~MSSQL 日志审计~~：已实现（`windows_incident/mssql_audit.rs`：注册表实例发现、ERRORLOG 有界尾部、Application 18454/18456 按来源+账户聚合、`xp_cmdshell`/Ole Automation/`xplog70.dll`/`odsole70.dll`/`sp_addextendedproc` 线索、`log.trc` 只报路径与大小；win-dvc `MSSQL_AUDIT` 固定只读脚本）。剩余缺口：真实 SQL Server 实例验证不可用（本机无 MSSQL，仅夹具与本机脚本回读，NOT_RUN）。

### Web 应急：一键 Webshell 扫描与 Web 日志规则

- 一键 Webshell 扫描（“D 盾扫 www”式工作流）：`WEBSHELL_SCAN_COMMAND`（`detection.rs`）已覆盖 Web 根自动发现（nginx/apache/tomcat 配置指令 + `nginx -T` + 常见目录）、扩展后缀集（php/php3-7/phtml/pht/phar/jspx/asp/aspx/asa/cer/ashx）、图片马（图片内嵌 `<?php`）、配置型后门（`.htaccess`/`AddType`、`./user.ini`/`auto_prepend_file`）、隐藏脚本与特征分级（确证/疑似，单行 base64 长串与解码链标为需人工核对）。扫描器已统一为收集器契约：命中行 `关注：<path> | <类别>，第 N 行：<摘录>` 使工作台 `file-webshell-hint` 直接展示同一结果，命中行经 `command_paths` 提供路径句柄，接通既有“下载留证”（file_evidence）与“隔离/去执行位”（emergency_path 计划-确认-执行-复核-恢复链路）；不可解析/歧义路径仅展示不提供操作。单测 9 项 + 真实 Debian 容器实跑验证。剩余缺口：
  - ~~批量处置带范围预览~~：已实现（路径句柄命中可批量去执行位/隔离，单次预览+确认，逐项结果与撤销；`probe-path-batch.mjs`）。
  - 容器 Web 根一键扫描：选中容器后发现 Web 根，容器内直接扫或整目录拉出扫后回定位容器文件。
  - `detection.rs` 结构化 `WebshellScan`/`DetectionService` 尚未接 RPC（工作台为桌面可见入口）。
  - ~~外部扫描器编排~~：已实现「取回本机扫描」（路径菜单 → `local.scan` 动作链 `engines/configure/fetch/inspect/run/reveal/discard`）：远端固定形状探测 + `tar -T` 打 tar 包（`find` 限普通文件/目录、单文件 4MiB、2 万成员、256MiB 上限），经既有证据通道下载（SFTP 或 SCP 回退，双读+stat+SHA-256 核对），本机自研 tar 解包器落隔离目录（拒绝链接/设备/穿越/保留名/尾部点号，去除执行权限并写 MOTW 网络标记），manifest 绑定目标标签/来源路径/摘要/传输方式，30 分钟 TTL 与按绑定清理。引擎配置仅存校验过的绝对路径+类型+argv（程序路径由宿主系统对话框注入，页面不送本机路径）：图形界面引擎（D 盾类）拉起并在提示中给隔离目录，命令行引擎限时 120s 捕获输出（64KiB 截断）。真实 Dropbear（无 SFTP 子系统）端到端 18/18：单文件/整目录取回、隐藏文件与符号链接处理、manifest 复核、cli/gui 双引擎、拒绝路径与丢弃清理。剩余缺口：
    - 外部引擎输出解析：CLI 引擎输出现可按取回 manifest 回映远端路径（本机扫描命中映射，`probe-local-scan.mjs`）；D盾等结构化命中解析未做，按决策不与案件记录关联（案件页已移除）。
    - 本机安全软件会实时检查取回内容（实验已验证 Defender 拦截 webshell 读取），属固有面已在 manifest 与界面说明。
    - 取回过程非原子快照，目标侧内容在打包与下载间变化时以 stat 核对失败为界。
- ~~Web 日志攻击特征内置规则~~：已实现固定内置特征集（`log_analysis.rs` `builtin_log_rules`，7 条：union select SQL 注入、路径穿越/`%2e%2e`、`${jndi:` JNDI 注入、ThinkPHP 利用路径、webshell 参数访问、扫描器 UA、IFS/`/dev/tcp` 反弹特征），经 `rules_for_matching` 在匹配点与自定义规则合并（自定义优先、内置不可删改列，`match` 命中带 `builtin` 来源标记与 `builtinRuleCount`），并按行内来源地址聚合 `sources` 攻击源统计（按命中数排序、上限 16 源/8 特征，回环与缺源不计），全部为排查线索而非定性。core 单测 7 项（签名命中/大小写/聚合排序/上限/共存/净日志不误报）；backend RPC 与契约同步扩展。剩余缺口：特征覆盖面仍小（无 LFI/RFI 与序列化利用、无更多国产框架与组件特征、无 XSS 线索），`log-web-trace` 的逐行 URI 尚未自动喂给匹配，攻击源仅限行内可解析 IPv4。
- ~~访问日志反查文件~~：运维2 的免杀马 D 盾扫不出，是从 apache 访问日志找到的。`log-web-trace`（`command_workbench.rs`）已覆盖第一版：读取 nginx/apache 访问日志尾部与 .1 轮转，提取点号隐藏段、样本内仅 POST、疑似随机命名、含 `..` 或 PUT/DELETE/TRACE/CONNECT 的脚本路径，并把前 20 条 URI 拼到常见站点根核对存在性，全部为需人工核对的线索。剩余缺口：自定义日志位置与 vhost 日志目录、压缩轮转文件、URL 编码与路径规范化带来的漏判，以及对命中文件的进一步特征深查（可结合 `file-webshell-hint`）。
- ~~Web 根内的站点打包与敏感文件~~：已实现（判定规则覆盖 Web 根内任意压缩包、依赖/认证清单、`.git`/`.svn`、云与集群凭据文件）。
- ~~Web 根内的隐藏文件~~：已实现（判定规则已含 Web 根隐藏脚本）。
- ~~Web 组件版本识别与已知漏洞~~：第一版已实现——`file-web-version`（`command_workbench.rs`）在常见站点根（含 `/usr/share/phpmyadmin`、`/home/*/public_html`）内定位 ThinkPHP（`base.php`、`library/think/App.php`、`thinkphp.php`、`topthink/framework`）、phpMyAdmin（`doc/html/index.html`、`README`、`ChangeLog`、`libraries/classes/Version.php`）与 Smarty（`Smarty.class.php`）的版本文件并解析版本，命中 ThinkPHP 5.0.x/5.1.x、phpMyAdmin <4.9、Smarty <3.1.45 历史风险区间时标为需人工核对的版本线索（非 CVE 确证）。剩余缺口：其他产品与自定义站点目录、更多版本证据来源、按精确补丁版本比对漏洞库。
- 模板编译缓存污染：发现已实现（`file-smarty-templates-c` 在站点目录定位 `templates_c`/`compile_dir`，核对编译产物的执行特征与可疑请求变量）。剩余缺口：清理动作未实现。

### 传输能力：整目录上传/下载与批量传输

- SFTP 单文件上传/下载、变更集原语已齐（`sftp.rs:244` 起的 `SftpMutation`，含 `CreateArchive`、`UploadStaged` 与 `ExtractedDirectory` 恢复令牌）；缺：
  - ~~整目录递归上传/下载~~：已实现（下载：远端 tar 拉回或逐文件落本地目录，`probe-sftp-dir-download.mjs`；上传：宿主打 tar 后经 `UploadStaged` + `ExtractedDirectory` 恢复令牌，`probe-sftp-dir-upload.mjs` 19/19；均有上限、预览确认与取消）。
  - ~~批量多文件传输队列~~：已实现（每绑定队列、并发 2、排队/进行/完成/失败/取消逐项可见、单项重试与全部取消，`probe-sftp-queue.mjs`）。
  - ~~双主机中转传输~~：已实现（宿主临时目录中转，两腿各用自身绑定句柄、凭据不交叉，EXCLUDE 语义与逐腿进度/取消，`probe-sftp-relay.mjs` 16/16）。
  - ~~大文件断点续传与分段限速~~：已实现于普通 SFTP 下载（`.part` 断点续传仅在远端大小与 mtime 不变时继续、KiB/s 限速、完成后 `sha256sum` 核对，`probe-sftp-queue.mjs`）。剩余缺口：SCP 下载不能续传（界面明示）；文件证据通道仍是单文件 512 MiB、非递归。
- ~~SCP 协议回退~~：已实现第一版并经真实 Dropbear 靶机（无 `Subsystem sftp`、无 sftp-server）验证。core 内嵌经典 SCP 协议（`scp.rs`，T/C 行握手与 ACK，不调用本机 ssh/scp 二进制）；`sftp_on_handle` 在子系统请求/握手失败且判定为"子系统缺失"时对 `DownloadNew`/`UploadNew`/`CollectFileEvidence` 回退，其余变体保留原始错误。回退侧远端 `scp` 存在性探测走白名单解析；`collect_scp_file` 复刻 SFTP 留证的双读+stat 一致性+SHA-256 核对，canonical 路径经 `readlink` 标记核对；上传要求绝对路径、父目录存在且拒绝覆盖既有路径（对齐 SFTP `EXCLUDE` 语义），失败清理远端半成品。证据 manifest 记 `transport: "scp"` 并附 SCP 版限制说明；无 SFTP 时报错明确告知浏览/修改不可用、留证仍可走 SCP。验证：`tools/lab/probe-scp-fallback.mjs` 8/8（连接、SFTP 面如实失败、路径句柄、留证字节与摘要一致、manifest 标记）。已知缺口收窄：exec+SCP 只读浏览已实现（固定 BusyBox 兼容命令列目录 + SCP 传输，界面横幅明示 rename/chmod/删除/递归不可用，`probe-scp-fallback.mjs`）；写操作与目录递归在此类目标仍无对应语义。

### 流量分析

- ~~pcap 离线解析~~：已实现（`pcap_offline.rs` 全自研：pcap/pcapng 容器、Ethernet/VLAN/raw/SLL/SLL2、IPv4/IPv6/TCP/UDP/ICMP、按四元组与方向的 TCP 重组与缺口标记、HTTP/1.x 含管道化/chunked/gzip、对象 SHA-256 导出、菜刀 `X@Y` 与 `->|`/`|<-` 回显；页面「流量分析」六视图；`probe-pcap-offline.mjs` 含真实容器抓包验证）。
- ~~恶意流量特征~~：已实现（冰蝎默认密钥 AES-128 强线索、菜刀、SQLmap、CS 周期心跳、frp 登录、ICMP 隧道、Stratum；均为线索+规则说明，不作定性）。决策（默认，用户可改）：TLS keylog 解密按议题推迟未做；冰蝎 v4 默认头模式因无可靠出处未纳入判定。

### Windows 侧

- ~~登录事件链分析~~：已实现（`windows_incident/logon_chain.rs`：4624/4625/4776/4648/4672/4634/4647 + System 7045 固定采集，按来源+账户 10 分钟链内分组，IPC/PsExec/WMIC/SharpRDP/爆破后成功五种指纹线索；win-dvc `LOGON_CHAIN`；本机 PowerShell 真实回读 31 条事件）。剩余缺口：真实 RDP 目标端到端采集（NOT_RUN）。
- ~~PowerShell 4104 与 WinRM/RDP 通道日志~~：已实现（`logs()` 新增 `winrm` 类别 6/91/168，`rdp` 类别含 RemoteConnectionManager 1149、LocalSessionManager 21/22/24/25 并新增 RdpCoreTS 131；PowerShell 4103/4104 经既有 powershell 类别与组合采集）。剩余缺口：真实 RDP 目标采集（NOT_RUN）。

### 基线小项（短期易补）

- ~~SSH 加密算法白名单~~：已实现（`baseline.rs` SSH 弱算法项按 `sshd -T` 生效值判定）。
- ~~SUID 包归属与 GTFOBins 标注~~：已实现（`perm-suid-ownership` 包归属核对 + `cmd_gtfobins.inc` 提权方式标注）。
- ~~systemd 自定义 unit 属主校验~~：已实现（`persistence-unit-owner`）。
- ~~SFTP 子系统引导修复~~：已实现（`ssh-sftp-subsystem` 经基线写入链补 `Subsystem sftp internal-sftp`，`sshd -t` 检查后重载；`probe-baseline-sftp.mjs`）。
- ~~Day1 课件对照~~：系统项（TMOUT、`pam_pwhistory` remember、`pam_wheel` 限制 su、sudo 操作日志、SSH AllowUsers/AllowGroups、90 天未登录账号）、Apache 六项（Indexes、server-status、运行用户、超时与请求大小、模块精简）、Tomcat 五项（manager/host-manager、AJP 8009、以 root 运行、目录列表、会话超时）已实现为只读基线项；MySQL 四项（匿名账号与 test 库、root 远程登录、口令策略、登录失败锁定）经 `mysql_instance.rs` 实例审查覆盖。均为检查不提供写入（SFTP 子系统除外，单独成项）。
- ~~攻击与隧道工具名单扩充~~：已实现（精确 basename 隧道工具名单，含 frp/nps/gost/earthworm/reGeorg 等；另在账号删除/锁定失败疑似命令被替换时给出工具可疑提示）。

### 连接辅助

- ~~SSH 本地端口转发~~：已实现（`port_forward.rs` + russh `direct-tcpip`；监听只绑 127.0.0.1，目的地限目标回环或当前 LISTEN 表内地址、需确认对话框明示本机可达性；8 转发/32 并发上限、可取消、随绑定关闭；`probe-port-forward.mjs` 18/18）。

### 本轮保留的决策与 NOT_RUN（2026-11-13）

以下为本轮采用的默认决策，可按需要改变：

- 默认不向目标上传静态工具；例外是用户主动发起并逐次确认的“进程活动监视”（规划见 2026-11-13 节；不上传的轮询方式与上传 pspy 均已实现，容器内验证，VM/实机 NOT_RUN）。可信工具路线的其余部分保持 待决策。
- 不做 Diamorphine 的 kill -63/-64 信号探测（会改变攻击者状态），检测经 kallsyms 与 `/sys/module` 差集。
- TLS keylog 解密按议题推迟，未实现也不暗示支持。
- 冰蝎 v4 默认 Accept/Content-Type 头模式无可靠出处，未纳入判定。
- IOC 与本机扫描结果不绑定案件记录（案件页已移除）。
- 仍为 NOT_RUN：真实 RDP 目标端到端采集、真实 SQL Server 实例、VM/实机的隐藏模块/隐藏进程真实命中、以及本波新页面中未进 CDP 巡页的截图。

### 不纳入范围

- CTF 与攻击工具（随波逐流、CTF-NetA、pwn 工具、tscan/fscan）及课件中的渗透、域渗透、抓密码内容：与应急工作台定位不符；仅取其防守侧排查位置清单作参考。
- 业务源码漏洞修补（Flask SSTI、PHP 反序列化/任意文件读取、ThinkPHP 控制器过滤等 writeup 中的代码改写）：属于应用开发，只取其日志溯源与“改完后验证、重启业务”的部分。

## 2026-10-27 Windows 通道与传输独立窗口

底部抽屉已迁为可缩放、最大化和复用的独立 Tauri 窗口；四个标签共享主工作台状态，关闭收起保留草稿，离开工作台参与任务和草稿检查。专用窗口权限、会话绑定、单次操作领取及全局通知接线见 [实现与验证边界](WINDOWS_CHANNEL_WINDOW.md)。真实 RDP 目标命令与文件传输矩阵仍待验证，合成桌面测试不替代远端验收。

## 2026-10-27 Windows 采集提示与大结果

重复的采集警告收进全局通知，页面只保留紧凑的范围/部分读取入口；分批采集也保留隐藏模块的警告。采集端与 DVC 接收端新增有界分段回传、请求/会话隔离及完整性校验，启动项容量提高到每类 5000 / 合计 20000。见 [实现与验证边界](WINDOWS_COLLECTION_NOTIFICATIONS.md)。真实 RDP 分段链路、旧端组合和可继续的远端分页仍待验证/实现，领域采集上限及 64 条通知容量没有被解释为全量覆盖。

## 2026-10-27 Windows 对象详情与删除

服务、驱动、计划任务的每行新增可见详情和全部操作入口；详情按对象编号读取运行信息、触发器 / 配置和依赖，不再依赖滚动到列表底部。删除接入一次性确认与独立缺失复核，要求先禁用、停止并满足保护条件，只移除注册定义，文件保留且没有一键恢复备份。见 [实现范围与验收](WINDOWS_INVENTORY_ACTIONS.md)。

自建任务删除及拒绝路径已有本机脚本证据；真实服务 / 驱动删除、等待 SCM 引用释放、真实 RDP 和其他系统矩阵仍待验证。完整备份恢复、对象重建竞态、驱动包卸载与业务恢复不能由本轮有限能力替代。

## 2026-10-27 Windows 快捷处置与启动项分类

服务、驱动、计划任务已接通快捷按钮、一次性计划确认、独立回读、处置记录与配置恢复；启动项增加 19 类固定采集、分类计数和缺口说明，相关对象可跳转处置。范围与实际验证见 [专项说明](WINDOWS_STARTUP_CONTROLS.md)。

隐藏计划任务已用当前用户独有的休眠任务验证启用、禁用、运行与停止。管理员服务 / 驱动变更及真实 RDP 全链路仍为待验证，不能把脚本与界面测试算作该矩阵通过。记录归档 / 导出、多用户 / 离线持久化、WMI 可恢复处置、完整驱动卸载和不可删除文件治理继续保留；100 条操作记录达到容量后拒绝写入，当前没有专用归档按钮。

## 2026-10-27 Windows 进程与通知增量

进程详情已接入单进程 / 进程树的固定预览、一次性确认与逐项退出复核；服务、驱动、计划任务具有独立的只读清单入口。远程桌面支持复制免落地脚本，主窗口操作提示集中到状态栏左侧通知中心。边界与验证见 [专项说明](WINDOWS_PROCESS_AND_NOTIFICATIONS.md)。

真实 RDP / Server / 保护进程矩阵、驱动强制卸载、服务与任务的完整修补恢复仍未验收。进程处置日志的专用浏览和归档，以及独立文件编辑子窗口的跨窗口通知转发保持待办，不因本次界面与脚本测试关闭。

## 2026-10-26 Windows 常见事件流程融合

依据 18 份已读取的 Microsoft、NIST 与 MITRE 原始资料，接入 14 类 Windows 响应方案，覆盖现场初查、勒索、挖矿、木马、异常登录、任务/WMI 驻留、脚本、凭据、横向、IIS、驱动/删除受阻、防护/日志异常、外传和域控专项分流。界面接通现有调查入口，离线可查，采集失败/断连保持可见，查询建议不覆盖草稿或自动执行，见 [方案与后续路线](WINDOWS_RESPONSE_PLAYBOOKS.md)。

后续按可验收流程推进完整事件日志留证、驱动/文件访问调查、多用户和 WMI 持久化、带恢复条件的遏制，再扩展内存取证、EDR/备份和 AD。每一项分别补充对象身份、权限、备份与恢复、独立复核和真实 Windows 环境证据；有限方案目录不代表应急响应全覆盖。

## 2026-10-26 Windows 排查与配置增量

案件工作台的入口和页面已按用户要求移除，旧案件/证据存储与其他模块的留证数据保留；下文较早的案件页面接线描述为历史记录。文件与注册表按确认草案改为底部详情，新增 32 个目录、37 个注册表预设、28 个只读命令预设，以及文件 ACL / 进程 / 服务 / 驱动路径诊断，见 [Windows 排查预设](WINDOWS_IR_PRESETS.md)。

69 项基线检测保留，19 项固定注册表策略已接通一键选择、原值备份、一次性计划、逐项回读、取消后续与有并发保护的恢复，旧无备份直接修复路径移除，见 [Windows 基线变更](WINDOWS_BASELINE_CHANGES.md)。实际 Windows 管理员目标写入/恢复和业务连接仍为实验性 / NOT_RUN；域成员和域控自动配置拒绝。口令/审计批量修补、其他用户策略、驱动卸载/强制删除、离线恢复、完整 Windows 版本与 RDP 矩阵保持待办，不以界面合成数据关闭。


本表承接根目录 `AGENTS.md` 的全部产品范围。应急响应是主线，通用运维、Docker/Kubernetes 与系统/中间件/数据库基线都持续建设。状态描述具体已获得的证据，不以有限覆盖代替国内外全产品的兼容目标。

产品已由 LovelyRes 改名为 LovelyHawk，桌面壳已从 Electron 换成 Tauri 2（宿主 `crates/lovelyhawk-desktop`，前端 `ui/`，后端 `crates/lovelyhawk-backend` 以库的形式链接进桌面进程）。下文 2026-09-07 起的工作基线、证据表、测试计数与命令都是 Electron 时期的记录：其中的 `pnpm electron:*`、`lovelyres-core`、`lovelyres-electron-backend`、`scripts/electron-*.ps1` 和 `target/electron-debug/...` 是当时实际运行的命令与证据，保留不改。现行对应入口为 `pnpm ui:check`、`pnpm desktop:build`、`pnpm desktop:test:debug`、`cargo test --locked --package lovelyhawk-core` / `lovelyhawk-backend` / `lovelyhawk-desktop` 及 `pnpm release:*`。Tauri 桌面壳上的界面与原生验收不能由这里的 Electron 结果代替。

## 当前工作基线（2026-09-07）

- 已核对当前仓库为 Electron + React + Rust 三个 crate 的架构；本轮开始时工作区已有大量未提交改动，作为既有工作保留。
- 已重写 `AGENTS.md`，纳入测试自动执行、真实环境逐次确认，以及纯新手和专家用户共同的体验要求。
- 已运行 Electron 原生 CDP smoke，以及 Ubuntu、Alpine 上的文件处置 UI 实测；其他发行版和 Docker/Podman/k3s 探针仍待本轮执行。
- Windows 本机存在 Node、pnpm、Cargo 和 WSL Ubuntu，WSL Docker 可用。已盘点发行版/服务/编排镜像，复用了现有 Ubuntu 与 Alpine 靶机；服务和编排容器本轮盘点时大多处于停止状态，未据此声称其运行路径通过。

## 并行的产品方向

这里的“并行”指长期需求都保持有效，不要求以多个 agent 或同时修改所有模块实现。

| 方向 | 已有实现入口 | 后续验收重点 | 当前结论 |
| --- | --- | --- | --- |
| 应急响应闭环 | `command_workbench.rs`、`EmergencyCommandsPage.tsx`、日志/抓包/SFTP/完整性模块 | 采集与证据导出、路径处置、迟到结果失效、操作恢复、报告关联 | Ubuntu/Alpine 文件处置及下载留证→案件→报告已实测；案件工作台的创建/检索/笔记快照/报告已接通；离线查看/归档恢复已验证，结案与重新调查进展见下方阶段记录；其他现场类型与处置闭环继续验收 |
| 系统管理 | `system_info.rs`、`SystemInfoPage.tsx` 及行操作 | 多发行版与缺工具降级、进程/网络/持久化项的准确关联、计划与复核 | 部分实现；跨环境矩阵待验收 |
| Docker/Podman | `docker.rs`、`DockerPage.tsx`、`tools/lab/orchestration/` | 对象身份、runtime 差异、日志/终端、动作失败与恢复、宿主/容器边界 | Docker 29.1.3 实验环境只读、动作与原生 UI 通过；2026-10-11 加入容器内目录浏览（BusyBox 与 GNU 镜像）、与镜像相比的文件改动和宿主侧进程列表（快速排查），Podman 实验主机上同样通过，并修正 Podman 在 cgroups v1 下的警告混进进程表、改动列表和容器日志 |
| Kubernetes | `kubernetes.rs`、`KubernetesPage.tsx` 及编排探针 | context/namespace/RBAC、对象版本、故障工作负载、扩缩容与节点操作复核 | k3s v1.31.4+k3s1 单节点的副本就绪、超时恢复、并发保护、停止工作负载及原生 UI 通过；2026-10-11 加入 Pod 终端（独立窗口，打开前核对 UID 与运行状态，关闭后结束遗留进程）、只读 Pod 文件浏览与读取、重启前日志，实验集群与桌面界面通过；RBAC 拒绝 exec、多容器选择与业务接口健康闭环待补 |
| 系统基线 | `baseline.rs`、`BaselinePage.tsx`、基线读写探针 | 有效配置、默认/重复/include、无法判断状态、检测→修补→复检→恢复 | 临时副本验证不代表完整运行时闭环；发现跨作用域风险后已禁止 Nginx 通用写入，检测与待复核流程已实测。2026-10-12 起可写单项（不含 Nginx/Redis/PostgreSQL）在桌面经计划、确认、检查、重载、读回完成修改与放回，sshd 按 Include 位置判断生效文件，容器内已验证，见 `BASELINE_CHANGE_VERIFICATION.md`；systemd 主机与虚拟机未测 |
| 中间件 | `middleware.rs`、`middleware_document.rs`、配置工作台与服务靶机 | 按产品和版本发现实例、配置验证、健康检查、失败恢复与幂等性 | Nginx 1.27.5 候选风险检测及普通进程的目录、版本与 TLS 协议修补、恢复、Electron 时期的桌面/HTTP/TLS 实测通过；自动业务健康与其他产品矩阵继续验收；Nginx、Apache httpd、Redis 与 HAProxy 可视化编辑（2026-10-11）已接通：配置页“可视化编辑”把配置文件显示成树（Nginx 块、Apache 区段、Redis 一行一项、HAProxy 关键字区段），常用项带中文说明，新项可在上方带一行中文注释，逐项改、加、删、移，经 core 重新解析校验，另存为新文件，敏感行隐藏且锁定，解析不了的内容原样保留，真实窗口 58/58；2026-10-12 再接入 MySQL、MariaDB 选项文件与内置目录里的数据库配置文件（按所选版本标出目录说明、目录参数检查后写入草稿、服务器生成的文件只读），真实窗口 62/62；生成器搜索框按目标给出做法、数据库目标与参数、配置文件和暂时做不到的原因，赋值句子先预览、确认后才写入本地草稿（真实窗口 4/4，config-generator 遗留 90 个测试 ID 全部替代）；Tomcat 的可视化编辑尚未接入 |
| 数据库 | `database*.rs`、配置 schema、运行时与来源模块 | 产品身份、实例与生效来源、国内外方言差异、权限/加密/审计、可恢复修补 | Redis 与 PostgreSQL 候选基线的误判、来源和建议已修正并有原生验证；实际实例、修补和恢复链路继续建设；schema 不能作为部署证据 |
| 新手与专家体验 | 现有页面、共享对话框、主题、搜索与菜单 | 明确下一步、可发现操作、准确反馈、专家快捷路径、键盘与布局 | 持续验收每条实际业务流程 |

以上源码路径分别位于 `crates/lovelyhawk-core/src/` 与 `ui/src/renderer/`；精确接线状态以 `UNWIRED_FEATURES.md`、`DESKTOP_UI_LEDGER.json`（Electron 时期的 `ELECTRON_UI_LEDGER.json` 作为历史记录保留）和实测结果为准。

## 兼容范围与证据要求

| 范围 | 当前可用的仓库依据 | 不能据此推断的能力 |
| --- | --- | --- |
| Ubuntu、Debian、Alpine、Rocky、Alma、openEuler、Anolis、deepin、SUSE | `tools/lab/matrix/` 与 `tools/lab/lab-target.mjs` 的靶机定义 | 全版本、全架构、真实宿主内核和启动行为 |
| UOS、麒麟及其他国内外发行版 | 纳入适配目标；当前靶机清单未覆盖 | 已验证兼容或已经取得合法测试镜像 |
| Nginx、Apache、Tomcat、HAProxy | `tools/lab/services/build.sh` 的服务定义与配置模块 | 全版本、全指令、所有部署方式或全部修补闭环 |
| MySQL、MariaDB、PostgreSQL、Redis、MongoDB、openGauss、TiDB | 服务定义、数据库模块和 schema | 所有实例发现、动态设置、恢复、客户端与服务端版本组合 |
| 达梦、人大金仓及其他国内外数据库/中间件 | 国内产品 schema 与长期范围 | schema 之外的运行时适配、真实部署或实测兼容 |
| Docker、Podman、k3s | `tools/lab/orchestration/` | 所有 Docker/Kubernetes 版本、发行版、CRI、CNI、存储与多节点集群 |
| SSH | `tests/ssh-compat/matrix.json`、`SSH_COMPATIBILITY.md` | 未实际运行的认证、服务端、网络、架构和权限组合 |

每个新增产品或版本应记录：产品与版本、架构、部署方式、具体能力、前提、测试日期、命令与退出状态、证据路径、未覆盖项。商业环境缺少授权或镜像时记录缺口；其他可用环境继续推进。

## 本轮推进顺序

1. 完成开发规范与工作区/工具/实验资源盘点。
2. 运行当前 Electron 和相关 Rust 验证，区分既有失败与本轮引入的问题。
3. 优先完善应急现场的实际操作流程与新手反馈，同时保持既有专家操作效率。
4. 使用现有隔离靶机验证系统基线、服务修补、Docker 与 Kubernetes 真实路径；按发现修正产品与探针。
5. 对每个闭环保留截图、测试结果和独立回读证据，更新具体状态与未解决项，继续扩展其他产品/版本。

## Tauri 2 迁移验证（2026-10-10 至 2026-10-11）

桌面壳从 Electron 换成 Tauri 2，项目改名 LovelyHawk。以下结果只覆盖 Windows x64 与列出的场景，证据目录在本机 `target/` 下。

| 检查 | 实际结果 | 命令 |
| --- | --- | --- |
| 完整质量门禁 | 通过（2026-10-11 Docker / Kubernetes 应急工具与文件管理到期提示之后再跑一遍）：格式；整个 workspace 的 clippy 无警告；Rust 1988 项通过 / 10 个实机测试忽略；UI 124 个文件、1007 项测试，类型检查与构建；源码（含已构建的 `ui/dist`）、依赖与账本门禁；调试构建 CDP 冒烟 42/42 | `pnpm release:quality-gate` 等，见账本 `desktop-quality-gate-2026-10-11x` |
| 界面打磨 | 2026-10-11 两轮：未连接页统一为说明卡片加“新建连接 / 连接目标”；配置页模式开关三种模式同一位置、产品分组用中文；数据库空状态给出“添加数据库连接”主按钮；命令工作台“运行只读调查”主按钮样式此前一直被覆盖，已修正；“能力约 N 分钟有效”等实现用语改成人话；命令审计、AI 历史、案件、完整性、Nginx 修补的文字层级与主操作统一。列表到期后自动续期尚未做，见 `OPEN_ITEMS.md` 第 24 条 | 账本 `desktop-ui-polish-2026-10-11`、`desktop-ui-polish-2026-10-11b` |
| PostgreSQL 桌面实测 | 127/127，PostgreSQL 16.15（Debian 13，x86_64），本次自建容器、只在其中安装 python3；数据库条目仍为 Pending（只接通了 PostgreSQL 只读检查） | 账本 `desktop-postgresql-2026-10-11`；`target/lab-postgresql-desktop/37e101c1-fa09-4433-925e-52d129a4c64b/` |
| 严格门禁 | 实际运行：账本之前的所有步骤都通过，在账本完整性检查处按设计停止（仍有 Pending 条目）；它之后的整个 workspace 格式、clippy 与测试（1856 项）单独运行也都通过 | `pnpm release:quality-gate:strict` |
| 门禁自检 | 质量门禁的失败传递，源码门禁与依赖门禁的正反例（含 GPUI、缺少锁文件、页面 Node 访问、打包内容远程加载）全部通过 | 各脚本 `-SelfTest` |
| 调试构建 CDP 冒烟 | 42/42 通过，无控制台错误，关闭后正常退出 | `pnpm desktop:test:debug` |
| 关闭握手 | 6/6 通过；把宿主临时改回旧行为时，这个探针会失败 | `node ui/scripts/probe-close-handshake.mjs` |
| 终端与文件编辑子窗口（lab-ubuntu） | 17/17 通过 | `node ui/scripts/probe-terminal-window.mjs` |
| 安全速查 | 15/15 通过（两次启动：目录、搜索、筛选、展开、复制、收藏跨重启保留、可访问名称） | `node ui/scripts/probe-security-reference.mjs` |
| 笔记 | 27/27 通过（含标签上限的错误状态、删除后结果提示不被清掉） | `node ui/scripts/probe-notes.mjs` |
| 连接管理 | 34/34 通过（刷新、导出不含秘密且不覆盖、删除确认、导入整体拒绝四类坏文件、跨重启保留、连接文件损坏时程序仍可用） | `node ui/scripts/probe-connections.mjs` |
| 应用日志 | 21/21 通过（另含 `data/logs/lovelyhawk.log`：清空浮层不动文件，程序退出后文件仍在、每行完整带时间，记录了被拒的保存，没有口令） | `node ui/scripts/probe-application-log.mjs` |
| 确认对话框 | 12/12 通过（修正前为 10/12：Tab 在“放弃更改”确认框里不移动） | `node ui/scripts/probe-dialogs.mjs` |
| 通知 | 9/9 通过 | `node ui/scripts/probe-notifications.mjs` |
| 设置 | 18/18 通过（取消不留痕、越界拒绝、各分组保存生效、API Key 只写不落明文、清除需确认、跨重启保留） | `node ui/scripts/probe-settings.mjs` |
| 无障碍与资源巡检 | 74/74 通过：欢迎页、15 个页面、5 个浮层离线各一遍，再连接 lab-ubuntu 巡检 15 个页面；每个可操作控件都有可读名称，无外部资源 | `LAB=ubuntu node ui/scripts/probe-accessibility.mjs` |
| 主机全景（lab-ubuntu） | 12/12 通过（摘要、26 个标签页、刷新、复制、恶意命名进程按纯文本显示、断开即清空） | `LAB=ubuntu node ui/scripts/probe-system-info.mjs` |
| 终端窗口里的文件传输、撤销与取消（九台靶机） | 每台 23/23 通过：经系统保存框下载且字节一致、经系统打开框上传（先看计划再执行，主机上哈希一致）、编辑器原子写回并在主机上复核、主机改过文件后拒绝保存且不动原文件；删除后撤销把文件连同字节和 640 权限放回且不留副本、改权限后撤销回到 640、重命名后原名被占就拒绝撤销且两边不动、新建文件夹撤销后删除；上传不提供撤销；撤销先问、焦点在“不撤销”、只给一次；6 GB 下载在 3～7 MB 时取消，本机不留半个文件，60 MB 上传取消后服务器上不留文件。只在容器上跑过 | `LAB=<靶机> node ui/scripts/probe-sftp-transfers.mjs` |
| 主机密钥与连接失败（lab-ubuntu / lab-debian / lab-alma） | 21/21 通过，未改动任何主机：导入的连接带着不属于该主机的指纹时拒绝连接、不提供信任入口、保留原指纹；首次连接显示的指纹与主机上 ssh-keygen 列出的一致，焦点在“取消尝试”，按回车是拒绝，不记录指纹、不留会话；确认后连接并记下正是这个指纹；口令错误、端口不通、主机名解析不了分别说明是哪一种失败（中文）。发现并修正：首次确认时焦点在“信任此指纹”，一次回车就会信任未核实的密钥；所有连接失败都只显示同一句英文 | `node ui/scripts/probe-host-key.mjs` |
| 交互认证 / MFA（lab-rocky，仅本次运行开启） | 8/8：服务器提示原样显示、输入隐藏且有焦点，答错拒绝并说明认证没有通过，答对连上，回答不写入数据目录；结束后确认 lab-rocky 恢复为不开放键盘交互认证。首次运行发现在回答框输入会让整个窗口空白，已修正 | `node ui/scripts/probe-mfa.mjs` |
| 日志留证（九台靶机） | 每台 28/28：在日志分析里打开的日志可以“留存这个日志文件”，走与命令工作台相同的下载留证：留存副本的 SHA-256 与主机上的 sha256sum 一致，清单记下来源路径与摘要，关闭后焦点回到按钮。首次截图发现留证对话框在日志页没有样式、显示成页面下方的散文字（文件完整性页先打开时也一样），已把对话框样式独立出来 | `LAB=<靶机> node tools/lab/probe-ui-log-analysis.mjs` |
| Kubernetes（k3s v1.31.4 单节点实验集群） | 只读 24/24、动作 30/30、就绪与恢复 35/35（含桌面界面说明超时与恢复、不把副本恢复说成业务恢复、0 副本明确显示、断开清空对话框、未确认的第二个动作不执行）、桌面正常扩缩容 10/10；结束后集群复原。RBAC 拒绝、多节点与其他版本未覆盖 | `probe-kubernetes.mjs`、`probe-kubernetes-action.mjs`、`HEALTH_UI=1 probe-kubernetes-health.mjs`、`LAB=kubernetes probe-ui-orchestration.mjs` |
| 日志分析（九台靶机） | 每台 21/21 通过：/var/log 之外的日志、无扩展名的 access_log、catalina.out、面板站点日志都能列出并打开；.gz 与 RPM 式无扩展名轮转能列出并解压成文本读取（屏幕上没有压缩字节），源码包不会被当成日志；敏感内容原位标注；分页显示页码与总数并可跳页；搜索只返回埋入的那一行。容器里没有 journald，日志服务来源未覆盖 | `LAB=<靶机> node tools/lab/probe-ui-log-analysis.mjs` |
| 终端里的中文输入法与终端尺寸（lab-ubuntu / lab-alpine / lab-rocky） | 12/12 通过：输入法分几步组字后上屏的“中文”以 UTF-8 送到 shell 且只送一次，放弃的组字不发送，按键与组字顺序不乱，输出与命令行都显示中文；终端在输入后不横向滚动，网格从第一个提示符起完整落在框内，隐藏/显示文件管理后重新适配。首次运行发现三处所有终端窗口共有的显示问题：输入法组字时框体横向滚动、首列被遮；网格按带内边距的框和字体加载前的字宽计算，右侧约 5 列和底部几行被裁掉；修正后又露出 xterm 黑色底的细条。均已修正 | `LAB=<靶机> node ui/scripts/probe-terminal-ime.mjs` |
| 在文件夹里打开终端（九台靶机） | 每台 16/16 通过：文件夹右键与工具栏“在这里打开终端”，文件上不提供；名字是 `it's a dir; touch PWNED` 的文件夹，shell 在里面且名字里的命令没有执行；新窗口没有文件管理，SSH 窗口的文件管理照常可用；再次请求开第二个 shell；exit 关闭窗口；列出后被删掉的文件夹、第 5 个终端都会留下窗口说明原因，关掉一个后再请求可以打开；状态栏不再在没有会话时写“已连接”。只在容器上、以 root 登录跑过 | `LAB=<靶机> node ui/scripts/probe-directory-terminal.mjs` |
| Kubernetes 导出 YAML 清单（k3s 实验集群，本次自建命名空间） | RPC 15/15、真实窗口 8/8：Pod、Deployment、Node 的清单是列表里那个对象的（UID 与 kubectl 独立读到的一致），原文含环境变量里的明文值原样保留，文件头写明来源主机、上下文、对象、UID、读取时间（本机时钟）与明文口令提示；命名空间行、伪造句柄、删除后同名重建的 Pod 各自被拒；导出不改动集群；关掉保存对话框不写不提示，已存在的文件不覆盖。顺带：窗口最小时 Docker 容器表把名称列和操作列固定在两侧、中间读数横向滚动；Kubernetes 搜索框不再截断提示文字 | `pnpm lab:kubernetes-manifest`、`pnpm lab:ui-kubernetes-manifest` |
| 字号统一（全部页面、浮层与子窗口） | 样式表原有 774 处字号、29 种取值（11.5/12/12.5/13/13.5px 混用于同类文字，浮层标题 24px 而页面标题 22px，未设字号的文字落到浏览器默认 16px，下拉框不继承页面字体）。现为一套字号阶梯：12 辅助信息、13 正文与控件、14 阅读文字（确认对话框的计划正文原为最小的 12px）、16 卡片与分区标题、18 面板与对话框标题、22 页面与浮层标题、28/38 大数字与欢迎页标题；按角色对齐后，各页面标题一律 22、分区标题 16、按钮/输入框/说明文字 13。测试禁止样式表出现字面字号。改后调整：文件管理的时间列与大小列按实测宽度重排，Docker 容器名不再被裁掉最后一个字、镜像只在 `:` `/` `@` 后换行、统计卡片说明不再折行 | `pnpm ui:check`（type-scale.test.ts）、`node ui/scripts/run-debug-smoke.mjs`、`LAB=<ubuntu\|docker> [VIEWPORT=1080x700] pnpm lab:ui-accessibility` |
| 无障碍与版面（真实窗口；未连接 15 页 + 连接后 15 页、主机全景全部标签、终端、文件编辑与容器窗口） | 未连接冒烟 95/95（默认尺寸、1080×700 最小窗口、深色主题）；连接 lab-ubuntu 后 1280×800 与 1080×700 各 191/191，svc-docker（含容器窗口）194/194（lab-alpine、lab-rocky 另跑 184 项版本也全部通过）：每个可见控件有名称（字段的选项不算名称）、图片有替代文字、id 不重复、页面有标题、整页不横向滚动、浮层是有名称的对话框并接住焦点、Esc 关闭后焦点回到打开它的按钮、Tab 落在带焦点框的控件上、无控制台与请求错误。审计脚本的反向自检植入五种缺陷全部报出。首次运行发现并修正：网络抓包页的两栏按窗口宽度而不是页面实际宽度换行，1280 宽的窗口里详情栏伸出右边、整页横向滚动；配置页的视图标签在窄于最小窗口时伸出卡片；文件编辑窗口的样式把标题栏的最小化/最大化/关闭也画成了带框按钮，与其他窗口不一致；命令工作台连接后没有任何页面标题（加载期间读屏软件读不到页名）。打包后的程序尚未覆盖 | `node ui/scripts/run-debug-smoke.mjs [--width 1080 --height 700] [--theme dark]`、`node ui/scripts/check-accessibility-audit.mjs`、`LAB=ubuntu [VIEWPORT=1080x700] pnpm lab:ui-accessibility` |
| 基线单项修改与放回（AlmaLinux 9、Debian 12 一次性容器；sshd 读法九个发行版） | 改动链路每次 25/25、真实窗口各 11/11：计划不改主机、未确认不执行、写入后 `sshd -T` 为 no、原会话仍可用、计划只执行一次、非法值/已是该值/只检查项/伪造句柄/文件路径均拒绝、放回后逐字节一致、之后被手工改过的文件拒绝放回。九个发行版各 37 项：每种 Include 布局先问 `sshd -T`，扫描值、来源文件与文件查看的生效行一致；写入程序在三台主机上由 `sshd -t`/`sshd -T -C` 核对 Match 块不被改动。首次运行发现并修正：主文件没有 Include 时附加文件仍被当成生效位置（改动写进 sshd 不读的文件）、sshd 写入删除 Match 块里的同名行或把新行追加进末尾的 Match 块、改完后回执随重新扫描消失、历史把“已恢复 → no”写得像改成了 no。systemd 主机、虚拟机与实机未测 | `LAB=<发行版> node tools/lab/probe-baseline.mjs`、`node tools/lab/probe-baseline-write.mjs <靶机>`、`BASELINE=<deb\|el> pnpm lab:baseline-actions`、`BASELINE=<deb\|el> pnpm lab:ui-baseline-actions` |
| 命令工作台右键处置与撤销（九台靶机） | 后端每台 49/49 通过：SUID 扫描行可直接下手、去掉执行权限后主机上 setuid 与执行位都没了、同一计划不能执行两次、计划后被改过就不动并说明“文件保持原样”、隔离留下只有属主可读的副本；撤销把权限放回 4755、同一次只能撤销一次、隔离后原路径又出现文件时拒绝撤销且两边原样、原路径空着时把文件连同 4755 放回去。桌面窗口（lab-ubuntu）27/27：撤销先问、焦点在“不撤销”、确认后主机回到 4755、不再提供第二次、焦点回到“关闭”。只在容器上跑过；这两种操作只改文件权限和同目录改名，不涉及内核、启动、审计、防火墙或服务管理 | `LAB=<靶机> node tools/lab/probe-emergency-path.mjs`、`node tools/lab/probe-ui.mjs` |
| 文件完整性：新建基线、比较与处置（九台靶机） | 每台 19/19 通过：页面没有实现术语；一个位置都没勾选时不能新建；新建前先确认并说明清单写在哪里、文件不会被改动，确认前主机上没有写任何东西；只多出一份清单；比较找出新增和改动的文件并带“文件操作”；隔离前计划在屏幕上时文件没动，隔离后原位置消失、留有副本，撤销恢复 4755；改动的文件去掉执行权限后为 644；第二次新建在中途取消，不留清单；无控制台错误 | `LAB=<靶机> node tools/lab/probe-ui-integrity.mjs` |
| 命令历史（lab-ubuntu / lab-debian / lab-rocky） | 23/23 通过：真实运行产生的记录、来源显示为“应急命令”、清单检查说明历史保存什么、复制、搜索、删除确认与 Escape、换主机不串历史、重连后保留；“到命令工作台再次运行”选中同一项检查并把焦点放在运行按钮上、不自动运行，运行后历史里有两次；26 条真实记录分两页，上一页/下一页都对；清空 | `node ui/scripts/probe-command-history.mjs` |
| 处置报告（lab-ubuntu / lab-debian） | 19/19 通过：文件管理里真实新建并删除一个名字是恶意 HTML 的文件夹，报告计数正确、三种预览都按纯文本显示且 Markdown/HTML 中已转义、复制一致、另存 MD/HTML、拒绝覆盖并说明原因、取消不写文件、焦点返回、换主机不串记录 | `node ui/scripts/probe-disposal-report.mjs` |
| 连接编辑（含真实私钥登录） | 33/33 通过：经系统打开框选私钥（选到 .pub 会被拒并说明）、真实私钥登录 lab-ubuntu 并记住主机指纹、改名保留指纹、改主机先提示再作废指纹、堡垒机与证书、私钥口令保存与移除、改用交互认证时提示并删除已保存密码、Agent 指纹格式校验、端口越界、放弃未保存修改前询问；页面与数据文件里都没有密码明文 | `node ui/scripts/probe-connection-editor.mjs` |
| 长命令期间的终端（lab-ubuntu） | 6/6 通过：主窗口命令卡满 30 秒期间，终端回显 280 毫秒、文件列表刷新 309 毫秒；改动前同一探针 40 秒内都没有回显 | `node ui/scripts/probe-terminal-during-long-task.mjs` |
| 编辑窗口关闭握手（lab-ubuntu / lab-debian） | 12/12 通过：有未保存修改时，页面外关闭（Alt+F4、任务栏）、关闭主窗口、连接新目标、断开连接都先询问，取消后修改和窗口都在；没有修改时直接关闭；主机上的文件从未被写入 | `node ui/scripts/probe-editor-close.mjs` |
| Docker 页与容器终端（svc-docker） | 36/36 通过（2026-10-11 起容器终端窗口不再带主机的文件管理；文件对话框默认浏览容器目录，从列表里打开文件进编辑器；详情顶部“快速排查”读到的进程数与守护进程自己的一致）：容器内文件打开、编辑后按计划写入并在容器里回读一致、打开后被改过则拒绝保存、不存在的文件如实说明、从容器复制到主机且字节一致、未保存关闭先询问；数量与守护进程一致、按名找到全部预置容器、安全审计点名特权/挂 sock/宿主网络/宿主 PID、镜像网络存储卷、详情与日志、启停在守护进程上复核、立即退出的容器启动判失败并回滚、两个容器各开一个终端窗口且重复打开复用、关窗后容器里留下的命令被结束、断开即清空 | `node ui/scripts/probe-docker.mjs` |
| Kubernetes Pod 工具（k3s 实验集群，桌面界面） | 13/13 通过（2026-10-11）：运行中的 Pod 行上有日志、终端、文件、排查，只有重启过的有“上次日志”，未运行的不给终端和文件；崩溃循环 Pod 的上次日志写明退出原因；Pod 文件从根目录浏览到 `/etc/hostname`，内容是 Pod 名且摘要一致；Pod 终端在独立窗口里、主机名是 Pod 名，断开连接后窗口关闭、终端里的命令被结束；无控制台错误 | `pnpm lab:ui-kubernetes-tools` |
| 配置生成器布局（真实窗口，按 GPUI 测试的尺寸） | 15/15 通过（2026-10-11）：页面区 1200×800 时三栏并排、各自滚动、页面不滚；所选特性的编辑器紧贴其行下方（六种产品）；PostgreSQL 14–18 与 MariaDB 四个版本可选、搜索收窄（遗留失败测试之一，同样断言现已通过）；四种预览用真实滚轮滚到最后一行而页面不动；可视化编辑长值单行截断、矮窗口滚到完整内容；预览只是文本节点。顺带修正矮窗口里说明和按钮叠在生成文字上。替代 13 个遗留测试，待办剩 36/90 | `pnpm lab:ui-config-layout` |
| 配置生成器交互（真实窗口） | 11/11 通过（2026-10-12）：MySQL、MariaDB 选项文件接入可视化编辑（选项组只在最外层、选项必须在组里、!include 放在文件开头、约 70 项中文说明，生成器写出的每个选项都有说明），MySQL 与 PostgreSQL/MariaDB 快速配置叠加/移除/各自重置/导出不覆盖后可按原文打开；修正 MariaDB 草稿因注释含 passwords 被整份隐藏、数据库草稿文件名旧前缀；待办剩 25/90。更早 9/9：Apache 依赖叠加/移除/重置后在可视化编辑中按原文打开；Redis 必需项拒绝时说明原因，复制与导出逐字节一致、再导出同一路径被拒绝；Tomcat 三文件复制按 BEGIN/END 标注，新增“导出全部 3 个文件…”新建文件夹写入、已存在即拒绝。顺带修正 Redis 拒绝无提示、预览头英文 REVISION、Tomcat 文件夹旧前缀；再替代 3 个遗留测试；可视化编辑里有未另存修改的 Apache 文档被导入的 Nginx 文件替换前先确认、取消不动、确认后逐字节一致（`probe-ui-config-visual.mjs` 59/59），待办剩 27/90。此前 6/6（2026-10-11）：恢复默认后再生成与首次逐字节相同；静态站点 SPA 回退与 404 回退互换、取消后回到基线；四套主题预览对比度 15–17.7；在搜索框输入“让 /admin 从外部访问全部返回 403”即给出 Nginx 403 目标，点后勾选规则、填入路径、编辑器紧贴行下方，草稿含 `= /admin` 与 `^~ /admin/` 两个 403，可视化打开后结构与全文一致。顺带修正静态模式不带默认特性、站点域名英文标签、重置不清提示、失效提示里的英文词。替代 5 个遗留测试，待办剩 31/90 | `pnpm lab:ui-config-interactions` |
| 配置生成器目标搜索与数据库赋值（真实窗口） | 4/4 通过（2026-10-12）：按目标列出 PostgreSQL 远端访问的各步骤（含必须在配置文件之外完成的步骤）、按作用找到 max_connections 并在可视化编辑中选好版本与参数、按产品找到 MogDB 配置文件，未另存的修改离开前先确认，神通、Apache TLS、PostgreSQL 15 给出做不到的原因；赋值句子只出现确认卡片，改值后确认才新建草稿（全文正好一行、另存逐字节相同），多候选先选、拒绝不回显值，可视化编辑里的一句话写入在重复参数或另一版本有未另存修改时先拦下，同版本原位写入一次。替代最后 3 个遗留测试（另 1 个由后端租约测试替代），待办 90/90 | `pnpm lab:ui-config-goals` |
| 容器与 Pod 目录、文件改动与进程（RPC） | Docker（BusyBox、GNU）、Podman、k3s Pod 全部通过：临时种下的换行名、setuid、所有人可写、符号链接如实列出，`..` 路径和伪造句柄拒绝；种下的计划任务文件和从 /tmp 运行的进程出现在改动和进程表里，结束后按确切路径清除；Podman 每行都是真实进程 | `pnpm lab:container-files`、`pnpm lab:kubernetes-terminal` |
| Java 热更新（本次运行创建的 Temurin 17 容器） | 29/29 通过：扫描列出进程及其 JAR（含只能从打开的文件找到的通配类路径 JAR），按进程筛选；按路径打开列表外的 JAR，含 `..` 的路径不发送、符号链接被拒并在输入框旁说明；生成与取消计划不改动主机；确认后 JAR 里正好是所选的类，属主与权限不变，运行中的进程在重启前仍用旧类；从记录恢复后逐字节一致、属主与权限不变；JDK 目录被改成组可写时不使用其中的工具；未被回收的进程不列出。首次运行发现：JDK 不在登录 PATH 里时误报“没有 jar”，被结束的进程仍显示为运行中，命令行没写明的 JAR 根本打不开，替换后的 JAR 变成 root 所有、权限 600（以自己账号运行的应用重启后读不了）；均已修正。非 root 登录、只装 JRE、Alpine、RPM 系、其他 JDK 版本与真实应用服务器未覆盖，见 `JAVA_HOT_UPDATE_VERIFICATION.md` | `node tools/lab/probe-java-hot-update.mjs` |
| 命令审计（九个发行版，各自新建一次性容器，root 与普通账号各连一次） | 每台 24/24：植入的脚本、真实程序和不存在的命令名分别标出，位置是真实路径；Rocky/Alma/Anolis 单文件 coreutils 的转接单独说明、不当作可疑脚本；没有日志、日志位置是指向 /etc/shadow 的符号链接（不跟随，页面上没有 shadow 内容）、空日志、普通账号读不了日志或目录，在三个标签页都如实说明；植入的日志读出全部记录，不是记录的行原样列出、不计入统计与周期；周期识别正确；建议里没有可执行内容；显示的记录可复制为 TSV。首次运行发现并修正：以上几种日志状态原来都显示成“没有匹配日志”，不是记录的行被丢弃或显示英文错误，任何非脚本程序都叫“原始二进制”，coreutils 转接被当作未知脚本，`file` 输出带文件名导致误判，侧栏名称与说明和页面内容不符 | `LAB=<发行版> node tools/lab/probe-check-audit.mjs` |
| 命令审计第二阶段：加采集、移除采集、清空日志（九个发行版，一次性容器） | 每台 26 项（Alpine 28 项）全部通过，真实窗口 Ubuntu、Alpine 各 14/14。首次运行发现并修正：没有 SELinux 标签的主机上 chcon 失败、BusyBox 不认 GNU 的 --reference 与 --preserve=all、BusyBox 主机上加采集会换掉整个 /bin/busybox（现标为多合一程序并拒绝）。SELinux enforcing 主机未实测 | `LAB=<发行版> pnpm lab:check-audit-actions`、`LAB=<发行版> pnpm lab:ui-check-audit-actions` |
| 网络抓包（九个发行版，各自新建一次性容器并装上 tcpdump） | 每台 15/15：真实网卡默认选中；三个 ping 恰好显示为六个包、地址正确；数据包上限、“停止抓包”、离开页面之后主机上都没有在跑的 tcpdump；带 `; touch …` 的过滤条件不执行任何东西，页面说明失败并给出 tcpdump 自己那一行。首次运行发现并修正：一个包被拆成两行乱码、Alpine 上抓包一律失败（BusyBox timeout）、过滤写错显示成“已停止”、到上限结束后不能再开始、tcpdump 的状态行混进数据包、失败原因被后续轮询和网卡刷新清掉、浅色主题下统计数字看不见。抓包留证（“抓包并保存…”）已接通：每台 26/26，保存的 capture.pcap 与目标上算出的 SHA-256、两次读取和本地回读一致，探针自己解析出恰好四个 ICMP 包，目标上不留临时文件，取消会停掉这次 tcpdump 并删除文件，证据登记到案件；非 root 的 sudo、中途断连、超过 512 MiB 与 VM/实机仍未覆盖 | `LAB=<发行版> node tools/lab/probe-ui-packet-capture.mjs` |
| 账本 | 22/53 Completed：外壳、后端边界、安全速查、笔记、主机全景、Docker、命令工作台、命令历史、文件完整性、连接列表、连接编辑与保存、连接导入导出、连接删除、处置报告、容器终端、设置、确认对话框、通知、图标与无障碍、源码与依赖门禁、质量门禁、SBOM 与许可证 | `pnpm release:ledger-gate` |
| Windows 便携包 | 构建、静态 CRT 检查、校验与冒烟通过（七个文件，含 Rust 依赖许可证全文与 CycloneDX SBOM；空格与中文路径、重定向用户目录无写入、正常退出） | `pnpm release:package -Build`、`pnpm release:smoke` |
| Linux 便携包（Debian 12 容器） | 构建无警告；启动级冒烟通过（1 秒内就绪、经窗口管理器关闭后正常退出、家目录无写入）。第一次冒烟发现 Linux 主页被宿主导航守卫拒绝，已修正 | `scripts/desktop-package-linux.sh`、`scripts/desktop-portable-smoke-linux.sh` |

这一轮在验证中发现并修正了以下问题：

- 关闭对话框超过 15 秒后，回答会被丢掉；
- 文件编辑窗口关闭时不询问未保存的修改；
- 笔记删除成功的提示会立刻被清掉；
- 连接导出覆盖已有文件、导入错误文件时，提示是英文或含糊不清；
- 后端错误码显示为英文；
- 对话框和应用日志里还有英文标签、实现术语，以及不准确的“持久日志文件”说法；
- 设置的“放弃更改”确认框里，Tab 键无法在两个按钮间移动（叠在下面的设置面板抢走了按键）；
- 连接文件损坏时整个程序无法启动，现在只影响连接本身，并说明是哪个文件、有无备份。
- 界面里残留的实现术语与英文标签：“未通过本地边界校验”（约 20 处）、“portable settings store”、“在 Notes 中”、“provider、model”、“live capture”、“全部 namespaces”、“Endpoint / Model / Keepalive”、日志级别选项等，统一改为中文说法；新增两条回归测试，分别拦截实现术语和纯英文标签。
- 终端窗口工具栏的“上传”必须先手填服务器上的文件名才能继续，可代码本意是留空沿用本机文件名；现在可以留空，对话框也说明下一步会选文件。文件管理的复核结果原来是英文句子，文件大小单位是 bytes，“绑定”“固定根目录”“页面失活”等说法也一并改成了中文日常说法。
- 命令历史把应急命令清单留下的占位串“# lovelyres emergency catalog entry”当作命令显示，把每条记录都标成“可写或未知风险”，结果摘要是英文，来源显示为 native-command-workbench，还有一个只会回答“执行消费者尚未接线”的重放按钮。现在清单检查会说明历史只保存名称、时间和结果，来源写成“应急命令”，重放按钮去掉（见 `UNWIRED_FEATURES.md`）。之后（同日）新记录会记下是哪一项检查，详情里换成“到命令工作台再次运行”。
- 下载或上传超过后端时限时，复制会被直接丢弃，原本“失败就删掉半个文件”的清理根本不会运行，本机或服务器上留下一个截断的文件，看起来像下载成功了一部分。现在下载自己创建的本机文件在未完成时一定会被删掉（包括被丢弃时），后端到时限改为先取消、等清理完成再报超时。
- 命令历史里再点一下已经选中的那条记录，详情就变成空白，再也不会自己读回来（选中状态没变，读取不会重新触发）。现在点已选中的记录保持原样；`command-history-state.test.ts` 加了回归，`probe-command-history.mjs` 实测发现。
- 处置报告：点一下已经选中的预览格式，预览会永久变成空白（内容被清掉却不会再读取），已修正并加了回归测试；导出失败只说“导出失败”，现在说出宿主给的原因（例如文件已存在）；交付给别人的报告里写着“代际”“目标身份”“快照”“第一阶段未附带可信 detection snapshot”，改成“会话编号”“连接编号”“报告数据”“报告暂不包含检测结果”。
- 连接编辑：私钥和证书只能手打本机绝对路径，现在可以经系统打开框选择（选到 .pub 会被拒并说明）；必填密码旁的“移除已保存值”只会导致保存失败，已去掉，改用其他认证方式时会提前说明保存后删除哪些已保存的秘密；改了主机或端口会提示原来记住的指纹作废；Agent 指纹格式错误时原来显示英文 “Invalid connection creation request.”，现在说明格式和查看方法；错误提示末尾的英文错误码不再显示给操作员；主机密钥确认框原来说“确认只对本次连接生效”，实际上指纹会记在连接里，已改正。
- Docker 页补上了容器内文件的编辑与复制（core 早已实现，一直没有后端方法和入口）：打开文件、编辑、先看计划再写入、在容器里回读核对、核对失败用备份恢复；可在容器与这台主机之间或容器内部复制。core 里这两类计划、还原说明和复核结果原来都是英文句子，已改成中文。
- 关掉容器终端窗口（或断开连接）后，在容器里启动的命令仍在运行：`docker exec`/`podman exec` 的客户端断开时不会结束容器里的进程。现在每个容器终端启动时带一个会话标记，关闭时在容器里按标记结束它留下的进程（先 HUP，一秒后 KILL）；`probe-docker.mjs` 在修正前后各跑一遍对照。Docker 安全审计与 Kubernetes 详情里“已按敏感信息与 UTF-8 字节安全边界处理”改为说明实际发生了什么：内容过长被截短，或看起来像口令、密钥而被隐去。
- 主窗口跑一个耗时的命令时，终端窗口的按键和输出要等它跑完，按键在页面 15 秒超时后丢失；宿主现在把终端、终端窗口的文件管理和其余调用分成三条通道。
- 编辑窗口有未保存修改时，Alt+F4、关闭主窗口、断开或切换连接都会不经询问丢掉修改；现在这四种情况都先询问。
- 应急命令里对文件下手（去掉执行权限、隔离）时，如果文件在计划之后被改过，core 会在写入前拒绝、什么都不动，但回执仍写“是否已还原：未能自动还原，请手动检查”，等于让操作员去找并不存在的破坏。现在回执带上“没有执行，文件保持原样”，不再尝试还原；`probe-emergency-path.mjs` 加了对应检查。
- 主机全景表格被截断时，提示让操作员“用上面的筛选”，但页面并没有筛选框；现在改为指向终端。另把“绑定”“能力可能过期”“本地预算”“绑定快照”等实现说法改为“连接”“操作入口”等日常说法，并加入回归测试。

实验室探针在 Tauri 外壳下重跑的结果（lab-ubuntu 22.04，另有 arena/nginx/redis 服务靶机）：

| 探针 | 结果 |
| --- | --- |
| `lab:ui`（右键处置） | 19/19 |
| `lab:ui-system-info`（行操作与核对） | 全部通过 |
| `probe-ui-overview`、`lab:ui-log-analysis`、`probe-ui-configuration` | 全部通过 |
| `probe-ui-baseline` | 全部通过；“两种模式”是过期断言，已改为核对三种模式 |
| `probe-ui-switch`（连续切换三个目标） | 12/12；原探针在连接详情加载完之前点击按钮，按钮仍处于禁用状态，现在会等它可用 |
| `probe-case-workspace` | 52/52，控制台无错误 |
| `probe-file-evidence` | 26/26，控制台无错误 |

案件与留证探针的控制台错误来自探针自身：它在页面里解析导出的 HTML 报告，报告里的内联样式触发了页面的 CSP。现在解析前会去掉样式，检查内容不变。`probe-nginx-*`、`probe-redis-baseline`、`probe-postgresql-*`、编排类探针需要新建一次性容器或编排实验环境，这一轮没有重跑。

各业务场景的实验室探针已改为驱动 Tauri 外壳。这一轮只重跑了 `pnpm lab:ui`（lab-ubuntu，19/19 通过）：右键输出行 → 属性来自目标机 → 计划 → 确认 → 去掉执行权限并在目标机上核对 → 断开连接。这个探针原本断言菜单有 3 项，是 2026-09-08 新增“下载留证”时漏改的过期断言，现在改为按顺序核对 4 个具名动作。其余探针仍待逐个重跑。下面 2026-09-07 的结果属于 Electron 外壳，不能当作 Tauri 外壳的证据。

## 本轮证据（Electron 时期，2026-09-07）

证据目录在本机 `target/` 下，由 Git 忽略；下面列出可重跑入口。日期均为 2026-09-07，不能把这些有限场景外推成全部产品或发行版通过。

| 检查 | 实际结果 | 命令或本机证据 |
| --- | --- | --- |
| Electron 类型、单测、构建 | 最新 116 个文件、817 项测试通过；类型与构建通过。包含文件处置、编排动作、基线文件生命周期与待复核回归 | `pnpm electron:check`；`target/goal-20260907/baseline-nginx-electron.log` |
| Rust core 全量 | 最新 1042 通过、7 个实机测试忽略；此前 Kubernetes 专项 21 项通过 | `cargo test --locked --package lovelyres-core --quiet`；`target/goal-20260907/baseline-nginx-core-full.log` |
| 最后一次 SFTP 变更回归 | 30 通过、1 个实机测试忽略 | `cargo test --locked --package lovelyres-core sftp:: --quiet` |
| Rust sidecar 及集成边界 | 638 项通过 | `cargo test --locked --package lovelyres-electron-backend --quiet`；`target/goal-20260907/baseline-nginx-backend.log` |
| Clippy | 通过，警告视为错误 | `cargo clippy --locked --package lovelyres-electron-backend --all-targets -- -D warnings` |
| 源码与依赖门禁 | 通过 | `scripts/electron-source-gate.ps1`、`pnpm electron:release:dependency-gate` |
| 接线 ledger 普通门禁 | 通过；仍仅 3/53 项 Completed，未运行严格全完成验收 | `pnpm electron:release:ledger-gate` |
| Electron 原生 CDP smoke | PASS；未出现 renderer 控制台错误 | `target/electron-debug/1daecb66-bdd1-4656-89e7-22ab3f224b82/evidence/report.json` |
| Ubuntu 文件处置 UI | 19/19 通过；权限实际从 4755 变为 0644；SUID 无执行位和断连页面正常 | `target/lab-ui/emergency-ubuntu-ee9d0eea-de4a-4149-9826-eaed89081263/report.json` |
| Alpine 3.20.10 文件处置 UI | 19/19 通过；包含最终中文权限回执；0 个 renderer 错误 | `target/lab-ui/emergency-alpine-347f9de2-3fed-413b-ba8c-1da98fda5a2f/report.json` |
| 隔离配置修补实验 | 20 项检查通过，5 个场景跳过；覆盖 SSH、Redis、Nginx、MariaDB、PostgreSQL 文件读写及 Nginx 好/坏/恢复语法检查 | `target/goal-20260907/baseline-write.log` |
| Docker 29.1.3 只读调查 | 容器 17 个、统计 15 个、镜像 5 个、网络 6 个、卷 2 个、Compose 1 个；25 个安全发现及详情/日志验证通过 | `node tools/lab/probe-docker.mjs`；`target/goal-20260907/orchestration/docker-read.log` |
| Docker 动作与拒绝路径 | 启动/停止、独立回读、立即退出容器的失败与恢复、未确认/重放/取消/伪造对象拒绝通过；测试对象恢复原状态 | `node tools/lab/probe-docker-action.mjs`；`target/goal-20260907/orchestration/docker-actions-before.log` |
| k3s 只读调查 | namespace 7 个、节点 1 个、Pod 10 个、Deployment 5 个及故障状态、详情、日志验证通过 | `node tools/lab/probe-kubernetes.mjs`；`target/goal-20260907/orchestration/kubernetes-read.log` |
| k3s 动作与拒绝路径 | `payments/ledger` 3→1 副本、节点不可调度→可调度、未确认/重放/取消/伪造对象与动作种类拒绝通过；最终恢复 3 副本和可调度 | `node tools/lab/probe-kubernetes-action.mjs`；`target/goal-20260907/orchestration/kubernetes-actions-with-health.log` |
| Docker 原生 UI | 11/11 通过，0 个 renderer 错误；计划/取消不改变容器，确认启动后独立回读，搜索保留，断连取消第二个计划并恢复实验对象 | `target/lab-ui/orchestration-docker-bf7f1e98-cf1a-410c-a7a0-aef6354ef957/report.json` |
| Kubernetes 正常原生 UI | 10/10 通过，0 个 renderer 错误；调整副本的计划/取消/确认/就绪回读、断连取消第二个计划并恢复实验对象 | `target/lab-ui/orchestration-kubernetes-b0613c3c-a3f0-4c42-b810-54df7b25a7c4/report.json` |
| Kubernetes 就绪与恢复实验 | 22/22 通过；正常扩容、持续未就绪后恢复、保护后续配置、故障工作负载缩到 0；包含 Electron 子探针；本次命名空间已删除 | `target/lab-kubernetes-health/982eb826-5159-486c-b770-b75b9e25dc58/report.json` |
| Kubernetes 故障恢复原生 UI | 最终 13/13 通过，0 个 renderer 错误；真实就绪失败、恢复说明、0 副本状态、取消与断连 | `target/lab-ui/orchestration-kubernetes-6b0adcf0-6655-42c1-89de-a8362126a422/report.json` |

文件处置 UI 入口为 `node tools/lab/probe-ui.mjs`；PowerShell 下 Alpine 使用 `$env:LAB = 'alpine'` 后运行同一命令。探针为每次运行创建唯一的无害文件与独立数据目录，核对目标为无挂载、非特权的既定实验镜像，并在结束后删除自己的文件；保存报告和截图供复核。

配置实验使用本地 `lovelyres-lab:arena` 镜像创建临时容器 `lab-goal-baseline-01a07b`，禁用网络、无挂载、限制 1 GiB 内存/2 CPU/512 PID。执行 `node tools/lab/probe-baseline-write.mjs lab-goal-baseline-01a07b` 后，核对完整 ID 和任务标签并删除该容器，未修改原有综合靶机。MongoDB/Tomcat 文件格式及 Apache/MySQL/MongoDB 校验器因副本未提供对应文件而跳过；本次实验不证明这些产品通过，也不证明所有写入已完成 reload/健康检查。

编排实验运行在 WSL Ubuntu 的独立嵌套 Docker 与 k3s 环境，均为 `linux/amd64`。使用前核对容器完整 ID、镜像、挂载、网络和启动脚本；Docker 仅挂载自己的实验卷，kubectl 客户端只读挂载实验 kubeconfig，k3s 的配置挂载限定为实验室注册表文件。原生 UI 使用独立数据目录；入口为 `node tools/lab/probe-ui-orchestration.mjs`，PowerShell 下分别设置 `$env:LAB = 'docker'` 或 `'kubernetes'`。新探针核对实验对象身份，结束时恢复自己的变更并保存截图和报告。

Deployment 扩缩容目前会核对对象与配置版本，等待控制器处理并核对当前、更新、就绪和可用副本；业务接口与恢复后的业务健康仍未验证。45 秒就绪期限、停止工作负载的特殊策略、并发保护和实验范围见 [Kubernetes 操作验证与恢复](KUBERNETES_VERIFICATION.md)。只读探针中的 `access-logger` 在 WSL 重启后处于退出状态，本次取到的是保留日志；不能登记为实时日志健康验证。多节点、RBAC 拒绝、CNI/存储恢复、不同 Kubernetes 发行版和 Podman 均保留后续验收。

## 本轮已修复与下一批缺口

- 已修复应急页连接/断开时 hook 数量变化；关闭、卸载和切换目标回收计划，迟到的属性、计划、确认与回执不得覆盖新对话框或触发执行。
- 已校验选择的文件、操作、确认正文与回执身份；旧对话框的确认不能批准替换后的对话框，重复点击不重复执行。
- 已修正 SUID/SGID 单独存在时的可执行标记、属性误导文案和通用失败被误称为“已经没有执行位”；权限复核回执改由 core 生成中文。
- “下载留证”近路及文件证据→案件→报告已接线，详见下方文件留证验收；证据/笔记快照关联及案件工作台已接线；案件归档、离线访问与成功处置后的明确恢复入口继续推进。
- 新手体验继续完善可发现的文件操作入口、术语解释和推荐下一步；键盘菜单、对话框焦点、窄窗口与专家快捷操作需要真实桌面应用验收。
- 已修复 Docker/Kubernetes 动作的目标与对话框生命周期：关闭、卸载、断连和 API/目标切换后回收计划，迟到确认不能执行；确认正文、对象与回执必须对应用户审阅的原计划，失败后不能重放旧计划。
- 已修复 K8s 页面断连时 hook 数量变化；计划准备期间可取消，失败后显示重新获取当前状态的提示，不再误显示执行中。两页原生 Electron 截图已检查，键盘焦点与窄窗口验收仍待完成。
- 已补 Deployment 有期限的就绪验证、超时恢复和配置 generation 并发保护；缩到 0 时不自动重新启动。恢复配置成功与业务恢复分开报告；列表不会把尚未全部可用/更新的副本标为正常，暂停调度不再写成已隔离。
- Docker/k3s 下一批补可明确追踪的恢复入口、可配置就绪期限、业务接口健康验证与错误引导；Podman 和多运行时环境继续实测，不能以 Docker 结果代替。
- 系统/中间件/数据库继续扩展实际版本矩阵，重点补生效配置读取、计划→写入→产品验证→健康检查→独立复检→恢复的全链路；国内商业产品的合法测试环境仍需逐项落实。

## Nginx 检测与定位进展（2026-09-07）

已修正同名指令跨 server/location 混读、TLS 配置仅按存在性通过、访问日志 off 被当作已启用、无法解析被当作默认值，以及配置查看错误标记唯一生效行的问题。通用写入器现在拒绝 Nginx；自动修补需走实例与配置图验证流程。页面新增待复核筛选、产品名搜索、跟随风险来源查看，以及文件读取的完整生命周期保护。语义、实验范围与下一步见 [Nginx 基线验证](NGINX_BASELINE_VERIFICATION.md)。

当前验证：Electron 116 个文件、817 项测试通过；core 1042 项通过、7 项忽略；backend 638 项通过。原生 Electron 与 Nginx 1.27.5 的完整探针报告列于本节后续记录，包含真实 HTTP 对照、缺工具与断连验证；实验写入不计为应用自动修补通过。源码门禁和 Clippy 通过，严格发布门禁仍未完成。

最终 Nginx/原生 Electron 探针 **34/34** 通过，控制台错误 0：`target/lab-nginx-baseline/489cb206-0387-4377-a82a-0116076b2c4b/report.json`；同目录保留风险定位、修改后待复核、最小支持窗口截图。刷新扫描后还检查了已选文件确实重新读取，而非保留旧配置。该运行已核实删除自建容器，并清理独立应用数据。

## Nginx 普通进程修补进展（2026-09-08）

`MiddlewareService` 新增普通进程模式：当 systemctl 不存在或没有运行 systemd 时，通过受限的 Nginx master 证据识别实例，复用配置图、精确确认、原子写入、备份、验证与恢复。原生检查固定实际可执行文件，HUP 使用 pidfd 指向已核实的 master，验证工作进程切换；持久恢复重新核对运行时和构建配置。新增记录向后兼容旧 systemd 记录。未确认、过期或重复执行的计划在写恢复记录前拒绝，避免把已应用状态降成待恢复。

真实实验还发现并修正了容器内无关僵尸进程干扰工作进程检查的问题。Nginx 1.27.5 / Debian bookworm / Linux amd64 的最终 **25/25** 条探针检查通过，报告：`target/lab-nginx-process/6f719de1-8db1-4666-a8d1-9c3d5814b7fc/report.json`；同目录 `core-repair.log` 是实际 core 集成测试输出。验证默认与前台启动、坏配置恢复、语法正确但端口占用导致重载失败、实际目录列表与版本响应头修补、幂等拒绝、持久恢复、后续配置保护及重启后旧计划拒绝。本次容器和独立连接数据已核实清理。

完整 Rust 回归：core **1047 通过、8 忽略**，backend **638 通过**，见 `target/goal-20260907/nginx-process-full.log`。上述 8 个常规忽略项中的 Nginx 实验测试已由探针明确指定并实际运行通过；其余忽略项不算通过。Python helper 的 5 项拒绝/进程竞态回归通过。早期零项测试、编译失败、测试连接超时和恢复失败的报告保留；探针现要求精确的实际测试数量及完成标记，无效运行不计通过。

范围与前提见 [Nginx 普通进程修补](NGINX_PROCESS_REPAIR.md)。目标需具备 Python 3.9+、Linux pidfd 及相应 procfs 权限，首批支持默认和固定前台启动；复杂参数、共享配置的多 master、其他版本/架构、rootless/只读容器和业务 TLS 健康仍待适配。上述记录是 core 阶段证据，后续 Electron 接线进展见下节；应急闭环、Docker/Kubernetes、系统和数据库的长期范围保持不变。

## Nginx Electron 配置修补与恢复（2026-09-08）

“配置 → 修补已有配置”已接通真实 Nginx 进程发现、配置图、按文件与行号选择的 `autoindex` / `server_tokens` 修补、精确差异、逐次确认、执行结果、历史和备份恢复。确认框展示绑定的 SSH 地址、端口和真实主进程；确认后仍核对不可变内容。取消、切换目标和迟到确认不会触发写入；执行仅提交一次，结果超时后引导检查历史。缺工具、未解析引用、实例变化或配置竞争不能显示成安全或成功。

真实联调发现并修复了两处单元测试之外的问题：恢复预览此前使用当前文件而显示“无差异”，现以实际备份计算，并分别保护两边的敏感值；沙箱 preload 不能 require 未打包的项目模块，现使用经过 shared 一致性测试的自包含请求校验。键盘取消返回原操作按钮，完成后焦点保留在工作区；确认按钮使用全局危险操作主题色，最小窗口内可见完整内容。

| 验证 | 结果与范围 | 证据 |
| --- | --- | --- |
| Nginx 核心真实实验扩展 | **28/28**；含有限节点修补、陈旧候选拒绝、多 master 共享配置及计划后新增共享 master 的拒绝；实验容器已清理 | `target/lab-nginx-process/b22c2cd2-5ea0-40c5-95fc-1a46de811a63/report.json`、同目录 `core-repair.log` |
| RPC + Electron 原生 CDP + HTTP | **46/46**，控制台异常 **0**；未确认/取消/重放拒绝、目录修补后 HTTP 403、版本隐藏与恢复、实际备份差异、外部修改保护、目标核对、键盘焦点、1080×700、断连清空和清理 | `target/lab-nginx-repair/fe5fc684-1cf7-4565-b615-f501f042444e/report.json`，同目录保留候选、确认、成功、恢复、并发修改、历史与断连截图 |
| Electron 全量检查 | 类型、**120 文件 / 857 测试**及主进程/renderer 构建通过 | `target/goal-20260907/nginx-repair-electron-check-6.log` |
| Rust 全量检查 | core **1051 通过、8 忽略**；backend **643 通过**；Clippy `-D warnings`、格式与构建通过 | `target/goal-20260907/nginx-repair-full-rust-3.log`、`nginx-repair-clippy-3.log`、`nginx-repair-backend-build-3.log` |
| 边界与 helper | source gate **151 个可达文件 / 6 个固定资源**通过；Python helper **6 项**通过；diff 检查通过 | `target/goal-20260907/nginx-repair-source-final.log`；`tools/lab/test_nginx_process_helper.py` |

桌面实验为 Nginx **1.27.5 / Debian bookworm / linux/amd64** 普通进程容器，镜像摘要 `sha256:57d0bb8d70b90e9e001a1ed2197d0217b82c7299aa30191a5eda008152611e8d`。报告使用 UTC 时间，对应本地 2026-09-08；最新运行的自建容器与临时应用数据均已核实清理。早期探针参数错误、恢复预览失败和沙箱启动失败的报告保留，不计为通过。

上述结果完成的是两项具体修补及恢复流程。通用中间件编辑器、其他 Nginx/系统组合、systemd 定制启动、OpenResty/Tengine、rootless/只读容器、ARM，以及自动 HTTP/TLS 业务健康仍待适配。普通 Cargo 运行的 8 个忽略项不计通过；严格发布台账仍按原标准验收，不能由这批结果推断全产品、全平台或整个长期目标已经完成。

## 文件留证、案件与报告（2026-09-08）

命令工作台新增可见的“文件操作”按钮与“下载留证”流程：保存原始二进制文件、目标与 SSH 指纹、属性、UTC 采集时间和摘要清单；两次远端读取与一次本地回读一致后，关联到采集开始时的案件。只含文件证据、没有处置操作的案件可以生成报告，导出保留来源、采集说明与 `external-artifact` 摘要范围。

修正了两种会丢失证据来源或记录的行为：相同摘要但来源/保存位置不同的证据不再合并；500 条证据或 30 个案件达到上限后拒绝新增，不再静默淘汰旧记录。进度快照按阶段顺序采样，避免并发读取产生“复核字节大于下载字节”的无效响应；取消、断连、严格模式卸载、迟到进度和确认关闭均有对应处理。

| 验证 | 实际结果与范围 | 本机证据 |
| --- | --- | --- |
| Ubuntu 22.04.5 / x86_64 / 普通容器 | **23/23**；真实 SFTP/RPC、二进制一致性、清单来源、同内容不同来源、证据报告、链接拒绝、512 MiB 上限、取消、Electron UI、焦点、1080×700、独立 HTML 无横向溢出；控制台异常 **0** | `target/lab-file-evidence/991d22df-94b2-4328-9e40-1f36a17e280d/report.json`，同目录的 MD/HTML、样本清单与截图 |
| Alpine 3.20.10 / x86_64 / 普通容器 | **17/17**；真实 SFTP/RPC 的采集、摘要、来源、案件报告、链接/大小拒绝及取消；不依赖 Python 或远端哈希工具 | `target/lab-file-evidence/beec7a2c-e6f5-423c-8346-5fc20e3e4c8f/report.json` |
| Rust 全量与补充回归 | core **1058 通过、8 忽略**；backend **644 通过**；最终报告展示调整后再运行 **12 项**报告回归通过 | `target/goal-20260907/file-evidence-rust-final.log`、`file-evidence-report-final.log` |
| Electron 全量 | 类型、**123 文件 / 868 测试**及构建通过；固定 API **126** 个 | `target/goal-20260907/file-evidence-electron-final-2.log` |
| 边界与质量 | source gate **155 个可达源码 / 6 个固定资源**通过；Clippy `-D warnings`、格式与 diff 检查通过 | `target/goal-20260907/file-evidence-source-final.log`、`file-evidence-clippy-final-2.log` |

复现入口与方法限制见 [文件留证](FILE_EVIDENCE_COLLECTION.md)。两个实验镜像摘要分别为 `sha256:9a86a7d4d3bd1b14e3cb9f6c70eed7d57e731d5fa33e77f875e00c00d51bc8f2` 与 `sha256:b407a95a376d371b079834457b0a42a66a841c7c6973e120afdeed8e9ca93458`。本次容器、临时应用数据与旧测试入口均已核实清理。

早期报告漏展示来源、探针按钮名称错误和自定义 Electron 测试入口的沙箱初始化错误均保留失败记录，不计通过。最新探针使用正常应用入口，只有系统目录选择器通过测试进程的 main debugger 返回专用目录；这不是 OS 目录选择器人工交互或全平台发布验收。SFTP 一致性观测不是原子快照。完整案件管理、目录批量取证、大文件与快照、外部证据重新导入、后续恢复入口和其余产品兼容矩阵继续保留，长期目标未完成。

## 案件工作台、笔记快照与所选案件报告（2026-09-08）

新增“调查 → 案件工作台”，接通创建案件、浏览历史、选择后续采集归属、证据/IOC/时间线搜索和分页、手工调查记录、笔记版本关联，以及所查看案件的报告。浏览案件不改变当前归档案件；真实文件采集在开始后切换案件时仍保存到原案。未保存内容参与导航、关闭和目标切换交互，切换主机首帧不会显示旧案件内容。

修正 IOC 和时间线达到上限后静默丢弃旧记录的问题，容量不足时拒绝整次新增。创建案件的重试记录持久化，重复请求不重新选择案件；关联笔记保存核对过的正文版本，过期或过长笔记拒绝关联。报告可以使用所查看的固定案件快照，来源主机名称来自本次 SSH 连接的不可变信息。方法与限制见 [案件工作台](CASE_WORKSPACE.md)。

| 验证范围 | 实际结果 | 证据 |
| --- | --- | --- |
| Ubuntu 22.04.5 / x86_64 / 普通容器 | **30/30**；真实 RPC/SFTP + 正常 Electron 入口；创建重试、分页、版本、跨目标拒绝、采集归属、界面建案/记录/关联、输入保留、时间线定位、键盘焦点、最小窗口与报告保存；0 个控制台错误 | `target/lab-case-workspace/06e3931a-68d1-44c5-a7db-637cab5ea6cc/report.json` |
| Alpine 3.20.10 / x86_64 / 普通容器 | **19/19**；真实 RPC/SFTP 的创建/重试、固定视图、分页、笔记版本、案件选择与采集归属；不计 Electron UI 验收 | `target/lab-case-workspace/5148a4f4-675f-4589-9794-97d3e90b95a9/report.json` |
| Rust core 全量 | **1061** 通过、**8** 个实机测试忽略；容量拒绝保留原档、笔记版本、创建重试和原有应急规则通过 | `target/goal-20260907/case-workspace-rust-final.log` |
| Rust sidecar 与集成边界全量 | **646** 通过；最后修改后的边界回归通过 | `target/goal-20260907/case-workspace-backend-all-final.log` |
| Electron | 类型与构建通过；最终 **126 文件 / 880 测试**；固定 API **127** 个，页面注册表 **15** 项 | `target/goal-20260907/case-workspace-electron-final-3.log`、`case-workspace-electron-tests-final.log` |
| Clippy / 源码门禁 / 格式与 diff | `-D warnings`、源码门禁、格式和差异检查通过 | `target/goal-20260907/case-workspace-clippy-final.log`、`case-workspace-source-final.log` |

Ubuntu 镜像为 `sha256:9a86a7d4d3bd1b14e3cb9f6c70eed7d57e731d5fa33e77f875e00c00d51bc8f2`，Alpine 镜像为 `sha256:b407a95a376d371b079834457b0a42a66a841c7c6973e120afdeed8e9ca93458`。截图 `case-workspace.png`、`case-evidence.png`、`case-report.png` 与实际保存的报告留在对应探针目录。全部本次容器及临时应用数据已清理，留证原件、清单与验收结果保留。

第一次真实启动暴露出启动 DTO 仍限定 14 个页面的遗漏，记录在 `target/lab-case-workspace/ae8c46cb-96db-4c14-9158-e067e64e5070/report.json`；该次启动失败及控制台错误不算通过。已修正启动校验，并增加读取真实 Rust 页面注册表的契约回归，后续正常入口实测通过。

报告保存测试仅替换 OS 文件选择的返回路径，实际 IPC、preload、Rust、报告生成和独占文件写入均真实执行；OS 对话框人工交互仍未验收。本轮不包含关闭/重开、改名、归档移除、离线案件访问、外部案件导入、跨案件转交、跨主机关联或全量处置自动关联。30 个案件的总容量目前无法在界面释放，现有记录可继续查看和导出。后续优先补齐归档与离线访问，同时继续系统、中间件、数据库与编排的应急闭环；严格发布台账仍为 **3/53**，不得以本轮通过放宽，长期目标未完成。

## 离线案件库、完整导出与归档恢复（2026-09-08）

接续上一轮，案件工作台新增“当前主机 / 本机案件库”。本机案件库无需 SSH，可按案件和当前连接库名称搜索，筛选活动案件或归档版本，查看固定版本的全部证据、线索和时间线，并通过系统文件选择导出完整案件 JSON。当前连接名称仅作为导航标签，历史采集来源仍保存在证据与清单中。

归档生成具体的 core 计划，经一次性确认后独占写入完整副本、刷新并按最终文件名回读核对，再移出活动列表，解决原先 30 个活动案件无法释放名额的问题。恢复保留归档原件，不覆盖同编号案件、不改变当前采集归属。采集进行中、确认期间内容或当前案件选择变化、文件摘要或清单不一致时拒绝归档/恢复。外部留证原件不移动或删除。方法、容量、导出范围和跨文件断电事务的限制见 [案件工作台](CASE_WORKSPACE.md)。

| 验证范围 | 实际结果 | 证据 |
| --- | --- | --- |
| Ubuntu 22.04.5 / x86_64 / 普通容器 | **40/40**，连续两次；正常 Electron 入口、RPC/SFTP、断连后访问、原生保存的完整 JSON、归档计划/取消/确认、完整副本释放名额、恢复保留原件与采集归属、拒绝重复覆盖；启动与页面控制台均 0 错误 | `target/lab-case-workspace/43abb499-1d85-4d78-ae5b-7e6e77e95533/report.json`；前次 `32636d45-5667-4990-b0fa-04332159e09d/report.json` |
| Alpine 3.20.10 / x86_64 / 普通容器 | **19/19**；本次采集占用保护改动后的真实 RPC/SFTP、固定视图、分页、笔记版本与采集归属回归；不计离线 UI 验收 | `target/lab-case-workspace/80d645bc-5ea7-4eee-bda8-c8f3207b1c00/report.json` |
| Rust 全量 | core **1067** 通过 / **8** 忽略；sidecar 与集成边界 **649** 通过；合计 **1716** 通过 | `target/goal-20260907/case-library-rust-final.log` |
| Electron | 类型、构建通过，**129 文件 / 890 测试**；固定 API **128** 个、页面 **15** 项；最终接口和页面接线回归另通过 **14** 项 | `target/goal-20260907/case-library-electron-all-2.log`、`case-library-typecheck-final.log`、`case-library-contract-final.log` |
| Clippy / 源码门禁 / 格式与差异 | `-D warnings` 通过；源码门禁 **163** 个可达源文件 / **6** 项固定资源；格式与 diff 检查通过 | `target/goal-20260907/case-library-clippy-final.log`、`case-library-source-final.log` |

Ubuntu 与 Alpine 镜像摘要沿用上表前一轮所列具体镜像，版本及身份再次核对在本次报告中。原生截图 `case-archive-review.png`、`case-library-offline.png`、`case-library-restored.png` 已检查；`exports/complete-case.json`、`exports/archive-version.json`、报告和 16 MiB 留证原件及清单保留，容器和临时应用数据均已清理。

验收曾连续两次捕获 Electron 初始空白上下文的 `binding.startupData` 沙箱日志，分别记录于 `f8241336-7e3a-419f-8923-8bc68aa86269`、`61a6ebb0-2820-4a38-ada3-1e49d69d22b4` 的探针目录，这两次 **39/40** 不算完整通过。随后等待可见窗口的实验超时，记录于 `c9f72efb-a05e-44c4-99e3-dadd0b2d44af`，同样不算通过。最终探针等待主窗口的真实文档完成加载后再接入 renderer CDP，并从 main 持续收集启动控制台；连续两次正常入口实测均为 **40/40、0 错误**。没有删除失败记录、过滤错误或变更应用沙箱设置；该结论仅覆盖本次正常入口自动化。

下一批仍需结案/重开、归档永久移除及孤立副本修复、外部证据包导入、跨案件转交、跨主机关联、处置日志自动关联、分卷与大档案性能、目录批量取证，以及各系统/中间件/数据库和编排的完整处置矩阵。200 个归档版本上限尚无永久移除入口；JSON 不包含外部原始文件字节，也不提供跨文件断电事务保证。严格发布台账仍为 **3/53**，整个长期目标尚未完成。

## 结案结论、重新调查与完整时间线报告（2026-09-08）

“当前主机”和离线案件库现可对明确查看的活动案件结案或重新调查。用户填写结论及未解决事项（重新调查时填写原因和后续计划），核对完整内容后经 core 不可变计划、一次性确认、日志和独立回读执行。结案保留全部证据、线索和旧时间线，增加带来源及操作编号的人工结案记录；结案当前案件会清除该采集归属，其他案件选择不变。重新调查保留原结案记录，也不自动设为当前案件。归档版本必须恢复后才能变更状态。

计划与执行均核对此案内容、状态、是否为当前采集案件和文件采集占用，拒绝过期状态、正在采集、重复确认及时间线容量不足。结论最多 1024 个 Unicode 字符，后续事项最多 512 个；完整确认超过 7 KiB 拒绝规划，不截断。长确认内容可用键盘滚动，标题与按钮在最小窗口内保持可见，阅读区域按回车不会误确认；取消结案或导航保留输入。结案是人工调查判断，不代表远端主机已修复或恢复安全。

原生验证发现旧报告只保留时间线标题，导致详细结论遗漏；现已让 Markdown / HTML 完整保留时间线内容、来源、记录编号和关联编号。Markdown 使用列表内的纯文本代码块，HTML 转义后按原换行展示；恶意 HTML、链接和代码围栏保持文本。具体行为与剩余容量限制见 [案件工作台](CASE_WORKSPACE.md)。

| 验证范围 | 实际结果 | 证据 |
| --- | --- | --- |
| Ubuntu 22.04.5 / x86_64 / 普通容器与正常 Electron 入口 | **52/52**；完整长结论核对、键盘滚动、防回车误确认、取消保留草稿、明确案件结案、原证据与其他案件选择不变、完整 Markdown / 独立 HTML、重新调查保留历史；并回归 RPC/SFTP、离线 JSON、归档/恢复及覆盖拒绝；启动和页面控制台 **0** 错误 | `target/lab-case-workspace/b8792b53-c0b4-4f16-804d-4949f0933f01/report.json` |
| Rust 全量 | core **1072** 通过 / **8** 忽略；sidecar 与集成边界 **651** 通过；合计 **1723** 通过 | `target/goal-20260907/case-status-rust-final.log` |
| Electron | 类型和构建通过，**129 文件 / 894 测试**；既有契约与 preload 内联校验一致性、确认失效和案件选择回归通过；固定 API 保持 **128** 个、页面 **15** 项 | `target/goal-20260907/case-status-electron-final-2.log` |
| Clippy / 源码门禁 / 格式与差异 | `-D warnings` 通过；**163** 个可达源文件 / **6** 项固定资源；格式与 diff 检查通过 | `target/goal-20260907/case-status-clippy-final.log`、`case-status-source-final.log`、`case-status-final-checks.log` |

本次 Ubuntu 镜像为 `sha256:9a86a7d4d3bd1b14e3cb9f6c70eed7d57e731d5fa33e77f875e00c00d51bc8f2`，报告记录了实际系统版本和架构。已检查 `case-close-review.png` 与 `case-closed-html.png`；同目录保留截图、`exports/closed-case-report.html`、完整案件 JSON、归档版本和原始留证文件。容器和独立应用数据均已清理，未修改真实目标。系统保存对话框的返回路径由本次 main debugger 指定，实际 IPC、Rust、导出和独占文件写入均真实执行；不计 OS 对话框人工操作验收。

初次原生运行因报告遗漏时间线详细记录而超时，失败材料保留于 `target/lab-case-workspace/a6c81a19-a4da-49d2-8ae1-3db300a03d65/`，不计通过；修复报告后重跑才得到上表结果。本轮未新增其他发行版的结案流程实测，不扩大此前 Alpine RPC/SFTP 的验证范围。

结案/重新调查入口已完成本轮验证。归档永久移除与孤立副本修复、外部证据包导入、跨案件转交与跨主机关联、处置日志自动关联、超过当前容量的检索/导出和目录批量取证仍待实现；系统、中间件、数据库和容器编排的完整检测、修补、独立复核及恢复矩阵继续推进。严格发布台账仍为 **3/53**，长期目标尚未完成。

## Redis 候选基线准确性与原生界面验证（2026-09-08）

修复了 Redis 配置中存在 `bind 0.0.0.0` 却被判为符合的问题，以及保护模式和 DEBUG/MODULE 建议使用通用 `on/off` 的错误。Redis 项目现在区分候选配置线索与尚未核实的运行状态；ACL 认证不能被缺少 `requirepass` 否定，任意命令改名也不能代表权限受控。四个常见配置路径独立检查，不把不同实例文件合并；同一文件内最后一条标量生效于该候选判断，未解析 include、转义、无效语法和过长内容保持待复核。扫描不回传口令或 ACL 秘密。

Redis 原生建议、右侧建议值和详情统一使用 `yes/no`，文件视图标明候选来源，避免声称唯一生效行或猜测服务重启命令。core 拒绝新的通用 Redis 写入请求；当前页面仍是只读检查和建议。实际实例的身份、版本、运行参数、ACL、备份、确认、持久修补、运行时和业务复核需继续接通，详见 [Redis 检测与修补边界](REDIS_BASELINE_VERIFICATION.md)。

| 验证范围 | 实际结果 | 证据 |
| --- | --- | --- |
| Redis 7.4.11 / Debian 12 bookworm / x86_64 / 普通容器与正常 Electron 入口 | **39/39**；真实 Redis 与 SSH/RPC、错误布尔语法的原生拒绝、正确语法接受、通配监听、ACL、空口令、重复项、来源、IPv6、未解析内容、无配置文件、最小窗口和断连；启动及页面控制台 **0** 错误 | `target/lab-redis-baseline/8a27d674-0eca-446b-aa8a-bc57731ca17a/report.json` |
| Rust 全量 | core **1073** 通过 / **8** 忽略；sidecar 与集成边界 **653** 通过；合计 **1726** 通过；后续 IPv6 和文案调整后的相关 core **44** / sidecar **18** 回归通过 | `target/goal-20260907/redis-baseline-rust-all.log`、`redis-baseline-core-final.log`、`redis-baseline-backend-final.log` |
| Electron | 类型和构建通过，**129 文件 / 896 测试**；固定 API 保持 **128** 个、页面 **15** 项 | `target/goal-20260907/redis-baseline-electron-final.log` |
| Clippy / 源码门禁 | `-D warnings` 通过；**163** 个可达源文件 / **6** 项固定资源 | `target/goal-20260907/redis-baseline-clippy-final.log`、`redis-baseline-source.log` |

镜像摘要为 `sha256:9cfb0ec4e2994b2566815b25a6d77e9b08ec6136356939114cad8e2922d3b6b9`。已检查 `redis-corrected-recommendation.png` 与 `redis-review-after-fixture-edit.png`；容器、临时应用数据均已清理。探针中的文件写入和 `CONFIG SET` 是对照输入，不计应用自动修补或业务恢复验收。复现旧错误的失败材料保留于 `target/lab-redis-baseline/924872cc-3898-4bc9-b914-c1cb58897a7d/`；先前通过 39 项的界面截图仍有建议值 `on`，纠正后才取得上表最终结果，没有删除旧证据。

旧基线恢复中的值比较和失败后重新应用还需适配候选检测语义，并验证完整文件恢复，暂不计为已完成恢复。Redis Sentinel、Cluster、Valkey、其他版本、架构和部署方式分别待适配。其他系统、数据库和中间件的检测与修补矩阵继续推进；严格发布台账仍为 **3/53**，长期目标尚未完成。

## 基线历史的完整文件恢复与后续变化保护（2026-09-08）

修复了基线历史恢复只比较旧配置项、可能在完整文件已恢复后因 Redis/Nginx 候选语义变化而触发重新应用的问题。新变更保存修改后完整文件摘要与身份属性；恢复前核对全部目标和备份，拒绝后续内容、权限、UID/GID、设备号、inode、链接数变化，以及符号链接替换。每个文件写入前再次核对，恢复后独立 SSH 回读完整摘要或原先缺失状态，通过后才标记为已恢复。复核失败保留备份和失败日志，不自动重新应用旧值。

原历史数据可继续加载，旧摘要与序列化兼容；缺少修改后证据的记录不能据此自动覆盖，应保留备份并结合当前完整文件重新规划。此轮没有迁移或伪造旧证据，也未开放新 Redis 通用写入。恢复前后核对与剩余并发限制见 [基线历史恢复](BASELINE_RESTORE_VERIFICATION.md)。

| 验证范围 | 实际结果 | 证据 |
| --- | --- | --- |
| Redis 7.4.11 / Debian 12 bookworm / x86_64 / 普通容器与实际 core 服务 | **15/15**；真实 SSH 基线计划/确认/写入形成新历史，完整恢复，后续内容/权限/inode 保护，整套备份预检，符号链接拒绝，候选语义兼容，原先缺失文件，恢复与回读之间干预后不重新应用 | `target/lab-baseline-restore/2785baa6-ac8e-4b9e-b044-c9007fdd291e/report.json`、同目录 `core-restore.log` |
| Rust 全量 | core **1077** 通过 / **9** 忽略；sidecar 与集成边界 **653** 通过；合计 **1730** 通过。新增需实验环境的忽略项已由上一行单独启用并通过，其余忽略项不算通过 | `target/goal-20260907/baseline-restore-rust-all.log` |
| Clippy / 格式 / 源码门禁 | core 和 sidecar `--all-targets -D warnings` 通过；格式与差异检查通过；固定 API **128** 个，源码门禁 **163** 个可达源文件 / **6** 项固定资源 | `target/goal-20260907/baseline-restore-core-clippy-final.log`、`baseline-restore-clippy.log`、`baseline-restore-final-checks.log`、`baseline-restore-source.log` |

镜像摘要与上一轮 Redis 一致，为 `sha256:9cfb0ec4e2994b2566815b25a6d77e9b08ec6136356939114cad8e2922d3b6b9`；实际版本、架构和资源边界记录在报告中。测试容器与独立应用数据已清理，未操作真实业务目标。Redis 历史样例由实验构造明确的修改前后完整证据，不计为应用已支持 Redis 实例修补；真实 Redis 运行时保护模式保持原值，证明文件恢复结论没有冒充运行状态变化。

首次完整执行发现旧 `apply_command` 拼接了多余分号，整段脚本被 Shell 拒绝；之前仅运行局部编辑器的探针没有覆盖这一问题。修正后才取得上表通过结果，失败材料保留于 `target/lab-baseline-restore/af7b777a-488e-4b72-a381-1c8d9de1ea63/`。core 额外 Clippy 检查发现实验代码的冗余借用，修正后复检，不放宽门禁。

本轮是 core 恢复验证，Electron 的基线修改/恢复确认入口仍未接线；上一轮 Redis 原生界面的 **39/39** 与 Electron **896** 项回归范围保持原记载。Shell 预检不是原子多文件事务，生产入口仍需处理持续并发写入、中途 I/O/断电、受控文件描述符和服务/业务健康；系统、中间件、数据库和编排的完整闭环继续推进。严格发布台账仍为 **3/53**，长期目标尚未完成。

## Nginx TLS 协议的桌面修补与实际连接验证（2026-09-08）

“配置 → 修补已有配置”新增移除旧版 TLS/SSL 协议，复用实例识别、配置图、差异预览、精确确认、原子比较写入、备份、原生验证、工作进程切换和恢复。规则从明确位置的 `ssl_protocols` 中移除 SSLv2/SSLv3/TLSv1/TLSv1.1，保留其原有 TLSv1.2/TLSv1.3 组合；不会为只剩旧协议的实例猜测升级，也不接受未知值、变量或无法解析的转义。其他指令、注释和作用域保持不变。

确认前说明旧客户端可能无法连接，以及监听地址默认服务器和 OpenSSL 设置对实际协议的影响；恢复明确提示旧协议可能重新启用。界面仍把配置/工作进程验证与实际业务复核分开。规则和资料依据见 [Nginx 进程修补](NGINX_PROCESS_REPAIR.md)。

| 验证范围 | 实际结果 | 证据 |
| --- | --- | --- |
| Nginx 1.27.5 / Debian 12 bookworm / x86_64 / 普通容器 / OpenSSL 客户端 3.0.20 / 正常 Electron 入口 | **64/64** 综合检查；旧目录/版本流程、取消与并发保护继续通过；新增真实 TLS 协议、CA/主机名校验、HTTP、SNI、恢复和幂等性验证；所收集的 renderer 异常与错误 **0** | `target/lab-nginx-repair/8d65c59c-bdb8-4007-a413-aacb124ae993/report.json` |
| Rust 全量 | core **1079** 通过 / **9** 忽略；sidecar 与集成边界 **653** 通过；合计 **1732** 通过 | `target/goal-20260907/nginx-tls-rust-all.log` |
| Electron | 类型与构建通过，**129 文件 / 898 测试**；闭合 TLS 配方标签/请求拒绝、兼容提示与完整协议差异验证通过 | `target/goal-20260907/nginx-tls-electron.log` |
| Clippy / 格式 / 源码门禁 | core 与 sidecar `--all-targets -D warnings` 通过，格式与差异检查通过；固定 API 保持 **128** 个，页面 **15** 项；源码门禁 **163** 个可达源文件 / **6** 项固定资源 | `target/goal-20260907/nginx-tls-clippy.log`、`nginx-tls-final-checks.log`、`nginx-tls-source.log` |

镜像摘要为 `sha256:57d0bb8d70b90e9e001a1ed2197d0217b82c7299aa30191a5eda008152611e8d`。修补前站点真实接受 TLS 1.0/1.1/1.2/1.3；经原生页面确认执行后，前两种返回协议拒绝，TLS 1.2/1.3 的证书校验与 HTTP 请求成功；再次确认恢复后，完整策略文件和原先四种协议行为恢复。另一个 SNI 名称还验证了默认服务器策略的影响。较低 OpenSSL 安全级别仅为本次容器负例输入，产品没有修改密码套件或证书。

已检查 `nginx-tls-review-minimum.png` 与 `nginx-tls-restore-review.png`，1080×700 下可完整查看差异、兼容影响、备份与确认按钮。报告保留逐协议的握手观察；实验容器和临时应用数据均已清理。此轮全部修改经本任务隔离环境完成，未操作真实业务目标。

自动监听地址/SNI/证书/业务复核、只支持旧协议的实例升级、Stream/TLS 代理及跨版本/架构矩阵仍待完成；系统基线的通用桌面变更/恢复、Redis 实例修补以及其他系统、数据库、中间件和编排的完整闭环继续推进。严格发布台账仍为 **3/53**，长期目标尚未完成。

## Nginx 实际监听端口的桌面 TLS/HTTP 复核（2026-09-08）

在“配置 → 修补已有配置”接通只读连接复核。端口来自所选主进程持有的 socket，绑定进程身份、inode 与网络命名空间；用户填写站点名称及不带查询参数的 HTTP 路径，不能指定其他连接地址、端口、CA 文件或命令。分别展示四种 TLS 协议的接受、明确拒绝、证书失败、本机能力不足及未能判断；现代协议完成证书校验后才发送 HEAD，只保留状态码与公开叶证书摘要。

修补、恢复、实例刷新和输入变化会清除旧观察，重复提交与迟到结果受控制。普通 HTTP 端口的握手失败不显示成旧 TLS 已关闭，HTTP 404 不冒充健康通过。源代码和验收范围见 [连接复核](NGINX_CONNECTIVITY.md)，长期开发规则已同步到根 `AGENTS.md`。

| 验证范围 | 实际结果 | 证据 |
| --- | --- | --- |
| Nginx 1.27.5 / Debian 12 bookworm / x86_64 / 普通容器 / OpenSSL 客户端 3.0.20 / 正常 Electron 入口 | **96/96**；原目录/版本/TLS 修补与恢复继续通过；新增真实自签证书拒绝、目标信任库、错误站点名、HEAD 404、IPv6、非 TLS 端口、修补后协议拒绝、恢复后旧协议返回和陈旧监听拒绝/刷新；所收集 renderer 异常与错误 **0** | `target/lab-nginx-repair/18ee45ac-c09b-4552-8ad5-b031f3c55e35/report.json` |
| Rust 全量 | core **1081** 通过 / **9** 忽略；sidecar 与集成边界 **654** 通过；合计 **1735** 通过。忽略项不计通过 | `target/goal-20260907/nginx-connectivity-rust-all.log` |
| Electron | 全量 **129 文件 / 904 测试**、类型和构建通过；最终边界收紧后另跑相关 **4 文件 / 48 测试**、类型与构建通过 | `target/goal-20260907/nginx-connectivity-electron.log`、`nginx-connectivity-final-ui.log` |
| Python helper | **14/14**；原生字序 IPv4/IPv6 解析、陈旧/共享监听拒绝、准确协议拒绝分类、旧协议不发 HTTP、证书上下文、秘密输出约束及弃用提示不污染 JSON | `target/goal-20260907/nginx-connectivity-helper.log` |
| Clippy / 源码门禁 | core 与 sidecar `--all-targets -D warnings` 通过；固定 API **128** 个、页面 **15** 项、源码门禁 **164** 个可达源文件 / **6** 项固定资源；没有放宽离线资源检查 | `target/goal-20260907/nginx-connectivity-clippy.log`、`nginx-connectivity-source.log` |

镜像摘要仍为 `sha256:57d0bb8d70b90e9e001a1ed2197d0217b82c7299aa30191a5eda008152611e8d`。原生报告分别保存独立 OpenSSL `tlsObservations` 和通过实际页面获得的 `nativeTlsObservations`。已查看 `nginx-connectivity-before.png` 与 `nginx-connectivity-after.png`：1080×700 的结果表能区分旧协议接受/拒绝、证书和 HTTP 状态，文案不把配置验证或 HEAD 200 当作业务恢复。唯一测试容器与临时应用数据已回收，未操作真实业务目标。

首次运行在连接复核时被拒绝：Python 的旧 TLS 版本弃用提示混入 SSH 合并输出，导致严格 JSON 解析失败。已仅对准确版本设置时的相关弃用提示作局部处理，并补回归后取得上述通过结果；失败材料保留于 `target/lab-nginx-repair/addf307a-c6f7-4a3f-801a-032de9ddc73e/`，不计通过。源码门禁曾识别到用于 IPv6 校验的 URL 字面量，改用直接 IP 解析后通过；门禁规则未改。

该阶段结果仍是页面当前观察，案件/报告留证进展见下一节；外部业务客户端、负载均衡、客户端证书、QUIC/Stream、更多产品版本和架构需分别验证。产品不会自动向真实目标添加 CA 或降低服务端安全级别，实验中的临时证书信任只发生在本次容器。系统、数据库、中间件与编排的完整闭环继续推进，严格发布台账仍为 **3/53**，长期目标尚未完成。

## Nginx 连接观察入案与失败恢复（2026-09-08）

完成的 TLS/HTTP 复核现已自动留存到案件，包括证书拒绝、握手失败和 HTTP 错误等观察。core 记录实际 SSH 来源、完成时间（UTC）、进程与监听身份、站点/路径、客户端版本、四种协议结果和公开证书摘要；完整记录进入案件时间线、Markdown/HTML 报告与离线 JSON。已核实的归属案件固定在复核开始时；更改当前案件或连接名称不会改写历史来源。新复核分别入案，同一份材料重试只补存一次。

保存失败仍保留页面结果，可展开/复制完整观察并重试；重试不重新连接目标。最初未能读取案件时，页面明确提示使用重试时的当前案件。未保存观察不能被新读取或修补静默替换；页面切换、断连、连接管理和关闭握手先等待正在进行的复核，随后处理未保存结果。保存成功后可直接打开对应案件，查看案件不改变后续采集归属。协议、证书和 HTTP 观察仍不等同业务恢复，案件 `stored-preview` 摘要仍区别于原始网络包及公开叶证书摘要。

| 验证范围 | 实际结果 | 证据 |
| --- | --- | --- |
| 正常 Electron 入口 + Nginx 1.27.5 / Debian 12 bookworm / x86_64 / OpenSSL 客户端 3.0.20 | **140/140**；保留原修补/恢复与 TLS 验收，追加 **11** 份完整观察入案、临时案件文件不可读、进行中立即切换页面、取消离开与取消断连、原记录重试、目标 HEAD 日志无新增、完整复制、案件入口、MD/HTML、独立 HTML 渲染与离线 JSON；所收集 renderer 错误和 main 观察错误均 **0** | `target/lab-nginx-repair/65f65619-cf0b-4faf-bc81-8e42d7474f70/report.json`；同目录 `nginx-connectivity-case.md` / `.html` / `.json` 及截图 |
| Rust 全量 | core **1083** 通过 / **9** 忽略；sidecar 与集成边界 **656** 通过，合计 **1739**。最终提示及 lint 修正后又执行连接留证相关 **11** 项测试通过。忽略项不计通过 | `target/goal-20260907/nginx-retention-rust-all.log`、`nginx-retention-final-rust.log` |
| Electron 全量 | **129 文件 / 910 测试**、类型检查及构建通过；涵盖精确字段和响应关联、不可伪造来源、原材料重试、进行中导航等待及保存状态展示 | `target/goal-20260907/nginx-retention-electron-final.log` |
| Clippy / 格式 / 源码门禁 | core 与 sidecar `--all-targets -D warnings`、`cargo fmt --check`、差异检查通过；固定 API **128**、页面 **15**、可达源文件 **164** / 固定资源 **6**，门禁未放宽 | `target/goal-20260907/nginx-retention-clippy.log`、`nginx-retention-final-checks.log`、`nginx-retention-source.log` |

实验镜像摘要仍为 `sha256:57d0bb8d70b90e9e001a1ed2197d0217b82c7299aa30191a5eda008152611e8d`。保存故障只发生在本次临时应用目录：完整原案件文件先保留，空目录占位使真实保存链路失败，恢复原文件后通过实际按钮补存。OS 文件选择和剪贴板在本次 main 中受控，未读写用户剪贴板；其余链路执行真实产品代码。已查看 `nginx-connectivity-unsaved.png` 和 `nginx-connectivity-standalone.png`，1080×700 下未保存提示、四行结果和独立 HTML 完整来源记录可读且无水平溢出。唯一测试容器与临时应用数据均已回收。

初次留证流程 **135/135** 通过，记录于 `target/lab-nginx-repair/62218bfc-50e9-436b-9df4-95fb7b93985e/`。补上进行中导航和断连保护后的运行 `b3bfb1d1-cbbb-4e96-a25e-a141c0ebf990` 虽然功能检查通过，却捕获 `binding.startupData` 为空的 Electron 沙箱初始化错误，整次仍记为失败。错误位置与 [Electron 43.4.1 沙箱初始化源码](https://github.com/electron/electron/blob/v43.4.1/lib/sandboxed_renderer/init.ts) 一致；[渲染器绑定源码](https://github.com/electron/electron/blob/v43.4.1/shell/renderer/electron_sandboxed_renderer_client.cc) 对启动数据与文档初始化顺序有明确假设。结合既有案件探针，把过早连接 CDP 视为可能诱因，改为从 main 注册错误观察、等待真实主文档加载完成，再连接 renderer。最终运行取得上述 **140/140**；未过滤错误、修改 Electron 依赖或放宽沙箱。此结果验证本次探针时序，不宣称修复 Electron 本身或覆盖所有冷启动条件；main 错误观察起点仍是 inspector 连接时。

边界见 [连接复核与留证](NGINX_CONNECTIVITY.md) 和 [案件工作台](CASE_WORKSPACE.md)。未保存材料只有当前连接的有期限缓存，意外退出后的持久待存恢复尚未实现。修补计划与前后观察自动关联、跨主机关联、更多系统/产品/运行时、业务恢复判定以及默认案件可读命名继续保留为后续工作；严格发布台账仍为 **3/53**。

## PostgreSQL 候选基线、字节边界与历史兼容（2026-09-08）

PostgreSQL 的 7 项检查现已区分候选文件与运行值。同一文件内最后标量按原生语法解释，各文件独立保留风险；常见 `postgresql.auto.conf` 与 Debian `main/conf.d` 路径已纳入。候选安全值不再标为运行状态符合，文件查看跟随风险来源且不标记唯一生效行。日志收集器改为核对实际持久留存，监听按业务范围处理；SCRAM 拼写、已有口令迁移、SSL 和重载/重启建议已修正。

扫描值和来源读取统一使用字节 locale，防止 GNU awk 在中文环境中按字符计算而越过读取上限。长建议自动换行，配置区保留 160px 最小外框并可滚动，避免原文被长说明挤没。历史 `logging_collector on/off` 和旧目录的 `scram_sha_256` 保留原值与摘要，仅历史校验接受；新的写入仍拒绝，缺少修改后完整文件证据的旧记录不能授权恢复。

| 验证范围 | 实际结果 | 证据 |
| --- | --- | --- |
| PostgreSQL 16.15（Debian 16.15-1.pgdg13+2）/ Debian 13 trixie / x86_64，真实 SSH/RPC 与正常 Electron | **50/50**，包含 **22** 组原生 `postgres -C` 对照、独立候选、超长内容、未重载文件、`ALTER SYSTEM` 与运行来源、实际文件视图、恶意文本、最小窗口、滚动及断连；观察到的控制台错误 **0** | [原生报告](../target/lab-postgresql-baseline/dcde9c12-0d3d-44f7-b36d-afe21918ac52/report.json) |
| WSL Ubuntu 的 GNU Awk 5.2.1 | **3** 组已包含在上述 50 项中：24 字节短中文注释保留线索，18,012 字节中文超长行与 540,370 字节文件保持待复核；值和来源命令均强制字节语义 | 同一报告的 `observations.gnuAwk`；`target/goal-20260907/postgresql-gawk-locale-control.log` 保留 UTF-8/C 对照 |
| Rust 最终全量及历史兼容专项 | core **1085** 通过、**9** 忽略；sidecar 与集成边界 **658** 通过，合计 **1743**。历史兼容专项 **1/1** 验证三类旧值、完整记录/摘要保留、新写入拒绝和旧记录恢复无远端副作用。忽略项不计通过 | `target/goal-20260907/postgresql-baseline-rust-all.log`、`postgresql-baseline-history.log` |
| Electron 类型、单测、构建及静态检查 | **129** 个文件、**911** 项测试通过；Clippy `-D warnings`、源码门禁 **164** 个可达文件 / **6** 个固定资源、格式与差异检查通过 | `target/goal-20260907/postgresql-baseline-electron.log`、`postgresql-baseline-clippy.log`、`postgresql-baseline-source.log`、`postgresql-baseline-final-checks.log` |

原生镜像为 `sha256:e00728409e510ae569d85927d0067046b9b09f9206c0b99f9e69c74d74c6d7d6`。已查看该报告目录的 `postgresql-auto-conf-source.png`、`postgresql-logging-context.png` 与 [配置原文截图](../target/lab-postgresql-baseline/dcde9c12-0d3d-44f7-b36d-afe21918ac52/postgresql-file-evidence.png)。1080×700 下配置区外框 160px、实际内容高度 143px，滚动 70px 成功，长建议完整换行。历史兼容补丁另由专项和最终全量 Rust 回归验证；该专项未计为历史页面的新增原生 UI 验收。长路径下的“重新读取”按钮保持单行。

失败材料保留在同类报告目录：`6cc33934-b511-4a58-8392-35bb178d907a` 暴露 Windows/WSL 内联脚本引号传递变化，改为标准输入写入测试文件；`60e34dcc-3696-4511-af3c-5e4048959937` 暴露 Windows 路径反斜杠传递问题；`5f5a7e55-add9-4a67-99de-6c30b149241b` 的尺寸断言没有扣除 Windows 横向滚动条，整次仍记失败，后续分别核验外框、可见高度和实际滚动。早期 42/42、44/44 与 49/49 记录保留；补齐历史兼容和长路径按钮显示后，最终采用上述 50/50。所有本次测试容器与临时数据已回收，各运行标签再次检查无残留，见 `target/goal-20260907/postgresql-baseline-cleanup.log`。

完整边界和复现见 [PostgreSQL 基线](POSTGRESQL_BASELINE_VERIFICATION.md)。SQL、`ALTER SYSTEM` 和配置文件写入只用于构造实验输入，不能计为应用修补。实际实例身份、主配置/include/启动与会话覆盖、HBA、现有账号口令、实际 TLS/日志与业务复核、精确修补及恢复尚待接通。其他 PostgreSQL 版本、架构、部署方式和衍生产品保留独立适配要求，本轮不扩大严格发布验收范围。

## PostgreSQL 原生认证与运行参数基础（2026-09-08）

PostgreSQL 运行参数读取现经 core 管理的原生协议和已绑定的 SSH 转发通道完成，密码不交给远端 `psql` 或 shell。默认验证 TLS 证书链与主机名；只有明确选择字面回环 IP 时允许仅由 SSH 保护。SCRAM/MD5 认证、闭合身份/参数查询、受限帧与通知、目标和配置变化、取消与断连共享任务生命周期。通道关闭后的服务端工作仍需其语句时限约束，不能声称立即取消了数据库 SQL。

真实 PostgreSQL 数据也补齐了两个旧解析缺口：Debian/Ubuntu 包版本标签，以及 `ssl_max_protocol_version` 的合法空枚举选项。新的原生入口只展示按名称和有限取值验证的 SSL、日志、口令算法等标量；其余值保持脱敏，原远端客户端 TSV 入口仍隐藏全部值。

| 验证范围 | 实际结果 | 证据 |
| --- | --- | --- |
| Windows 原生 core → WSL/SSH → PostgreSQL 16.15 / Debian 13 trixie / x86_64 | **29/29**；实际 SCRAM/MD5、CA/IP 与主机名验证、TLS 不降级、权限拒绝、锁时限、取消、目标/配置变化、SSH 断连/禁止转发、秘密不进入便携明文与测试日志，以及独立 `pg_stat_activity` 清理检查 | `target/lab-postgresql-native/53209016-d643-4f8b-b766-19b32285392c/report.json` |
| PostgreSQL 相关单测 | **35** 通过；本次原生容器用例在默认单测中明确忽略，由上一行单独执行 | `target/goal-20260907/postgresql-native-unit.log` |
| core/backend 回归 | **1,756** 通过：core **1,098**，backend **658**；默认 **10** 项忽略不计通过 | `target/goal-20260907/postgresql-native-rust-all.log` |
| 编译和静态验证 | 最新 backend 编译、Clippy `-D warnings`、依赖门禁、格式与差异检查通过 | `target/goal-20260907/postgresql-native-build.log`、`postgresql-native-clippy.log`、`postgresql-native-dependency.log` |
| Electron 静态接线边界 | **164** 个可达文件 / **6** 个固定资源通过；本次没有新增数据库 RPC 或桌面页面 | `target/goal-20260907/postgresql-native-source.log` |

该原生容器镜像为 `sha256:e00728409e510ae569d85927d0067046b9b09f9206c0b99f9e69c74d74c6d7d6`，服务日志记录真实应用连接使用 TLS 1.3。测试使用独有临时连接库、两个 SSH 测试端口和数据库 tmpfs，未向系统信任库导入实验 CA。

失败材料保留在同类报告目录：`67ca4a10-34c9-4f92-9bc6-a62ddc95686a` 定位到 `connect_raw` 的 Config 主机名缺失；`e443163c-28a6-4408-953f-1d046da534d7` 定位到 Debian 包版本标签；`8986c171-8819-4703-bbef-2f1b289a09f6` 暴露 WSL/Windows 时钟偏差导致证书尚未生效，探针改为记录并等待合法有效期；`632de206-7e18-459d-92b7-759b16c469b9` 与 `a7c8c33f-7a9b-49ff-a844-9988c9c27026` 定位到合法空枚举被拒绝；`85d4cc16-5aac-4e04-b40d-fe67cab42962` 确认旧 TSV 入口隐藏全部值，随后新增原生入口的有限标量授权。这些记录不计通过，最终使用上述 29/29。

实现和复现见 [原生连接边界](POSTGRESQL_NATIVE_RUNTIME.md)。该核心基础阶段尚无 Electron 数据库专用页，旧 GPUI 接线描述已更正；随后桌面接线见下节。实际实例、配置图、HBA、修补/恢复和案件留证仍须继续推进。PostgreSQL 17/18、其他桌面 TLS 平台和衍生产品仍需独立实测；本次不扩大严格发布矩阵。

7 次实验的容器均已按各自运行标签复查无残留，最终报告中的 9 份源码/依赖摘要与当前文件一致，见 `target/goal-20260907/postgresql-native-cleanup.log`。本次 7 份文档中的 46 个本地链接通过检查；本轮未增加 Electron API/页面或变更发布 ledger。

## PostgreSQL 桌面参数检查与连接管理（2026-09-08）

“数据库”页现可通过当前 SSH 主机保存和编辑 PostgreSQL 连接、验证 TLS、开始只读检查、取消、搜索及分页。新手视图解释观察值和局限；专家可核对来源、生效范围、待重启状态及保留的合法空枚举。参数结果保留于内存十分钟，不能据此声称完整基线合规或业务已恢复。

新连接明确关联 SSH 配置；旧未关联连接必须保存确认关联后才能读取。core 在同一配置库锁内比较完整版本（含加密凭据）再保存或准备删除，读取前再次核对该版本。删除本机连接走具体计划、两分钟确认、单次执行、journal 和独立回读。编辑、保存、导航、连接管理、断连及真实窗口关闭参与同一生命周期。过期或冲突等正常业务拒绝使用有限 `rejected` 结果并显示给用户，避免被 Electron 自动记录成 IPC 异常；异常采集没有过滤。

| 验证范围 | 实际结果 | 证据 |
| --- | --- | --- |
| 正常 Electron → 原生 core / SSH → PostgreSQL 16.15，Debian 13 trixie / x86_64 | **39/39**：真实 TLS/SCRAM/MD5、错误口令/CA、显式回环与非法范围拒绝、配置并发和删除计划失效、50 行分页、空枚举、实际锁等待取消、旧连接关联、脏编辑导航及真实关闭取消、删除核实和断连；启动、main 和 renderer 的控制台错误 **0** | [最终桌面报告](../target/lab-postgresql-desktop/67d6bb10-a10e-4670-9c9e-35af071fa27c/report.json)；同目录保留新手、专家与认证失败截图 |
| Rust | core 全量 **1,102** 通过、**10** 忽略；最新 backend 全量 **662** 通过，合计 **1,764**。最后的条件合并另跑数据库专项 **31/31**；忽略项不计通过 | `target/goal-20260907/postgresql-page-rust-final.log`、`postgresql-page-backend-final.log`、`postgresql-page-core-final.log` |
| Electron | **132** 个测试文件、**924** 项通过；类型检查与正常构建通过 | `target/goal-20260907/postgresql-page-electron-final.log` |
| 静态与依赖 | Clippy 全 targets `-D warnings`、格式、diff、依赖门禁通过；源码门禁 **168** 个可达文件 / **6** 个固定资源，有限 preload API **129** 个 | `target/goal-20260907/postgresql-page-clippy-final.log`、`postgresql-page-source-final.log`、`postgresql-page-dependency.log` |
| 证据复核与清理 | 最终报告 **19** 个源码/依赖摘要匹配；解码报告、完整探针输出及服务日志均无口令 canary。六次实验均已回收各自容器与临时应用数据，容器标签另查无残留 | `target/goal-20260907/postgresql-page-evidence-check.json`、`postgresql-page-cleanup.json` |

真实镜像仍为 `sha256:e00728409e510ae569d85927d0067046b9b09f9206c0b99f9e69c74d74c6d7d6`。原生核心 **29/29** 与候选基线 **50/50** 是前述独立阶段记录，不与本次 **39/39** 混算。数据库页的迁移项继续保持 Pending，严格发布账本仍为 **3/53**，未扩大其他版本、平台和部署方式的发布证明。

失败记录全部保留：`5bc2ee53-3e9d-4c84-b272-bd305e4765a0` 在启动阶段启用 main Runtime 时出现 Promise 被回收错误；后续改为主文档就绪后启用；`a6cef27c-2eaa-4d06-b91e-80fa8e8b6c54` 是测试误数 DTO 字段，改为核对完整十字段集合；`ccfd503e-fe76-4f9c-9355-06bce67491d2` 是探针用了不存在的导航文案，改为实际“主机全景”；`47cf9df4-cc8d-411c-9927-891cdcf19761` 记录了六次预期业务拒绝产生的 main 控制台错误，随后修正产品的错误响应契约。`02abefad-2027-47c3-a458-508fffedc442` 的 **38/38** 保留为增加真实窗口关闭验证之前的通过记录，最终采用上表 **39/39**。

下一步仍需关联数据库实例、主配置/include/启动与会话覆盖、HBA 和业务认证，完成按实例计划、修补、恢复、独立业务复检及案件留证。其他数据库原生协议、PostgreSQL 17/18、国内发行版、其他架构和桌面 TLS 平台继续分别适配与实测。复现命令及边界见 [PostgreSQL 原生与桌面流程](POSTGRESQL_NATIVE_RUNTIME.md)；长线任务仍覆盖 Linux 应急、Docker/Kubernetes 管理与排查及国内外基线，不以这一阶段验收代替整个目标完成。


---

## PostgreSQL 会话、来源与检查摘要（2026-09-08）

数据库检查现增加服务端报告的数据库 OID、登录/执行身份、会话 PID、连接两端、启动/配置加载时间、恢复状态与有权限时的集群标识；显示四种配置位置和十项重点参数的来源文件/行号。参数读取前后比较这些观察并交叉核对参数来源，拒绝混合或不完整结果。默认视图保留主要身份说明，专家按需展开来源详情；报告路径不构成主机文件操作权限。

“读取并留证”沿 core → 原生 SSH/数据库协议 → sidecar → 精确 main/preload 契约 → 数据库页 → 案件/报告接线。开始时捕获案件并占用采集，成功、失败与取消生成不同摘要；本机存储失败保留原文和原案件，补存幂等且不重新采集。未保存摘要在参数过期、连接配置变化后仍可处理，并参与导航与真实关闭保护；取消无法核实时允许用户明确选择离开并核对案件。

该记录是会话与十项公开参数的有限摘要，不包括全部参数、配置内容、来源路径或 HBA。未保存摘要的异常退出恢复尚未完成；实例与 SSH 进程/网络命名空间的可靠关联、完整配置图、按实例计划、修补、恢复及业务复核仍须继续。Database 迁移项保持 Pending，严格发布账本仍为 3/53。

最终验收为 Windows 正常 Electron 入口 → WSL2 Ubuntu → 独有 PostgreSQL 16.15 / Debian 13 / x86_64 容器，**62/62**，控制台错误 **0**。固定实测镜像 `sha256:e00728409e510ae569d85927d0067046b9b09f9206c0b99f9e69c74d74c6d7d6`；容器限制 512 MiB / 1 CPU / 128 PID，数据使用本次 tmpfs。报告包含 23 个源码摘要、真实会话/来源观察、服务日志、七张桌面截图和具体检查结果，见 [最终报告](../target/lab-postgresql-desktop/00933df3-3a32-4408-a20c-d0a88ec30976/report.json)。

受限角色实测确认 `ssl_min_protocol_version` 与 `ssl_max_protocol_version` 在 `pg_settings` 中不可见，其余参数仍可读取；基础查询和参数读取一致缺失时保留明确的“未取得”，前后变化或不完整来源继续拒绝。新增回归同时拒绝缺失参数伪造来源文件或待重启状态。集群控制函数单独按执行权限查询，不将受限角色误报成完整读取失败，也不静默提权。

测试中故意损坏本次临时案件库并持有数据库锁，实际验证读取与保存同时失败、原文继续可复制、取消导航/窗口关闭、活动案件变化后的原案件补存、重复补存幂等、明确放弃、取消记录及案件报告。普通值显示与案件留证均通过正常产品边界；夹具中的 SQL、授权和文件修改不计产品修补能力。

Rust core 与 sidecar 合计 **1,770 通过、10 忽略**；Electron **132 文件 / 930 测试通过**，类型检查与构建通过。core/sidecar Clippy（含全部测试目标、拒绝 warning）、格式检查、源码门禁（168 个 renderer 可达源码 / 6 个资源）、依赖门禁和 `git diff --check` 通过。preload API 仍为 129 个；忽略项及其他版本/平台未执行项不计通过。参见 [读取与留证边界](POSTGRESQL_NATIVE_RUNTIME.md)。

本轮调试与最终证据均保留。表中的失败不是通过项：

| 运行记录 | 结果与处置 |
| --- | --- |
| [e84e362d](../target/lab-postgresql-desktop/e84e362d-abcb-46b2-8d6e-0aaaaf74469c/report.json) | 首次观察读取失败；定位数据库 OID 的 JSON 类型差异。 |
| [5a09a03](../target/lab-postgresql-desktop/5a09a036-42e9-412b-ba83-6e58d76803cf/report.json) | 独立查询确认 OID 被序列化为字符串；闭合 SQL 显式转为 int8 数值。 |
| [65335141](../target/lab-postgresql-desktop/65335141-53dd-4f38-bc8e-9d2a534ff43a/report.json) | 旧取消夹具的数据库锁未释放；新增场景先核实本次锁已释放。 |
| [7d0799e6](../target/lab-postgresql-desktop/7d0799e6-1946-41d9-a7e8-f597602950ba/report.json) | 受限角色触发未选中 CASE 分支中函数的权限检查；改为按权限发送独立控制数据查询。 |
| [2bf1c4eb](../target/lab-postgresql-desktop/2bf1c4eb-5602-4fcb-9ff8-b2f668255dde/report.json) | main 调试器启动观察报 Promise 被回收；同步观察表达式不再等待 Promise。原错误保留。 |
| [938f0377](../target/lab-postgresql-desktop/938f0377-9d1e-41d8-93d7-ccf09ec75bf1/report.json) | 受限角色的空来源校验失败，未计为桌面通过。 |
| [0e05f8e2](../target/lab-postgresql-desktop/0e05f8e2-1ceb-40a3-9220-518df40cf81d/report.json) | 独立查询确认两项参数按角色隐藏；补齐一致缺失处理及新手可见提示。 |
| [cfb1bdb9](../target/lab-postgresql-desktop/cfb1bdb9-fee2-4a1a-80ad-79be32d68216/report.json) | 完整桌面 61/61，通过并检查权限缺口、保存成功/失败与案件页截图。 |
| [00933df3](../target/lab-postgresql-desktop/00933df3-3a32-4408-a20c-d0a88ec30976/report.json) | 补强 JSON 转义口令检查后的最终 62/62，控制台 0 错误。 |

[独立证据复核](../target/goal-20260907/postgresql-observation-verification.json)确认最终 23 个源码摘要全部匹配，九次报告/文本日志解码后均未检出本次测试口令；九次运行均记录清理，本轮标签对应的容器在 Docker 中无残留。保留全部失败证据，未清理其他任务或用户资源。


## PostgreSQL 主机进程对应（2026-09-08）

原生数据库连接保持存活时，通过同一个 SSH 会话核对数据库报告的完整 TCP 两端、连接 socket 所属、pidfd、父子进程、可执行文件摘要与相同 PID/网络/挂载命名空间；核对后再次读取 SQL 身份和来源。主进程工作目录与数据库报告目录分别保留，一致、不同和未取得均明确展示。远端固定程序只读，未读取 argv、环境或配置内容，也不安装、提权或执行被检查的程序。

新手可直接看到是否对应和剩余缺口，专家按需展开进程及二进制依据。缺少 Python、pidfd、权限或无法对应时仍可查看参数。v2 案件摘要保留对应状态与可执行文件 SHA-256，原案件补存、保存失败保护和关闭保护继续有效；旧 v1 历史记录不改写。

实际验收为 Windows 正常 Electron → WSL2 Ubuntu → 独有 PostgreSQL 16.15 / Debian 13 / x86_64 容器、Python 3.13.5、内核 `5.15.167.4-microsoft-standard-WSL2`；独立主机 boot ID 与采集 boot ID 相同。基础镜像仍为 `sha256:e00728409e510ae569d85927d0067046b9b09f9206c0b99f9e69c74d74c6d7d6`，夹具限 512 MiB / 1 CPU / 128 PID，仅本次 tmpfs 数据目录与私有 SSH 映射。为验证跨 UID 读取，仅该容器增加 `SYS_PTRACE` 并安装 Python；产品不进行这些准备，不将此权限组合冒充默认容器能力。

最终 **69/69**、控制台 **0 错误**，见 [原生报告](../target/lab-postgresql-desktop/6c681078-9238-4fcf-a0ea-3882b449b4e2/report.json)。独立读取主进程与二进制并对比；另保持一个受回环 HBA 认证限制的 TCP 夹具会话，确认错误端口、错误 PID 和低权限账号不能取得对应。真实 Electron 中临时缺工具仍显示参数与明确缺口；受限数据库账号仍可核对主机进程，但其 SQL 数据目录保持未取得。案件摘要和报告保留新的进程对应内容。

Rust core/sidecar **1,772 通过、10 忽略**，Electron **133 文件 / 932 测试**，独立 procfs Python 测试 **6/6**；类型、构建、全部目标 Clippy、格式及源码门禁（169 个 renderer 可达源码 / 6 个资源）通过。新增测试拒绝外来/缺失 PID、错误端口、非 ESTABLISHED/重复连接、socket 非该进程持有、未知或部分 DTO、整数溢出和伪造目录一致状态；IPv4、IPv6 mapped 与字节序用固定 procfs 样例核对。忽略项不计通过。

| 运行记录 | 结果与处置 |
| --- | --- |
| [098a5a9d](../target/lab-postgresql-desktop/098a5a9d-7188-46a6-af19-4e91f99a461b/report.json) | 容器归属检查因 Docker 返回 `CAP_SYS_PTRACE` 而停止；按完整 ID、标签、镜像、资源与权限核实后仅清理该容器，保留 [补充清理证据](../target/lab-postgresql-desktop/098a5a9d-7188-46a6-af19-4e91f99a461b/cleanup-after-capability-normalization.json)。修复仅归一化 `CAP_` 前缀，额外权限仍拒绝。 |
| [dcaa7582](../target/lab-postgresql-desktop/dcaa7582-e168-4bff-a598-7112f07b27a6/report.json) | 正常桌面进程对应与独立摘要比较通过；补充 TCP 夹具账号被原有 HBA 拒绝。后续仅在本次容器中增加回环认证规则，并保留错误日志。整轮未计通过。 |
| [6c681078](../target/lab-postgresql-desktop/6c681078-9238-4fcf-a0ea-3882b449b4e2/report.json) | 最终 69/69。九张原生截图保留；主机对应成功与缺工具两种状态已视觉核对。 |

[证据复核](../target/goal-20260907/postgresql-process-verification.json)确认 28 个源码摘要匹配、明文/转义测试口令未进入报告和文本日志、本轮三次容器无残留。临时连接库也已按归属清理。详见 [主机进程对应边界](POSTGRESQL_PROCESS_CORRELATION.md)。

此阶段仍未完成完整配置图、HBA/ident 与账号权限检测、跨命名空间/代理实例映射、按实例变更与恢复、业务复核或异常退出后的待存恢复。进程对应只是采集时证据，不能直接授权后续处置。其他 PostgreSQL/Python/内核版本和 rootless/Kubernetes 组合仍待实测；Database 迁移项保持 Pending，严格发布账本仍为 3/53。


## PostgreSQL 访问规则与角色诊断（2026-09-08）

「读取数据库状态」现在在原生只读连接中同时检查 HBA/ident 当前文件视图与角色直接属性，结合参数、会话和主机进程观察。缺权限、查询失败、异常输出、读取变化和数量/字节超限各自保留；未取得不作为通过。全部认证选项值、原始解析报错、口令校验值和用于前后比较的私有摘要不进入 DTO 或留证。

新手先看总数、需复核数和下一步，专家可看来源行、认证名称、角色属性并搜索分页；查看、搜索、翻页后自动定位并把键盘焦点放到结果标题。`md5` 规则与 MD5 存储标识分开，口令到期只解释口令认证影响。视图丢失的引号不被拼回配置；LDAP 的派生 `ldapscope` 只在诊断上下文识别，没有扩大原始 HBA 的可写选项。v3 案件摘要只增加数量、提示代码与缺口，保留旧记录及原案件补存规则。

最终 **94/94**，正常 Electron 启动/preload/renderer **0 错误**，见 [最终报告](../target/lab-postgresql-desktop/6be33e26-486f-4d98-8ebd-663f209a465c/report.json)。环境为 Windows 桌面 → WSL2 Ubuntu → 独有 PostgreSQL 16.15 / Debian 13 / x86_64 容器；镜像、资源和进程准备边界与前一阶段相同。真实测试覆盖未重载拒绝规则、include 来源、带引号选择项、LDAP/RADIUS 秘密、角色权限与到期、口令更换、真实搜索分页/焦点、坏规则和留证、受限账号、三类数量上限和 HBA 字节上限；全部原连接、进程和留证回归保留。

Rust core/sidecar **1,776 通过、10 忽略**；Electron **134 文件 / 937 测试**，类型检查和构建通过；Clippy（全部目标、拒绝 warning）、格式、源码门禁（171 个 renderer 可达源码 / 6 个资源）和 diff 检查通过。固定 preload API 仍为 129。私有字段变化即使公开行相同也使结果失效、额外秘密字段、缺失字段、重复行、权限矛盾、过期后的迟到页和原任务数量不一致都有对应拒绝测试；没有把忽略项计为通过。

| 运行记录 | 结果与处置 |
| --- | --- |
| [0c348d12](../target/lab-postgresql-desktop/0c348d12-7298-4fa9-a6d5-afe4e2f475e6/report.json) | 旧参数搜索探针定位到新增访问搜索框，超时；限定输入框到全部参数区域。 |
| [43d5ca4d](../target/lab-postgresql-desktop/43d5ca4d-8517-4f21-b7fb-e967e63c7e74/report.json) | 搜索按钮也采用了宽泛匹配；同时限定参数按钮区域。两次超时均不计整轮通过。 |
| [f4741cd6](../target/lab-postgresql-desktop/f4741cd6-d913-4daf-a80a-8b86ce3dde7e/report.json) | 原生访问查询、独立数量和标识分类通过；夹具 `DO $$` 被 WSL 命令行展开。夹具 SQL 改走带引号分隔符的标准输入，清理错误独立保留。 |
| [47ee9e12](../target/lab-postgresql-desktop/47ee9e12-0581-435a-9095-ee2b0e44c6a9/report.json) | 未重载规则观察通过；夹具把普通参数配置的单引号用于 HBA/ident include，产生文件问题。改用其实际认证文件语法。 |
| [13fab690](../target/lab-postgresql-desktop/13fab690-899b-4b97-a60e-514d3cf6aa1b/report.json) | 第一轮完整 **89/89**。随后依据实际截图完善详情焦点，并识别服务端派生的 LDAP 字段。 |
| [3ec3eb98](../target/lab-postgresql-desktop/3ec3eb98-2af3-4096-8222-483ccdc1339e/report.json) | 新焦点、真实搜索分页和派生字段通过；新增磁盘扫描遇到应用实例锁，移到 Electron 退出后执行，仍扫描全部文件。 |
| [6be33e26](../target/lab-postgresql-desktop/6be33e26-486f-4d98-8ebd-663f209a465c/report.json) | 最终 **94/94**；含关闭后的全部临时本机数据秘密标记检查、查询无残留和归属清理。 |

[独立复核](../target/goal-20260907/postgresql-access-verification.json)确认最终 37 个关键源码摘要匹配；本轮七次报告与文本日志未检出主连接测试口令的明文或 JSON 转义形式，七次容器和应用数据均清理，本轮标签无残留。更小窗口、其他 PostgreSQL 版本/架构/部署方式未借用此结果。

当前访问视图不证明已加载策略，角色直接属性不代替成员关系、对象授权或实际登录；完整配置图、访问策略关联、按实例修补恢复、业务复核和异常退出待存恢复仍需继续。Database 迁移项保持 Pending，严格发布账本仍为 **3/53**。实现、复现和边界详见 [访问诊断](POSTGRESQL_ACCESS_DIAGNOSTICS.md)。


## PostgreSQL 成员授权与静态权限来源（2026-09-08）

访问诊断增加有界 `pg_auth_members` 读取和当前数据库所有者核对。角色行可展开成员、自动继承、SET ROLE、切换后新增普通权限四类路径；区分逐条授权选项、原始会话身份、不同授权者、数据库所有者隐式关系和超级用户分支。管理属性不能随普通权限继承，ADMIN 只作有条件提示。页面提供搜索、分页、明确长路径截断及键盘焦点；产品仍不执行权限修改。

v4 案件摘要保留原来参数、会话与进程信息，增加成员数量、路径分析状态和可切换取得额外管理属性的登录角色数，旧 v1/v2/v3 不重写。两次读取变化、缺少角色/成员/数据库数据、超限、无效图、过期和迟到页均保留缺口或拒绝。

Rust **1,781 通过 / 10 忽略**；Electron **135 文件 / 941 测试**，类型检查与构建通过。Clippy（core/sidecar 全部目标、拒绝 warning）、格式、源码门禁（173 个 renderer 可达源码 / 6 个资源）和 diff 检查通过。新增覆盖多种路径、超级用户区别、多个授权者、循环/引用拒绝、分页/长路径、缺失和秘密字段、权限来源页面的过期及数据库归属变化。原生正常桌面完整 **110/110**，启动/preload/renderer **0 错误**，见 [最终报告](../target/lab-postgresql-desktop/bbaa35ba-b046-4345-be1d-93e080868e95/report.json)。与 6 组实际角色的 MEMBER/USAGE/SET 共 18 组原生查询比较一致，独立会话复核混合路径与权限变化；覆盖隐式数据库所有者、多授权者、NOINHERIT 默认值、ADMIN、44 步路径、2048 条成员上限、权限拒绝、v4 留证和真实页面焦点。当前 43 个关键源码摘要一致，详见 [独立复核](../target/goal-20260907/postgresql-membership-verification.json)。

首轮 [8d3701b7](../target/lab-postgresql-desktop/8d3701b7-3087-4e98-8e3e-aa9ecc228ae5/report.json) 已完成的 61 项断言通过，但夹具把 OID JSON 字符串传入数值请求而被拒绝，整轮失败。夹具查询显式转 bigint 后第二轮完整通过；没有放宽请求边界。两轮都清理了容器和临时应用数据，并独立查询确认相应 UUID 标签无残留。主连接口令明文/JSON 转义未进入报告和文本日志；最终退出后的全部临时本机文件扫描也未发现认证选项/错误秘密标记。环境仍为独有 PostgreSQL 16.15 / Debian 13.6 / x86_64、固定基础镜像、512 MiB / 1 CPU / 128 PID 和自有 tmpfs。

未完成具体对象授权、已加载访问规则匹配、完整配置图、按实例修补/恢复及业务验证；大量角色的额外管理属性快捷筛选、其他 PostgreSQL 版本/架构/部署方式仍需推进。Database 迁移和整个长期目标保持进行中，严格发布账本仍为 **3/53**。详见 [访问诊断范围](POSTGRESQL_ACCESS_DIAGNOSTICS.md)。
