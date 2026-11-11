# 数据库账号口令修改：设计与验收边界

2026-11-10 立项。来源：运维2 writeup 用 `SET PASSWORD` 加固 MySQL root 弱口令；路线图条目见 [PRODUCT_ROADMAP](PRODUCT_ROADMAP.md) “数据库应急”节。范围为 PostgreSQL 与 MySQL/MariaDB 两种产品，可修改连接账号以及访问诊断/账号列表中的其他登录账号，连接账号具备读取旧口令校验值的权限时提供一次性恢复。

本功能是对真实数据库的写入：每次执行前展示目标、账号、影响和恢复条件，绑定不可变计划并逐次确认，专家模式不跳过。不复用 core 遗留的通用 `plan_mutation`（任意 SQL，未接线，见 `UNWIRED_FEATURES.md`）。

## 实施状态（2026-11-10）

- PostgreSQL：已实现。core `database_password.rs`（计划、执行、登录复核、恢复令牌与已存口令放回），`postgresql.runtime` 方法新增 `plan-password` / `execute-password` / `plan-password-restore` / `execute-password-restore`，数据库页 `PostgresqlPasswordDialog`。
  - 实验：PostgreSQL 16 一次性容器 6/6（`tools/lab/probe-postgresql-password.mjs`）。
  - 桌面：调试构建 21/21（`tools/lab/probe-ui-postgresql-password.mjs`），报告在 `target/desktop-debug/postgresql-password-*/`。
  - 已知限制：执行中按 Escape 的阻止只有单元测试覆盖（探针中执行先于按键完成）；服务层 duplex 夹具未建，提交后失败路径由单元接缝测试与实验覆盖；其他 PostgreSQL 版本、TLS 证书模式、复制拓扑未测。
- MySQL / MariaDB：进行中（2026-11-11，本地未推送）。core `mysql_wire.rs`（自写协议：HandshakeV10、`mysql_native_password`/`caching_sha2_password` 快速认证、完整认证仅 TLS、COM_QUERY 文本结果集、有界读取）与 `mysql_native.rs`（TLS 升级、请求校验、会话封装）已实现并过单测 8 项；口令模块、backend API、UI、实验室验证未完成。

## 共同规则

- **语句闭合**：只有本模块生成的固定语句能到达数据库；账号名、host 部分由 core 按各产品的标识符/字符串规则转义，页面只提交账号句柄，不提交语句或账号名文本。
- **新口令**：页面输入两次，后端只接收一次；core 校验 12–1024 字节 UTF-8、无控制字符和 NUL、至少三类字符（大写/小写/数字/其他）、不包含账号名（不区分大小写）。只存在于后端计划条目的 `SecretValue`（清零），执行或计划到期（120 秒）即丢弃；不进入 DTO、日志、操作日志、案件和报告。
- **计划绑定**：SSH 目标与会话代次、数据库连接配置版本摘要（含已存口令）、服务端身份（产品、版本；PostgreSQL 另含集群标识/启动时间观察）、账号身份（PostgreSQL 角色 OID+名称，MySQL `user`+`host`+认证插件）、口令格式、是否可恢复、是否同时更新已存连接口令。任一项在执行时不一致即拒绝，要求重新计划。计划只能执行一次。
- **确认内容**（简明中文）：主机与数据库地址、账号、改后格式；“已经连上的会话不受影响，业务程序下次用旧口令连接会失败，请同步更新应用配置”；复制账号、超级用户、连接账号本身的额外提示；可恢复或“改后无法取回旧口令”。
- **执行后复核**：用新口令新建独立连接，以该账号登录并核对服务端报告的当前账号。结果分三类分别报告，不混为一谈：
  - 复核通过；
  - 新口令被拒绝（强烈建议恢复或再次修改）；
  - 无法复核（账号来源/访问规则不允许从当前路径登录、网络或超时），说明原因，不说成失败也不说成通过。
- **不自动恢复**：复核失败不自动放回旧口令（失败可能来自访问规则而非改动本身）；可恢复时给出“放回旧口令”按钮，走独立计划与确认。
- **已存连接口令**：改的是连接配置自己的账号时，计划默认勾选“同时更新已保存的连接口令”。只在复核通过后、按计划时的配置版本做比较写入；配置已被编辑则不覆盖并说明。复核未通过时不改已存口令。
- **恢复**：仅当执行事务中成功读到旧校验值时可用；旧值只保存在后端进程内存（清零），执行后 10 分钟内有效、恢复一次或到期后丢弃，不落盘、不进 DTO。恢复同样绑定计划与确认；完成后以目录回读比较（恒定时间比较）复核，PostgreSQL 读 `pg_authid.rolpassword`，MySQL 读 `SHOW CREATE USER` 的认证串。已存连接口令若在执行时被更新，恢复计划提示需要手工改回。
- **审计**：沿用 `OperationPlan` / `PlannedOperation` / `OperationJournal`，记录目标、数据库地址、账号、格式、执行/复核/恢复状态与时间；不记录口令、校验值或语句原文。
- **错误**：只按封闭错误码映射中文原因，不回传服务端错误正文。
- **生命周期**：所有网络连接由 SSH actor 持有（`direct-tcpip`），沿用现有排队、取消、目标代次检查（100 ms）。取消只关闭通道，界面说明服务端事务可能仍在回滚或已提交，需刷新确认状态；执行阶段一旦发送提交即不允许取消。

## PostgreSQL（第一期）

### 语句与格式

- 写连接与只读检查分开：去掉 `default_transaction_read_only`，保留 `statement_timeout=20000`、`lock_timeout=3000`、`idle_in_transaction_session_timeout=5000`、`search_path=pg_catalog`，`application_name = LovelyHawk password change`。不修改 `log_statement` 等审计相关设置。
- 只发送客户端计算的校验值，不发送明文：服务端 `password_encryption = scram-sha-256` 时用 `postgres_protocol::password::scram_sha_256` 生成 SCRAM 校验值；为 `md5` 时生成 `md5` 校验值以保持现有客户端兼容，并在确认中说明 md5 偏弱、迁移需单独处理。语句日志里只会出现校验值；校验值仍可被离线猜测，确认说明中提示日志访问控制。
- PostgreSQL 10 以下拒绝（不支持预计算 SCRAM）。`postgres-protocol` 已在锁文件中（0.6.12，`tokio-postgres` 的依赖），作为 workspace 直接依赖固定到同一版本，不引入新包。
- 执行事务：`BEGIN` → 按 OID 读取 `rolname, rolcanlogin`，与计划比较 → 连接账号为超级用户时读取 `pg_authid.rolpassword`（旧校验值，可为空）→ `ALTER ROLE <quoted> PASSWORD '<verifier>'` → `COMMIT`。权限不足（42501）映射为“当前连接账号无权修改该角色的口令”。
- 恢复：`ALTER ROLE <quoted> PASSWORD '<旧校验值>'`；旧值为空时 `PASSWORD NULL`。

### 账号范围

- 连接账号本身（`current_user`）始终可选。
- 访问诊断角色列表中的其他角色：仅 `rolcanlogin = true` 的角色可选；不能登录的角色拒绝（设置口令没有作用）。修改他人口令需要超级用户，或 PostgreSQL 16 起对该角色有 ADMIN 选项、旧版本为 CREATEROLE；计划阶段只提示，最终由数据库判定。超级用户角色只能由超级用户修改。

## MySQL / MariaDB（第二期）

### 原生连接

- 新增 core `mysql_wire.rs`：经 SSH `direct-tcpip` 的最小客户端，不调用目标或本机的 mysql 客户端。HandshakeV10、`CLIENT_PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH | DEPRECATE_EOF`，`COM_QUERY` 文本结果集、OK/ERR 包；帧与总量上限对齐 PostgreSQL 现有 `WireBudget` 规模。
- TLS：默认 SSL 请求后升级为 `native-tls` 并验证证书与主机名（最低 TLS 1.2），可附加一份公开 CA PEM（MySQL 自签证书在数据目录的 `ca.pem`）；与 PostgreSQL 相同的显式“仅 SSH 保护（字面回环 IP）”模式。新增 `DatabaseProfileConfig.mysql_tls`，旧配置可反序列化且序列化不增加空字段。
- 认证插件：`mysql_native_password`、`caching_sha2_password`（快速认证；完整认证只在 TLS 下发送口令，未加密的回环模式下需要完整认证时拒绝并说明“需启用数据库 TLS”，不实现 RSA 公钥交换）。`mysql_clear_password`、`client_ed25519`、`auth_socket`/`unix_socket` 等拒绝并说明。依赖均已在锁文件中（`sha1`、`sha2`、`native-tls`、`tokio-native-tls`），不新增包。
- 身份：`SELECT VERSION(), @@version_comment` 区分 MySQL 与 MariaDB 及版本；首期适配 MySQL 8.0 / 8.4 与 MariaDB 10.11 / 11.x，其他版本拒绝写入。

### 账号列表与语句

- 列表：`mysql.user` 的 `user, host, plugin, account_locked, password_expired`（MariaDB 用其兼容视图列）；无读取权限时只提供 `CURRENT_USER()`。
- 修改保持原认证插件不变，`unix_socket`/`auth_socket` 等无口令插件拒绝。
  - `mysql_native_password`：客户端计算 `*` + `HEX(SHA1(SHA1(口令)))`，MySQL 用 `ALTER USER 'u'@'h' IDENTIFIED WITH mysql_native_password AS '*…'`，MariaDB 用 `ALTER USER 'u'@'h' IDENTIFIED VIA mysql_native_password USING '*…'`，不发送明文。
  - `caching_sha2_password` / `sha256_password`：只能 `IDENTIFIED BY '<明文>'`，只在 TLS 或 SSH 回环模式下发送；依赖服务端对 general/slow log 与 binlog 的口令改写，此前提必须在实验环境实测后才能宣称；`--log-raw` 开启时（`@@log_raw = ON`）拒绝。
  - 连接账号改自己且服务端要求当前口令（`password_require_current`）时附带 `REPLACE '<已存口令>'`；未保存口令时拒绝并说明。
  - `validate_password` 拒绝（1819）映射为“新口令不符合数据库的口令策略”。
- 恢复：连接账号可读 `mysql.user` 时，执行前在同一连接 `SET SESSION print_identified_with_as_hex = ON`（MySQL 8.0.17+）后读取 `SHOW CREATE USER`，只严格解析插件名与认证串；恢复用 `IDENTIFIED WITH <plugin> AS <hex>`（MariaDB `IDENTIFIED VIA … USING`）。解析不了即视为不可恢复。
- 复核：账号 host 部分为 `%`，或与当前连接路径可匹配（`localhost`/`127.0.0.1`/`::1` 对应回环模式）时复核登录；否则标为“无法从当前连接路径复核”，并说明原因。

### 桌面

- 新增 MySQL 连接配置管理（列表/编辑/保存/删除，与 PostgreSQL 相同的版本比较写入与删除计划）、账号列表读取与口令修改，后端 `mysql_runtime_api.rs`，shared `mysql-runtime-contract.ts`；数据库页按产品切换 PostgreSQL 与 MySQL/MariaDB。

## 接线（两期一致）

core → backend 方法 → shared DTO 校验 → 宿主 `backend_bridge.rs` 白名单 → `ui/src/host` 桥 → 页面。PostgreSQL 的动作并入现有 `postgresql.runtime` 方法（复用绑定、连接配置句柄与读取任务）：`plan-password`、`execute-password`、`plan-password-restore`、`execute-password-restore`。页面入口：角色面板每个可登录角色行的“修改口令”，连接配置上的“修改此账号的口令”；确认用 `DialogHost` 受控操作对话框；脏输入（已填新口令）参与导航与关闭握手；执行中锁定数据库页的其他写入与读取。

## 测试与验收

- core 单元测试（duplex 伪服务端）：语句只含校验值不含明文；标识符转义（含引号、反斜杠、Unicode）；计划字段任一变化拒绝；复核三类结果；恢复只在捕获旧值后可用且只一次；权限错误映射；口令规则；DTO/日志/操作日志中不出现口令与校验值（canary）。
- backend 拒绝测试：多余字段、超长口令、旧计划句柄、重复执行、跨绑定句柄、到期计划。
- 实验室（只在本次 UUID 标签的一次性容器中执行写入）：PostgreSQL 16（scram 与 md5 两种 `password_encryption`、超级用户与非超级用户连接）、MySQL 8.0、MariaDB 11（`lab-base` 服务镜像）；核对执行后新旧口令登录结果、目录回读、日志中无明文（开启 `log_statement=all` / general log），恢复后旧口令可登录。
- 桌面 CDP：计划 → 确认（焦点默认在取消）→ 执行 → 复核结果 → 可恢复时恢复；断连、切换目标、计划到期、重复点击均不执行第二次。

## 未覆盖

其他数据库（Redis ACL、MongoDB、openGauss、达梦、人大金仓等）、口令到期/锁定策略修改、批量修改、生成随机口令、MariaDB ed25519 与 MySQL RSA 公钥交换、复制拓扑中的从库同步核对，均不在本设计内。
