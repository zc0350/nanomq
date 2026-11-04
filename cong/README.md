# cong-nanomq：NanoMQ 的 JSONL 登录 + ACL 插件

`cong/` 是一套进程内 MQTT 登录认证与主题授权方案：规则写在两份 JSONL 文件里
（`rules/auth.jsonl` 登录、`rules/acl.jsonl` 授权），由一个 dlopen 进 broker 的
`.so`（`cong_nanomq.so`）执行。规则引擎是 `src/core/` 下五个与 broker 无关的
翻译单元，摘要登录支持多因子 scheme（salt / username / clientid 及其正则捕获
组的任意拼接）、逐段清洗与四种摘要算法；ACL 支持 allow/deny、发布与订阅两个
方向的覆盖判定、`%c/%u/%1..%9` 主题模板与 IPv4/IPv6 CIDR。

规则文件本身的注释就是最完整的使用说明（装载期校验、模板记号、命中顺序、
反例），`tools/cong_pwgen.py` 可生成设备口令并离线校验规则文件能否被 C 侧装载。

## 目录

```
cong/
  src/core/           规则引擎：cong_util / cong_digest / cong_auth / cong_acl / cong_topic
  src/cong_nanomq.c   NanoMQ 侧 hook 适配层（.so 入口 nano_plugin_init）
  include/cjson/      转发头，指向 nng 自带的 cJSON
  rules/              示例规则（生产上请替换成自己的）
  tools/cong_pwgen.py 口令派生 + 规则文件校验（stdlib-only）
  test/test_core.c    规则引擎单测（不需要 broker）
  conf/nanomq.conf    带 plugin 块的 broker 配置样例
  deploy/nanomq.service  systemd 单元
  patch/01-nng-connect-hook.patch  NanoNNG 的 CONNECT 钩子补丁（构建期打）
```

## 接线方式（为什么有补丁）

NanoMQ 0.25.x 的 CONNECT 口令校验在 NanoNNG 协议栈内部（`nano_pipe_start()` →
`verify_connect()`），pub/sub 只有原生 ACL 文件一条路。本仓库的接线分三块：

1. **nng 侧（`cong/patch/01-nng-connect-hook.patch`，构建期打）**：给协议栈加一个
   `nano_connect_auth_set()` 函数指针 seam，`nano_pipe_start()` 在有钩子时用它
   取代 `verify_connect()`。nng 是 git submodule，所以这个补丁只能构建时应用
   （CI 与 `cong/patch/` 都先 `git apply --check` 再打）。
2. **nanomq 侧（已原生提交）**：`nanomq/include/plugin.h` 增加
   `HOOK_BASIC_AUTH / HOOK_ACL_CHECK / HOOK_RELOAD` 三个 hook 点；`plugin_hooks.c`
   在插件认领时把 CONNECT 决策交给插件（没人认领时内置校验照旧，见下文
   fail-closed 第 5 条）；`handle_pub()/sub_ctx_handle()` 在 mount-point 重写之后
   先问插件再走原生 ACL；插件加载挪到 broker() 顶部、第一个 listener 打开之前，
   失败 `NANO_NNG_FATAL` 直接下线。
3. **插件（`cong/src/`）**：注册三个 hook，读写两份规则表，rwlock 保护 reload。

`.so` 不链 libnng：`plugin_hook_register` 由宿主进程提供（nanomq 目标以
`ENABLE_EXPORTS` + `-rdynamic` 导出符号表，见 `nanomq/CMakeLists.txt`）。cJSON
用 nng 自带那份编进 `.so` 并加 `-Wl,-Bsymbolic`，宿主与插件不会混用两个版本。

## 构建

依赖：cmake ≥ 3.13、gcc/clang、libssl-dev（OpenSSL EVP）、git（拉 submodule 与
打补丁）。Windows 只能当开发机：插件框架在 WIN32 下 CMake 直接 FATAL_ERROR。

```sh
git submodule update --init --recursive
# nng 是 submodule，补丁在构建前打入（CI 同样这样做）
git -C nng apply --check  cong/patch/01-nng-connect-hook.patch
git -C nng apply          cong/patch/01-nng-connect-hook.patch

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
      -DENABLE_PLUGIN=ON -DENABLE_ACL=ON -DNNG_ENABLE_TLS=ON \
      -DBUILD_CLIENT=OFF -DBUILD_NANOMQ_CLI=OFF -DBUILD_BENCH=OFF
cmake --build build -j

ctest --test-dir build -R cong_core_test     # 规则引擎单测，必须全过
nm -u build/cong/cong_nanomq.so | grep -c plugin_hook_register   # 宿主符号应恰好 1 个
python3 cong/tools/cong_pwgen.py validate cong/rules/auth.jsonl cong/rules/acl.jsonl
```

`cmake --install` 会装：`cong_nanomq.so` → `lib/`，`conf/nanomq.conf` 与
`rules/*.jsonl` → `etc/nanomq/`，systemd 单元 → `share/cong-nanomq/`。

## 配置

插件框架不给插件传选项，规则路径只走环境变量（`nano_plugin_init()` 读一次，
改路径要重启）：

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `CONG_AUTH_FILE` | `/etc/nanomq/cong_auth.jsonl` | 登录规则 |
| `CONG_ACL_FILE` | `/etc/nanomq/cong_acl.jsonl` | ACL 规则 |
| `CONG_DEBUG` | 未设 | 设了才打印「放行」的判定（每条一行，别在生产常开） |

`conf/nanomq.conf` 的要点（样例已按此写好）：

- `plugin { libs = [{ path = ".../cong_nanomq.so" }] }`——路径要与安装位置对上；
  插件装载失败 broker 会直接下线。
- 不写 `auth.acl = {...}`、不写 `auth.password = {...}`：登录与主题授权只由
  JSONL 决定，避免同一份消息被判两次。
- `allow_anonymous = false`：有插件认领 `HOOK_BASIC_AUTH` 时它不参与判定，但没有
  插件认领时它重新生效（见 fail-closed 第 5 条），所以这行不是装饰。
- `deny_action = ignore | disconnect`：**插件的拒绝也按它处理**（断连时发布侧回
  `BANNED`，订阅侧不发 SUBACK）。
- `log.to` 选 `console` 时插件日志（stderr）与 broker 日志同流，journald 收拢在一起。

## fail closed 的五个层次

1. 规则文件读不进来 → broker 起不来（`plugin_register` 失败 `NANO_NNG_FATAL`，
   且加载发生在第一个 listener 之前，不存在「先用内置口令服务一会儿」的窗口）。
2. hook 先注册、规则后加载：装载失败时表为 `NULL`，core 对 `NULL` 表判定为
   `CONG_NO_MATCH` ⇒ 拒绝一切，而不是放行。
3. reload 读到坏文件 → 保持上一份好规则（两份新表都装成功才换，日志
   `reload FAILED for ...`）。改错一个字符不会让 broker 下线，也不会放宽权限。
4. 未知字段、同一行重复键、坏的 `%uN/%cN/%1..%9` 引用 → 整个文件拒绝加载
   （core 层；重复键会破坏「校验器与插件读同一条规则」，Python json 取最后、
   cJSON 取第一个）。
5. CONNECT seam 只在有人认领 `HOOK_BASIC_AUTH` 时才装：`plugin_hook_call()` 对
   未注册的 hook 返回 0（=接受），所以装 seam 前先问 `plugin_hook_has()`；没有
   插件认领时内置 `allow_anonymous`、空凭据拒绝与 `auth.password` 照旧当家。
   两种日志都有话：`a plugin owns CONNECT authentication ...` /
   `no plugin owns CONNECT authentication ...`。

装载成功后 core 还会扫一遍 ACL 表：对「不指名任何 client/地址/主题却 allow」的
兜底行打 NOTICE（示例 `rules/acl.jsonl` 最后一行正是这个形状，生产文件应以 deny 收尾）。

## 改完规则怎么生效

```sh
sudo nanomq reload --conf /etc/nanomq/nanomq.conf
```

SIGHUP 不管用（NanoMQ 收 SIGHUP 只重开日志）。`nanomq reload` 在刷新 broker
自己的表之后广播 `HOOK_RELOAD`，插件随即重读两份规则。前提：**不要开
`PrivateTmp=true`**（CLI 靠 `ipc:///tmp/nanomq_cmd.ipc` 找 broker），且 pid 目录
要先建好（unit 里有 `ExecStartPre=/bin/mkdir -p /tmp/nanomq`）。

## NanoMQ 侧的已知差异与限制

- **IPv4-only 的 `ip` 规则**：协议栈只在 `AF_INET` 时填客户端地址，IPv6 连接拿到
  空串 ⇒ 带 `ip` 约束的规则对 IPv6 永不命中（拒绝方向，安全但要知道）。
- **证书登录**：`peer_cert_as_username` 换出的用户名会跳过登录 hook（身份已由
  TLS 验证），但仍受 ACL hook 约束。
- **共享订阅**：hook 拿到的是原样 filter（含 `$share/组/主题`），规则要用
  `{"eq":"$share/..."}` 或以 `$` 开头的显式模式才可能命中。
- **没有 UNSUBSCRIBE 点位**（原生框架没有，补丁也不造）；订阅/发布是全局一张表，
  不分 listener。
- `$SYS` 的 birth/kill 是 broker 内部事件，`is_event` 跳过 ACL hook，不会被
  自己的规则挡住。
- 匹配比原生 `topic_filter()` 严：发布主题带 `+`/`#` 按拒绝处理，订阅按「覆盖」
  判定（`sensor/+` 不授权 `sensor/#`），畸形通配符（`a/+b`）也是拒绝。

## 升级 NanoMQ 时要重新验的东西

补丁/hook 语义按 0.25.x 的代码结构接线，升版本至少复看：

1. nng `nmq_mqtt.c` 的 `auth_verify:` 附近——seam 调用点与
   `nano_pipe_peer_cert_as_username()` 的先后。
2. `handle_pub()` / `sub_ctx_handle()` 里 mount-point 重写与插件 hook 的先后
   （hook 必须问在**重写之后**的主题上）。
3. `plugin.c` 的 `plugin_hook_call()` 未注册时是否仍返回 0（改成非 0 = 全拒）。
4. `conf_ver2.c` 的 `auth { no_match / deny_action }` 是否仍在 `#ifdef ACL_SUPP` 下。
5. `ENABLE_EXPORTS/-rdynamic` 是否仍必要（若 nanomq 改为显式导出表则换 version
   script）；nng vendored cJSON 是否变版本（变了要重编插件）。

## 上机要做的第一件事

```sh
# 1. 正确摘要应放行（rules/auth.jsonl 第一条：sha256(salt + "dashboard")）
export CONG_DEBUG=1
nanomq start --conf /etc/nanomq/nanomq.conf &
mqttcli pub -h 127.0.0.1 -u dashboard -P <pwgen 算出的口令> -t "$SYS/broker/uptime" -m hi
# 2. 错口令应被拒（CONNACK 失败，日志 "matches no rule" 或 "password digest does not"）
# 3. %1 模板：abcde_aaaa 只能发 abcde/aaaa/event，发 abcde/bbbb/event 应被拒
# 4. $SYS：非 dashboard、非 127.0.0.1 的连接订阅 "$SYS/#" 应被拒
# 5. reload：改规则后 nanomq reload 立即生效；把文件改坏再 reload，旧规则应继续生效
# 6. seam 回归：注释掉 plugin.libs 重启，日志应出现 "no plugin owns CONNECT
#    authentication ..."，此时 allow_anonymous=false 要能拒匿名连接
```

口令生成：

```sh
python3 cong/tools/cong_pwgen.py digest --username pump_0007 --clientid PUMP-0007 \
        --salt pl4nt --alg sha256 --scheme username+clientid+salt
```
