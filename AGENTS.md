# 仓库约定（给 AI 协作与本仓库维护者）

## 每一轮修改都要发版 —— 这是本项目的固定要求

改完一轮代码不能停在 `git push master`：**必须打新 tag、推代码、推 tag**，让这一轮
变更落成一个 GitHub Release（`.github/workflows/release.yaml` 只在 tag 上建 Release）。

流程：

1. **等 master 的 CI 全绿再打 tag**。tag 触发的流水线会把构建、单测、两个架构的
   tar.gz 与 .deb 打包再跑一遍，任何一步红了都不会有 Release。
2. **版本号接着上一轮递增**：`0.25.7-cong.N`。当前用到几，看 `git tag --list '0.25.7*'`。
3. **用附注 tag，消息写清这一轮的变更**（仓库风格：正文条目形如
   `* NEW [范围] …` / `* FIX [范围] …`，说清"为什么"而不只是"改了什么"）：

   ```sh
   git tag -a 0.25.7-cong.N -F <消息文件>
   git push origin master
   git push origin 0.25.7-cong.N
   ```

4. **推完确认 Release 资产齐全**（每个架构的 tar.gz + .deb + 各自 .sha256，共 8 个）：

   ```sh
   gh release view 0.25.7-cong.N --json assets --jq '.assets[].name'
   ```

5. **tag 指向的 commit 本身有问题时**（打包失败、CI 红），修好后把 tag 移到修好的
   commit 再强推：`git tag -f -a …` + `git push --force origin 0.25.7-cong.N`。
   前提是这次 tag **还没有成功产出过 Release**（Release job 被 skip 或失败），
   并在汇报里说明 tag 被移动过。

## 其他

- 提交消息沿用仓库风格：`* NEW/FIX/DOCS/MDF [范围] 简述` + 正文讲清动机与验证方式。
- `nng/` 是 submodule，改动只能走 `cong/patch/*.patch` 构建期打入；本地工作树里
  打了补丁会让 `git status` 显示 `m nng`，不要把 submodule 指针提交进去。
- 发布产物（tar.gz 与 .deb）里的二进制必须来自同一个构建 job，不要手工上传本地编译
  的二进制——`.github/workflows/release.yaml` 负责这件事。
