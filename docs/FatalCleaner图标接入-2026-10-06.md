# FatalCleaner 图标接入

2026-10-06，接入用户提供的硬盘与扫帚图标。

## 资源和接入

- 原稿：[FatalCleaner.png](../src/CleanSweep.App/Assets/FatalCleaner.png)，与用户 Downloads 中的源文件逐字节一致，保留白底、留白和造型。
- Windows 图标：[FatalCleaner.ico](../src/CleanSweep.App/Assets/FatalCleaner.ico)，含 16、24、32、48、64、128、256 像素的 32 位 PNG 帧。
- 通过 [tools/build-icon.ps1](../tools/build-icon.ps1) 从原稿重新生成 ICO，只做等比例尺寸转换和封装。
- App 项目 ApplicationIcon 嵌入 EXE；PNG 和 ICO 作为 WPF Resource，主窗口及侧栏通过程序集资源地址引用，不依赖 Downloads。
- Inno Setup 配置 SetupIconFile；现有安装脚本的快捷方式和卸载图标指向 EXE，使用其中嵌入的图标。

## 验证

Release App 构建成功，UiLayoutTests 6 项通过，覆盖 960×600、1240×800 窗口及嵌入资源加载。已从构建后的 EXE 提取图标确认资源嵌入，并检查界面预览。

证据：`artifacts/verification/brand-icon-2026-10-06/`，含 TRX、`exe-icon.png` 和 screenshots。原图 SHA-256：`b45aaec893084d099429dddee282dd10130c7e4113274ba8aef20e3f2a6a5cf3`。

本轮没有重跑完整 669 项测试；此前完整结果见 GitHub 仓库更名记录。未执行真实安装、Inno Setup 编译或发布。保留原图导致小尺寸主体偏小、中心细节收缩，未进行重绘或透明化处理。


## 后续现场反馈：本地入口仍为旧包

用户反馈未看到新图标。检查确认之前只构建了 Release 开发输出，Debug 为旧构建，`publish/win-x64` 仍是 10 月 2 日的 CleanSweep 包。检查时没有运行中的 CleanSweep/FatalCleaner 进程，也没有在常见桌面、开始菜单和任务栏目录发现同名快捷方式；用户实际查看位置尚未确认，不能认定为图标缓存问题。

已补齐 Debug 构建、自包含 win-x64 包，提取新 EXE 图标确认包含用户图案。统一 Release 和包检查通过：Core 545 + App 124 = 669 项通过，零警告/错误，包内安装清单、必要二进制、版本和数据验签通过。

经过验证的新包已放回 `publish/win-x64`。旧目录完整保留在 `publish/win-x64-before-icon-20261006-231607`。可运行 `publish/win-x64/CleanSweep.exe` 查看，内部文件名继续兼容旧更新器。未运行软件、改动已安装副本或上传 GitHub Release。

证据 `artifacts/verification/icon-local-package-2026-10-06/`：包含新旧 EXE 提取图标、TRX、summary.json 及 local-deployment.json。公开版本仍为 v0.22.0，当前本地包是包含未提交代码的开发构建，不是公开版本原始包。
