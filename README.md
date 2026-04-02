# First

> 微信小程序调试工具 —— 基于 Frida + CDP 代理，支持 GUI 与 CLI 双模式

---

## 截图预览

### 主界面 / Control Panel
![QQ20260402-192426](https://s1.galgame.fun/imgb/u0/20260402_69ce51f6c6f60.png)

### 路由导航
![微信图片_2026-04-02_192531_552](https://s1.galgame.fun/imgb/u0/20260402_69ce523e8b90d.png)

### 云函数分析
![QQ20260402-192623](https://s1.galgame.fun/imgb/u0/20260402_69ce527ca5480.png)

### 安全扫描
待优化

---

## 功能特性

- 通过 Frida 注入微信客户端，转发小程序调试协议
- CDP 代理桥接，支持 Chrome DevTools 直接连接调试
- 路由枚举与一键跳转导航
- 云函数调用监控与参数分析
- UserScript 自动注入（支持按 URL 匹配、run-at 时机控制）
- 内置安全扫描模块，生成扫描报告
- 深色 / 浅色主题切换
- GUI（PySide6）与 CLI 双模式运行

---

## 环境要求

| 依赖 | 版本 |
|------|------|
| Python | >= 3.9 |
| frida | >= 17.0.0 |
| websockets | >= 12.0 |
| protobuf | >= 4.0.0 |
| PySide6 | >= 6.5.0 |

安装依赖：

```bash
pip install -r requirements.txt
```

---

## 使用方法

### GUI 模式（推荐）

```bash
python gui.py
```

启动后在主界面点击 **Start** 即可开始调试。

### CLI 模式

```bash
# 默认端口启动
python main.py

# 自定义端口
python main.py --debug-port 9421 --cdp-port 62000

# 开启详细日志
python main.py --debug-main --debug-frida
```

### 连接 Chrome DevTools

启动后，在 Chrome 地址栏输入：

```
devtools://devtools/bundled/inspector.html?ws=127.0.0.1:62000
```

### 参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--debug-port` | `9421` | 远程调试服务端口 |
| `--cdp-port` | `62000` | CDP 代理监听端口 |
| `--debug-main` | 关闭 | 输出主进程调试日志 |
| `--debug-frida` | 关闭 | 输出 Frida 客户端日志 |
| `--scripts-dir` | `./userscripts` | UserScript 目录路径 |
| `--script` | — | 指定单个 .js 文件注入（可多次使用） |

### UserScript 注入

将 `.js` 脚本放入 `userscripts/` 目录，工具启动时自动加载并按规则注入。

也可手动指定文件：

```bash
python main.py --script ./my_hook.js --script ./another.js
```

---

## 打包为可执行文件

```bash
pyinstaller WMPFDebugger.spec
```

---

## 参考项目

本项目参考并学习了以下优秀工具的实现思路：

- [evi0s/WMPFDebugger](https://github.com/evi0s/WMPFDebugger)

---

## 致谢

感谢 **0xsdeo** 师傅的大力支持与思路提供。

---

## 免责声明

本工具仅供安全研究与学习使用，请勿用于未授权的目标，使用者须自行承担相关法律责任。
