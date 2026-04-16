# First

> 微信小程序调试工具 —— 基于 Frida + CDP 代理，支持 GUI 与 CLI 双模式
---
本项目仅支持windows，macos用户使用pd虚拟机即可
## 截图预览

### 主界面 / Control Panel

![zhuyem](https://s1.galgame.fun/imgb/u0/20260408_69d655f49ca7e.png)

### 路由导航
![luyou](https://s1.galgame.fun/imgb/u0/20260408_69d6560ca1a39.png)

### 云函数分析
![QQ20260402-192623](https://s1.galgame.fun/imgb/u0/20260402_69ce527ca5480.png)

### 调试开关(JSRPC 与调用 wx.cloud)
![调试](https://s1.galgame.fun/imgb/u0/20260408_69d6564195009.png)

### 敏感信息提取

![PixPin_2026-04-16_18-45-08](https://s1.galgame.fun/imgb/u55/20260416_69e0be0e1c1d7.png)

<img src="https://s1.galgame.fun/imgb/u55/20260416_69e0be0c38e39.png" alt="PixPin_2026-04-16_18-45-59" />

![PixPin_2026-04-16_18-45-52](https://s1.galgame.fun/imgb/u55/20260416_69e0be0c70d46.png)

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
| Python | >= 3.10 |
| frida | >= 17.0.0 |
| websockets | >= 12.0 |
| protobuf | >= 4.0.0 |
| PySide6 | >= 6.5.0 |

安装依赖：

```bash
pip install -r requirements.txt
```

---

## 微信版本要求

- WMPF版本支持列表:11581, 11633, 13331, 13341, 13487, 13639, 13655, 13871, 13909, 14161, 14199, 14315, 16133, 16203, 16389, 16467, 16771,
   16815, 16965, 17037, 17071, 17127, 18055, 18151, 18787, 18891, 18955, 19027, 19201  
- 推荐微信版本为4.1.0.30
- 下载地址[weixin/4.1.0.30](https://github.com/vs-olitus/wx-version/releases/tag/4.1.0.30)

## 使用方法

### GUI 模式（推荐）

```bash
python gui.py
```
双击启动.bat
启动后在主界面点击 **启动调试** 即可开始调试。

### 小程序页面操作

点击启动调试前请勿打开小程序, **启动调试**打开后再次启动**小程序**即可。

### CLI 模式

```bash
# 默认端口启动
python main.py

# 自定义端口
python main.py --cdp-port 62000

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

## 常见问题解决办法

1. Frida 已显示连接，但小程序端显示未连接或无法断点调试

若操作顺序无误，建议先彻底卸载微信并重启电脑（如有重要聊天记录请提前备份）。
删除路径C:\Users\用户名\AppData\Roaming\Tencent\xwechat\XPlugin\Plugins\RadiumWMPF下所有以数字命名的文件夹，再次重启电脑后，安装微信 4.1.0.30 版本。安装完成后检查上述路径，确认文件夹编号为 16389。

## 参考项目

本项目参考并学习了以下优秀工具的实现思路：

- [evi0s/WMPFDebugger](https://github.com/evi0s/WMPFDebugger)
- [0xsdeo/HeartK](https://github.com/0xsdeo/HeartK)
- [残笑/FindSomething](https://github.com/momosecurity/FindSomething)
- [进击的HACK/JSRPC与调用wx.cloud](https://mp.weixin.qq.com/s/hTlekrCPiMJCvsHYx7CAxw)
---

## 致谢

感谢 **0xsdeo** 师傅的大力支持与思路提供。

---
## 交流群
群满200变成手动挡了。加我拉
![1db5b1b2699ae709a191207cf97dcf4b](https://s1.galgame.fun/imgb/u55/20260413_69dcaf1310fc4.jpg)

## 免责声明

本工具仅供安全研究与学习使用，请勿用于未授权的目标，使用者须自行承担相关法律责任。
