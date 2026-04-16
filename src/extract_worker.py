"""
extract_worker.py — 独立子进程 worker
由 GUI 通过 subprocess 启动，避免阻塞主 UI

支持两种模式:
  1. decompile  —— 解密解包单个小程序
  2. scan       —— 扫描已解包目录的敏感信息

通信协议 (stdout JSON lines):
    {"type": "progress", "done": N, "total": N}
    {"type": "log", "msg": "..."}
    {"type": "result", "data": {...}}
    {"type": "error", "msg": "..."}

命令行:
    python extract_worker.py decompile --packages-dir DIR --appid APPID --output-dir DIR
    python extract_worker.py scan --scan-dir DIR --output-dir DIR [--custom-patterns JSON_FILE]
"""
import json
import os
import sys
import traceback


def _init_stdout():
    """Windows 下强制 stdout 使用 UTF-8，避免 GBK 编码错误"""
    if sys.platform == "win32":
        import io
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace"
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer, encoding="utf-8", errors="replace"
        )


def _emit(obj):
    """输出一行 JSON 到 stdout"""
    print(json.dumps(obj, ensure_ascii=False), flush=True)


def do_decompile(args):
    """解密解包单个小程序"""
    src_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(src_dir)
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)

    from src.wxapkg import find_wxapkg_files, extract_wxapkg

    packages_dir = args.packages_dir
    appid = args.appid
    output_dir = args.output_dir

    os.makedirs(output_dir, exist_ok=True)

    _emit({"type": "log", "msg": f"正在查找 {appid} 的 wxapkg 文件..."})

    # 查找该 appid 的包
    all_pkgs = find_wxapkg_files(packages_dir)
    pkgs = [p for p in all_pkgs if p["appid"] == appid]

    if not pkgs:
        _emit({"type": "log", "msg": f"未找到 {appid} 的 wxapkg 文件"})
        _emit({"type": "result", "data": {"appid": appid, "files": 0, "extracted": 0}})
        return

    _emit({"type": "log", "msg": f"发现 {len(pkgs)} 个 wxapkg 文件"})

    decompile_dir = os.path.join(output_dir, "decompiled")
    os.makedirs(decompile_dir, exist_ok=True)

    total = len(pkgs)
    extracted_total = 0

    for i, pkg in enumerate(pkgs, 1):
        try:
            files = extract_wxapkg(pkg["path"], decompile_dir, appid)
            extracted_total += len(files)
            _emit({"type": "log", "msg": f"  解包 {pkg['name']}: {len(files)} 个文件"})
        except Exception as e:
            _emit({"type": "log", "msg": f"  解包失败 {pkg['name']}: {e}"})
        _emit({"type": "progress", "done": i, "total": total})

    _emit({"type": "result", "data": {
        "appid": appid,
        "files": total,
        "extracted": extracted_total,
        "decompile_dir": decompile_dir,
    }})
    _emit({"type": "log", "msg": f"反编译完成! 共提取 {extracted_total} 个文件"})


def do_scan(args):
    """扫描已解包的目录"""
    src_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(src_dir)
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)

    from src.extractor import Extractor

    scan_dir = args.scan_dir
    output_dir = args.output_dir

    os.makedirs(output_dir, exist_ok=True)

    extractor = Extractor()

    # 加载自定义正则
    if args.custom_patterns and os.path.isfile(args.custom_patterns):
        try:
            with open(args.custom_patterns, "r", encoding="utf-8") as f:
                custom = json.load(f)
            loaded = 0
            for name, info in custom.items():
                # 兼容新格式 {"regex": str, "enabled": bool} 和旧格式 str
                if isinstance(info, dict):
                    if not info.get("enabled", True):
                        continue
                    pat = info.get("regex", "")
                else:
                    pat = info
                if pat:
                    extractor.add_custom_pattern(name, pat)
                    loaded += 1
            _emit({"type": "log", "msg": f"已加载 {loaded} 个自定义正则"})
        except Exception as e:
            _emit({"type": "log", "msg": f"加载自定义正则失败: {e}"})

    _emit({"type": "log", "msg": f"正在扫描目录: {scan_dir}"})

    def on_progress(done, total):
        _emit({"type": "progress", "done": done, "total": total})

    scan_result = extractor.scan_directory(scan_dir, on_progress=on_progress)

    # 导出
    result_dir = output_dir
    html_path = os.path.join(result_dir, "report.html")
    json_path = os.path.join(result_dir, "report.json")
    Extractor.export_html(scan_result, html_path)
    Extractor.export_json(scan_result, json_path)

    summary = Extractor.get_summary(scan_result)
    total_findings = sum(summary.values())

    _emit({"type": "result", "data": {
        "files_scanned": scan_result.get("files_scanned", 0),
        "elapsed": scan_result.get("elapsed", 0),
        "findings": total_findings,
        "summary": summary,
        "html_path": html_path,
        "json_path": json_path,
        "result_dir": result_dir,
    }})
    _emit({"type": "log", "msg": f"扫描完成! 发现 {total_findings} 条敏感信息，耗时 {scan_result.get('elapsed', 0)}s"})


def main():
    import argparse
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    # decompile 子命令
    p_dec = subparsers.add_parser("decompile")
    p_dec.add_argument("--packages-dir", required=True)
    p_dec.add_argument("--appid", required=True)
    p_dec.add_argument("--output-dir", required=True)

    # scan 子命令
    p_scan = subparsers.add_parser("scan")
    p_scan.add_argument("--scan-dir", required=True)
    p_scan.add_argument("--output-dir", required=True)
    p_scan.add_argument("--custom-patterns", default="")

    args = parser.parse_args()

    if args.command == "decompile":
        do_decompile(args)
    elif args.command == "scan":
        do_scan(args)
    else:
        _emit({"type": "error", "msg": "未知命令，使用 decompile 或 scan"})
        sys.exit(1)


if __name__ == "__main__":
    _init_stdout()
    try:
        main()
    except Exception as e:
        _emit({"type": "error", "msg": f"worker 异常: {traceback.format_exc()}"})
        sys.exit(1)
