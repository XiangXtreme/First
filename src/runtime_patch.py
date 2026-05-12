import json
import os
import re
from collections import Counter


TEXT_EXTS = (".js", ".html", ".htm", ".wxml", ".json")


def build_runtime_patch(appid: str, decompile_dir: str, output_base: str) -> dict:
    manifest_path = os.path.join(output_base, appid, "manifest.json")
    if not os.path.isfile(manifest_path):
        return {"pairs": []}
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception:
        return {"pairs": []}

    pairs = []
    api_pairs = []
    page_methods = []
    for pkg in manifest.get("packages", []):
        source_path = pkg.get("path")
        if not source_path or not os.path.isfile(source_path):
            continue
        try:
            from src.wxapkg import decrypt_wxapkg, unpack_wxapkg
            with open(source_path, "rb") as f:
                raw = f.read()
            original_files = dict(unpack_wxapkg(decrypt_wxapkg(raw, appid)))
        except Exception:
            continue
        for item in pkg.get("files", []):
            rel = item.get("path", "")
            if not rel.lower().endswith(TEXT_EXTS):
                continue
            package_path = item.get("package_path") or ("/" + rel.replace("\\", "/"))
            disk_path = os.path.join(decompile_dir, rel)
            if not os.path.isfile(disk_path):
                continue
            try:
                old = original_files.get(package_path)
                if old is None:
                    old = original_files.get(package_path.lstrip("/"))
                if old is None:
                    continue
                old_text = old.decode("utf-8", errors="replace")
                with open(disk_path, "r", encoding="utf-8-sig", errors="replace") as f:
                    new_text = f.read()
                pairs.extend(extract_literal_replacements(old_text, new_text))
                if rel.lower().endswith((".js", ".wxs")):
                    api_pairs.extend(extract_api_string_replacements(old_text, new_text))
                    page_methods.extend(extract_page_method_patches(old_text, new_text))
            except Exception:
                continue

    return {
        "pairs": _dedup_pairs(pairs)[:100],
        "api_pairs": _dedup_pairs(api_pairs)[:100],
        "page_methods": _dedup_methods(page_methods)[:50],
    }


def _dedup_pairs(pairs: list) -> list:
    dedup = []
    seen = set()
    for old, new in pairs:
        key = (old, new)
        if key in seen:
            continue
        seen.add(key)
        dedup.append(key)
    return dedup


def _dedup_methods(methods: list) -> list:
    dedup = []
    seen = set()
    for item in methods:
        key = (item.get("name"), item.get("source"))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(item)
    return dedup


def extract_literal_replacements(old_text: str, new_text: str) -> list:
    if old_text == new_text:
        return []
    pairs = []
    old_set = extract_visible_literals(old_text)
    new_set = extract_visible_literals(new_text)
    removed = sorted(old_set - new_set, key=len, reverse=True)
    added = sorted(new_set - old_set, key=len, reverse=True)
    for old in removed:
        best = None
        old_norm = re.sub(r"\s+", "", old)
        for new in added:
            new_norm = re.sub(r"\s+", "", new)
            prefix = 0
            for a, b in zip(old_norm, new_norm):
                if a != b:
                    break
                prefix += 1
            if prefix >= 2 or old_norm[:2] == new_norm[:2]:
                best = new
                break
        if best and old != best:
            pairs.append((old, best))
    return pairs


def extract_visible_literals(text: str) -> set:
    values = set()
    quote_patterns = [
        r"'((?:\\.|[^'\\])*)'",
        r'"((?:\\.|[^"\\])*)"',
        r"`((?:\\.|[^`\\])*)`",
    ]
    for pattern in quote_patterns:
        for quoted in re.finditer(pattern, text, re.S):
            values.add(_unescape_literal(quoted.group(1)))
    for tag_text in re.finditer(r">([^<]{1,120})<", text):
        values.add(tag_text.group(1))
    return {v for v in (_normalize_visible_literal(v) for v in values) if v}


def extract_api_string_replacements(old_text: str, new_text: str) -> list:
    old_counts = extract_runtime_string_literal_counts(old_text)
    new_counts = extract_runtime_string_literal_counts(new_text)
    removed = []
    added = []
    for value, count in old_counts.items():
        extra = count - new_counts.get(value, 0)
        if extra > 0:
            removed.extend([value] * extra)
    for value, count in new_counts.items():
        extra = count - old_counts.get(value, 0)
        if extra > 0:
            added.extend([value] * extra)
    removed = sorted(removed, key=len, reverse=True)
    added = sorted(added, key=len, reverse=True)
    pairs = []
    for old in removed:
        best = _best_string_replacement(old, added)
        if best and best != old:
            pairs.append((old, best))
            added.remove(best)
    return pairs


def extract_runtime_string_literals(text: str) -> set:
    return set(extract_runtime_string_literal_counts(text))


def extract_runtime_string_literal_counts(text: str) -> Counter:
    values = []
    quote_patterns = [
        r"'((?:\\.|[^'\\])*)'",
        r'"((?:\\.|[^"\\])*)"',
        r"`((?:\\.|[^`\\])*)`",
    ]
    for pattern in quote_patterns:
        for quoted in re.finditer(pattern, text, re.S):
            value = _normalize_runtime_string(_unescape_literal(quoted.group(1)))
            if value:
                values.append(value)
    return Counter(values)


def _normalize_runtime_string(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) < 2 or len(value) > 80:
        return ""
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", value):
        return ""
    if re.search(r"[{}[\];=]|=>|function|require|module|exports|prototype", value):
        return ""
    if not re.search(r"[\u4e00-\u9fffA-Za-z0-9]", value):
        return ""
    return value


def _best_string_replacement(old: str, candidates: list) -> str:
    old_norm = re.sub(r"\s+", "", old)
    best = ""
    best_score = 0
    for new in candidates:
        new_norm = re.sub(r"\s+", "", new)
        prefix = 0
        for a, b in zip(old_norm, new_norm):
            if a != b:
                break
            prefix += 1
        suffix = 0
        for a, b in zip(reversed(old_norm), reversed(new_norm)):
            if a != b:
                break
            suffix += 1
        score = prefix + suffix
        if prefix >= 2 or suffix >= 2 or old_norm[:1].lower() == new_norm[:1].lower():
            if score > best_score:
                best = new
                best_score = score
    return best


def extract_page_method_patches(old_text: str, new_text: str) -> list:
    old_methods = extract_page_methods(old_text)
    new_methods = extract_page_methods(new_text)
    patches = []
    for name, new_method in new_methods.items():
        old_method = old_methods.get(name)
        if not old_method:
            continue
        if _js_compare_key(old_method["source"]) == _js_compare_key(new_method["source"]):
            continue
        if not _method_change_is_significant(old_method["source"], new_method["source"]):
            continue
        patch = {
            "name": name,
            "params": new_method["params"],
            "body": new_method["body"],
            "source": new_method["source"],
        }
        modal_payload = _extract_show_modal_payload(new_method["body"])
        if modal_payload:
            patch["modal_payload"] = modal_payload
        patches.append(patch)
    return patches


def _extract_show_modal_payload(body: str) -> dict:
    match = re.search(r"wx\.showModal\s*\(", body)
    if not match:
        return {}
    obj_start = _skip_ws(body, match.end())
    if obj_start >= len(body) or body[obj_start] != "{":
        return {}
    obj_end = _find_matching(body, obj_start, "{", "}")
    if obj_end < 0:
        return {}
    obj = body[obj_start + 1:obj_end]
    payload = {}
    for key in ("title", "content", "confirmText", "cancelText"):
        m = re.search(
            rf"(?:^|[,{{\s]){key}\s*:\s*(['\"])((?:\\.|(?!\1).)*)\1",
            obj,
            re.S,
        )
        if m:
            payload[key] = _unescape_literal(m.group(2))
    for key in ("showCancel", "editable"):
        m = re.search(rf"(?:^|[,{{\s]){key}\s*:\s*(!0|!1|true|false)\b", obj)
        if m:
            payload[key] = m.group(1) in ("!0", "true")
    return payload


def _method_change_is_significant(old_source: str, new_source: str) -> bool:
    old_key = _js_compare_key(old_source)
    new_key = _js_compare_key(new_source)
    if not old_key or not new_key:
        return False
    old_len = len(old_key)
    new_len = len(new_key)
    ratio = abs(old_len - new_len) / max(old_len, new_len)
    if ratio >= 0.25:
        return True
    calls = [
        "wx.navigateToMiniProgram",
        "wx.showModal",
        "wx.showToast",
        "wx.setClipboardData",
        "wx.getClipboardData",
        "wx.chooseMessageFile",
        "this.setData",
    ]
    old_calls = {call for call in calls if call in old_key}
    new_calls = {call for call in calls if call in new_key}
    return old_calls != new_calls


def _js_compare_key(source: str) -> str:
    out = []
    quote = ""
    escape = False
    line_comment = False
    block_comment = False
    i = 0
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        if not ch.isspace():
            out.append(ch)
        i += 1
    key = "".join(out)
    key = key.replace(";}", "}")
    key = key.replace(";)", ")")
    key = key.rstrip(";")
    return key


def extract_page_methods(text: str) -> dict:
    methods = {}
    page_pos = text.find("Page({")
    if page_pos < 0:
        return methods
    i = page_pos + len("Page({")
    while i < len(text):
        match = re.search(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*function\s*\(", text[i:])
        if not match:
            break
        name = match.group(1)
        fn_start = i + match.start()
        params_start = i + match.end() - 1
        params_end = _find_matching(text, params_start, "(", ")")
        if params_end < 0:
            i = fn_start + 1
            continue
        body_start = _skip_ws(text, params_end + 1)
        if body_start >= len(text) or text[body_start] != "{":
            i = params_end + 1
            continue
        body_end = _find_matching(text, body_start, "{", "}")
        if body_end < 0:
            i = body_start + 1
            continue
        params = text[params_start + 1:params_end].strip()
        body = text[body_start + 1:body_end]
        methods[name] = {
            "params": params,
            "body": body,
            "source": text[fn_start:body_end + 1],
        }
        i = body_end + 1
    return methods


def _skip_ws(text: str, pos: int) -> int:
    while pos < len(text) and text[pos].isspace():
        pos += 1
    return pos


def _find_matching(text: str, start: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    quote = ""
    escape = False
    line_comment = False
    block_comment = False
    i = start
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            continue
        if ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _unescape_literal(value: str) -> str:
    if "\\" not in value:
        return value
    try:
        return bytes(value, "utf-8").decode("unicode_escape")
    except Exception:
        return value


def _normalize_visible_literal(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) < 2 or len(value) > 80:
        return ""
    if not re.search(r"[\u4e00-\u9fff]", value):
        return ""
    if re.search(r"[{}[\];=]|=>|function|require|module|exports|prototype", value):
        return ""
    return value


def build_text_patch_js(pairs: list) -> str:
    pairs_json = json.dumps(pairs, ensure_ascii=False)
    return f"""
(() => {{
  const pairs = {pairs_json};
  try {{
    if (window.__firstRuntimePatchTimer) {{
      clearInterval(window.__firstRuntimePatchTimer);
      window.__firstRuntimePatchTimer = null;
    }}
    if (window.__firstRuntimePatchObserver) {{
      window.__firstRuntimePatchObserver.disconnect();
      window.__firstRuntimePatchObserver = null;
    }}
  }} catch (e) {{}}
  window.__firstRuntimePatchPairs = pairs;
  const applyString = (value) => {{
    if (typeof value !== 'string') return value;
    let out = value;
    const activePairs = window.__firstRuntimePatchPairs || pairs;
    for (const [oldText, newText] of activePairs) {{
      if (oldText && out.includes(oldText)) out = out.split(oldText).join(newText);
    }}
    return out;
  }};
  const deepPatch = (value, stat) => {{
    if (typeof value === 'string') {{
      const next = applyString(value);
      if (next !== value) stat.changed++;
      return next;
    }}
    if (Array.isArray(value)) return value.map(v => deepPatch(v, stat));
    if (value && typeof value === 'object') {{
      const out = {{}};
      Object.keys(value).forEach(k => out[k] = deepPatch(value[k], stat));
      return out;
    }}
    return value;
  }};
  const mutateInPlace = (value, stat, seen) => {{
    if (!value || typeof value !== 'object') return value;
    if (seen.has(value)) return value;
    seen.add(value);
    if (Array.isArray(value)) {{
      for (let i = 0; i < value.length; i++) {{
        if (typeof value[i] === 'string') {{
          const next = applyString(value[i]);
          if (next !== value[i]) {{
            value[i] = next;
            stat.changed++;
          }}
        }} else {{
          mutateInPlace(value[i], stat, seen);
        }}
      }}
      return value;
    }}
    Object.keys(value).forEach(k => {{
      if (typeof value[k] === 'string') {{
        const next = applyString(value[k]);
        if (next !== value[k]) {{
          value[k] = next;
          stat.changed++;
        }}
      }} else {{
        mutateInPlace(value[k], stat, seen);
      }}
    }});
    return value;
  }};
  const patchWxmlRuntime = () => {{
    const stat = {{changed: 0, errors: []}};
    try {{
      if (window.__WXML_GLOBAL__) mutateInPlace(window.__WXML_GLOBAL__, stat, new WeakSet());
      if (window.__wxAppCode__) mutateInPlace(window.__wxAppCode__, stat, new WeakSet());
    }} catch (e) {{
      stat.errors.push(String(e && e.message || e));
    }}
    return stat;
  }};
  const patchPages = () => {{
    const stat = {{pages: 0, changed: 0, errors: []}};
    try {{
      const wxFrame = (window.nav && window.nav.wxFrame) || window;
      const getPages = wxFrame.getCurrentPages || window.getCurrentPages;
      const pages = typeof getPages === 'function' ? getPages() : [];
      pages.forEach(page => {{
        if (!page || !page.data || typeof page.setData !== 'function') return;
        const local = {{changed: 0}};
        const patched = deepPatch(page.data, local);
        if (local.changed > 0) {{
          page.setData(patched);
          stat.changed += local.changed;
        }}
        stat.pages++;
      }});
    }} catch (e) {{
      stat.errors.push(String(e && e.message || e));
    }}
    return stat;
  }};
  const patchDom = () => {{
    try {{
      const root = document && document.body;
      if (!root) return 0;
      let count = 0;
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {{
        const next = applyString(node.nodeValue);
        if (next !== node.nodeValue) {{
          node.nodeValue = next;
          count++;
        }}
      }}
      return count;
    }} catch (e) {{
      return 0;
    }}
  }};
  const wxmlStat = patchWxmlRuntime();
  const pageStat = patchPages();
  const domChanged = patchDom();
  window.__firstRuntimePatchObserver = new MutationObserver(() => patchDom());
  window.__firstRuntimePatchObserver.observe(document.documentElement || document.body, {{
    subtree: true,
    childList: true,
    characterData: true
  }});
  window.__firstRuntimePatchTimer = setInterval(() => {{
    try {{ patchWxmlRuntime(); patchPages(); patchDom(); }} catch (e) {{}}
  }}, 800);
  return JSON.stringify({{ok:true, pairs:pairs.length, wxml:wxmlStat, page:pageStat, domChanged:domChanged}});
}})()
"""


def build_api_hook_js(api_pairs: list) -> str:
    pairs_json = json.dumps(api_pairs, ensure_ascii=False)
    return f"""
(() => {{
  const pairs = {pairs_json};
  const applyString = (value) => {{
    if (typeof value !== 'string') return value;
    let out = value;
    for (const [oldText, newText] of pairs) {{
      if (oldText && out.includes(oldText)) out = out.split(oldText).join(newText);
    }}
    return out;
  }};
  const patchObject = (value, stat, seen) => {{
    if (typeof value === 'string') {{
      const next = applyString(value);
      if (next !== value) stat.changed++;
      return next;
    }}
    if (!value || typeof value !== 'object') return value;
    if (seen.has(value)) return value;
    seen.add(value);
    if (Array.isArray(value)) {{
      for (let i = 0; i < value.length; i++) value[i] = patchObject(value[i], stat, seen);
      return value;
    }}
    Object.keys(value).forEach(k => value[k] = patchObject(value[k], stat, seen));
    return value;
  }};
  const installOnWx = (wxObj) => {{
    const stat = {{hooked: 0, changed: 0, errors: []}};
    if (!wxObj || typeof wxObj !== 'object') return stat;
    const names = [
      'showModal',
      'showToast',
      'showActionSheet',
      'setNavigationBarTitle',
      'showLoading',
      'showNavigationBarLoading'
    ];
    if (!wxObj.__firstApiPatchOriginals) {{
      try {{
        Object.defineProperty(wxObj, '__firstApiPatchOriginals', {{value: {{}}, configurable: true}});
      }} catch (e) {{
        wxObj.__firstApiPatchOriginals = {{}};
      }}
    }}
    wxObj.__firstApiPatchPairs = pairs;
    names.forEach(name => {{
      try {{
        const current = wxObj[name];
        if (typeof current !== 'function') return;
        const raw = wxObj.__firstApiPatchOriginals[name] || current;
        wxObj.__firstApiPatchOriginals[name] = raw;
        wxObj[name] = function(...args) {{
          const local = {{changed: 0}};
          for (let i = 0; i < args.length; i++) args[i] = patchObject(args[i], local, new WeakSet());
          stat.changed += local.changed;
          return raw.apply(this, args);
        }};
        stat.hooked++;
      }} catch (e) {{
        stat.errors.push(name + ': ' + String(e && e.message || e));
      }}
    }});
    return stat;
  }};
  const stats = [];
  try {{ stats.push(installOnWx(window.wx)); }} catch (e) {{}}
  try {{
    const wxFrame = window.nav && window.nav.wxFrame;
    if (wxFrame && wxFrame.wx && wxFrame.wx !== window.wx) stats.push(installOnWx(wxFrame.wx));
  }} catch (e) {{}}
  return JSON.stringify({{ok:true, pairs:pairs.length, stats}});
}})()
"""


def build_behavior_hook_js(methods: list) -> str:
    method_names = {m.get("name") for m in methods}
    modal_bodies = [
        m.get("body", "") for m in methods
        if "wx.showModal" in m.get("body", "") and "navigateToMiniProgram" not in m.get("body", "")
    ]
    if not modal_bodies or not ({"jumpToAppId", "jumpToPage", "jumpCustom"} & method_names):
        return ""
    modal_match = re.search(r"wx\.showModal\s*\(\s*(\{[\s\S]*?\})\s*\)", modal_bodies[0])
    modal_options = modal_match.group(1) if modal_match else '{content:"hello world",showCancel:false}'
    return f"""
(() => {{
  const stat = {{hooked: 0, calls: 0, errors: []}};
  const modalOptions = {modal_options};
  const install = (wxObj, label) => {{
    if (!wxObj || typeof wxObj.navigateToMiniProgram !== 'function') return;
    try {{
      if (!wxObj.__firstOriginalNavigateToMiniProgram) {{
        wxObj.__firstOriginalNavigateToMiniProgram = wxObj.navigateToMiniProgram;
      }}
      wxObj.navigateToMiniProgram = function(opts) {{
        stat.calls++;
        try {{
          if (typeof wxObj.showModal === 'function') {{
            return wxObj.showModal(Object.assign({{}}, modalOptions));
          }}
        }} catch (e) {{
          stat.errors.push(label + '.call: ' + String(e && e.message || e));
        }}
        return wxObj.__firstOriginalNavigateToMiniProgram.apply(this, arguments);
      }};
      stat.hooked++;
    }} catch (e) {{
      stat.errors.push(label + ': ' + String(e && e.message || e));
    }}
  }};
  try {{ install(window.wx, 'window.wx'); }} catch (e) {{}}
  try {{
    const wxFrame = window.nav && window.nav.wxFrame;
    if (wxFrame && wxFrame.wx && wxFrame.wx !== window.wx) install(wxFrame.wx, 'wxFrame.wx');
  }} catch (e) {{}}
  return JSON.stringify({{ok:true, behaviorHook:stat}});
}})()
"""


def build_page_method_hook_js(methods: list) -> str:
    methods_json = json.dumps(methods, ensure_ascii=False)
    direct_registry_lines = []
    for item in methods:
        name = item.get("name", "")
        params = item.get("params", "")
        body = item.get("body", "")
        if not name or re.search(r"[{};]", params):
            continue
        direct_registry_lines.append(
            f"  registry[{json.dumps(name, ensure_ascii=False)}] = function({params}) {{\n"
            f"    const wx = getWx();\n{body}\n  }};"
        )
    direct_registry_js = "\n".join(direct_registry_lines)
    return f"""
(() => {{
  const methods = {methods_json};
  const registry = {{}};
  const compileErrors = [];
  const getWx = () => {{
    if (typeof wx !== 'undefined' && wx) return wx;
    if (typeof window !== 'undefined') {{
      if (window.wx) return window.wx;
      const wxFrame = window.nav && window.nav.wxFrame;
      if (wxFrame && wxFrame.wx) return wxFrame.wx;
    }}
    return null;
  }};
  const modalFallback = (payload) => function() {{
    const opts = Object.assign({{}}, payload || {{}});
    if (!opts.content && !opts.title) opts.content = 'hello world';
    const wxObj = getWx();
    if (wxObj && typeof wxObj.showModal === 'function') {{
      return wxObj.showModal(opts);
    }}
    throw new Error('wx.showModal is not available');
  }};
  const compileMethod = (item) => {{
    try {{
      if (item.modal_payload) return modalFallback(item.modal_payload);
      const params = (item.params || '').split(',').map(p => p.trim()).filter(Boolean);
      return Function.apply(null, params.concat(item.body + '\\n'));
    }} catch (e) {{
      if (item.modal_payload) {{
        try {{
          compileErrors.push(item.name + ': dynamic compile failed, using modal fallback: ' + String(e && e.message || e));
          return modalFallback(item.modal_payload);
        }} catch (fallbackError) {{
          compileErrors.push(item.name + ': modal fallback failed: ' + String(fallbackError && fallbackError.message || fallbackError));
        }}
      }} else {{
        compileErrors.push(item.name + ': ' + String(e && e.message || e));
      }}
      return null;
    }}
  }};
  try {{
{direct_registry_js}
  }} catch (e) {{
    compileErrors.push('direct registry: ' + String(e && e.message || e));
  }}
  methods.forEach(item => {{
    if (typeof registry[item.name] === 'function') return;
    const fn = compileMethod(item);
    if (typeof fn === 'function') registry[item.name] = fn;
  }});
  const installOnObject = (obj, stat, label, countChange) => {{
    if (!obj || typeof obj !== 'object') {{
      return;
    }}
    const registryNames = Object.keys(registry);
    if (!registryNames.length) {{
      return;
    }}
    registryNames.forEach(name => {{
      try {{
        const fn = registry[name];
        if (typeof fn !== 'function') return;
        const wrapped = function() {{
          try {{
            return fn.apply(this, arguments);
          }} catch (e) {{
            try {{
              const msg = name + ': ' + String(e && e.message || e);
              const wxObj = getWx();
              if (wxObj && typeof wxObj.showModal === 'function') {{
                wxObj.showModal({{title:'运行时修改错误', content:msg.slice(0, 500), showCancel:false}});
              }}
              if (typeof window !== 'undefined') {{
                window.__firstRuntimeMethodErrors = window.__firstRuntimeMethodErrors || [];
                window.__firstRuntimeMethodErrors.push({{name, message:msg, time:Date.now()}});
              }}
            }} catch (_) {{}}
            throw e;
          }}
        }};
        if (!obj.__firstOriginalMethods) {{
          try {{
            Object.defineProperty(obj, '__firstOriginalMethods', {{value: {{}}, configurable: true}});
          }} catch (e) {{
            obj.__firstOriginalMethods = {{}};
          }}
        }}
        if (!obj.__firstOriginalMethods[name] && typeof obj[name] === 'function') {{
          obj.__firstOriginalMethods[name] = obj[name];
        }}
        const beforeType = typeof obj[name];
        try {{
          Object.defineProperty(obj, name, {{
            value: wrapped,
            configurable: true,
            writable: true,
            enumerable: true
          }});
        }} catch (e) {{
          obj[name] = wrapped;
        }}
        const afterType = typeof obj[name];
        const same = obj[name] === wrapped;
        if (same && countChange) stat.changed++;
        if (same) stat.targets.push(label + '.' + name + '(' + beforeType + '->' + afterType + ')');
      }} catch (e) {{
        stat.errors.push(label + '.' + name + ': ' + String(e && e.message || e));
      }}
    }});
  }};
  const installOnPage = (page, stat, index) => {{
    if (!page || typeof page !== 'object') {{
      return;
    }}
    installOnObject(page, stat, 'page' + index, true);
    try {{ installOnObject(Object.getPrototypeOf(page), stat, 'pageProto' + index, true); }} catch (e) {{}}
    try {{ installOnObject(page.$vm, stat, 'pageVm' + index, true); }} catch (e) {{}}
    try {{ installOnObject(page.__wxWebviewPage__, stat, 'webviewPage' + index, true); }} catch (e) {{}}
  }};
  const hookPageConstructor = (root, stat, label) => {{
    try {{
      if (!root || typeof root.Page !== 'function') return;
      const raw = root.__firstOriginalPage || root.Page;
      root.__firstOriginalPage = raw;
      root.Page = function(options) {{
        try {{
          if (options && typeof options === 'object') installOnObject(options, stat, label + '.PageOptions', true);
        }} catch (e) {{}}
        return raw.apply(this, arguments);
      }};
      stat.pageConstructors++;
    }} catch (e) {{
      stat.errors.push(label + '.Page: ' + String(e && e.message || e));
    }}
  }};
  const shouldSkipObject = (obj) => {{
    if (!obj || typeof obj !== 'object') return true;
    try {{
      if (obj === window || obj === document || obj === location || obj === navigator) return false;
      if (typeof Node !== 'undefined' && obj instanceof Node) return true;
      if (typeof Window !== 'undefined' && obj instanceof Window && obj !== window) return true;
    }} catch (e) {{}}
    return false;
  }};
  const deepInstall = (root, stat, label) => {{
    const queue = [{{obj: root, path: label, depth: 0}}];
    const seen = new WeakSet();
    let scanned = 0;
    while (queue.length && scanned < 2500) {{
      const item = queue.shift();
      const obj = item.obj;
      if (shouldSkipObject(obj) || seen.has(obj)) continue;
      seen.add(obj);
      scanned++;
      installOnObject(obj, stat, item.path, false);
      if (item.depth >= 5) continue;
      let keys = [];
      try {{ keys = Object.keys(obj); }} catch (e) {{ continue; }}
      for (const key of keys.slice(0, 120)) {{
        let child;
        try {{ child = obj[key]; }} catch (e) {{ continue; }}
        if (child && typeof child === 'object' && !seen.has(child)) {{
          queue.push({{obj: child, path: item.path + '.' + key, depth: item.depth + 1}});
        }}
      }}
    }}
    stat.scanned += scanned;
  }};
  const stat = {{
    methods: methods.length,
    compiled: Object.keys(registry).length,
    registry: Object.keys(registry),
    pages: 0,
    changed: 0,
    pageConstructors: 0,
    targets: [],
    errors: compileErrors.slice()
  }};
  stat.scanned = 0;
  try {{
    const wxFrame = (window.nav && window.nav.wxFrame) || window;
    const getPages = wxFrame.getCurrentPages || window.getCurrentPages;
    const pages = typeof getPages === 'function' ? getPages() : [];
    pages.forEach((page, index) => {{
      installOnPage(page, stat, index);
      stat.pages++;
    }});
    hookPageConstructor(window, stat, 'window');
    if (wxFrame && wxFrame !== window) hookPageConstructor(wxFrame, stat, 'wxFrame');
    try {{ deepInstall(window.__wxAppCode__, stat, '__wxAppCode__'); }} catch (e) {{}}
    try {{ deepInstall(window.__WXML_GLOBAL__, stat, '__WXML_GLOBAL__'); }} catch (e) {{}}
    try {{ if (wxFrame && wxFrame !== window) deepInstall(wxFrame, stat, 'wxFrame'); }} catch (e) {{}}
    try {{ deepInstall(window, stat, 'window'); }} catch (e) {{}}
  }} catch (e) {{
    stat.errors.push(String(e && e.message || e));
  }}
  return JSON.stringify({{ok:true, pageHook:stat}});
}})()
"""


def extract_runtime_value(result):
    try:
        value = result.get("result", {}).get("result", {}).get("value")
        if isinstance(value, str):
            try:
                return json.loads(value)
            except Exception:
                return value
        return value
    except Exception:
        return None


def count_runtime_patch_changed(value) -> int:
    if not isinstance(value, dict):
        return 0
    wxml = value.get("wxml") or {}
    page = value.get("page") or {}
    return (
        int(wxml.get("changed") or 0)
        + int(page.get("changed") or 0)
        + int(value.get("domChanged") or 0)
    )


def runtime_patch_hit_summary(data) -> str:
    if not isinstance(data, dict):
        return ""
    for item in data.get("results", []):
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if not isinstance(value, dict) or count_runtime_patch_changed(value) <= 0:
            continue
        ctx = item.get("context", {})
        aux = ctx.get("auxData", {}) if isinstance(ctx, dict) else {}
        frame = aux.get("frameId", "")
        return frame[:8] if frame else str(ctx.get("id", ""))
    return ""
