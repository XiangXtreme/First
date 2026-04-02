"""
敏感信息提取引擎 — 纯 Python 实现
完整移植 HeartK-1.1.1/js/background.js 的全部匹配规则。
"""
import re
import json
import os
import time
from datetime import datetime

# ══════════════════════════════════════════
#  信息提取正则 (1:1 移植自 HeartK background.js extract_info)
# ══════════════════════════════════════════

_TLD = (r'xin|com|cn|net|com\.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|'
        r'news|pub|fun|online|win|red|loan|ren|mom|net\.cn|org|link|biz|bid|'
        r'help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|'
        r'store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|'
        r'photo|market|tel|social|press|game|kim|org\.cn|games|pro|men|love|'
        r'studio|rocks|asia|group|science|design|software|engineer|lawyer|'
        r'fit|beer|tw|我爱你|中国|公司|网络|在线|网址|网店|集团|中文网')

_PATTERNS = {
    "sfz": re.compile(
        r"""['"]((\d{8}(0\d|10|11|12)([0-2]\d|30|31)\d{3}$)|"""
        r"""(\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)([0-2]\d|30|31)\d{3}(\d|X|x)))['"]"""),
    "mobile": re.compile(
        r"""['"](1(3([0-35-9]\d|4[1-8])|4[14-9]\d|5([\d]\d|7[1-79])|"""
        r"""66\d|7[2-35-8]\d|8\d{2}|9[89]\d)\d{7})['"]"""),
    "mail": re.compile(
        r"""['"][a-zA-Z0-9._\-]*@[a-zA-Z0-9._\-]{1,63}"""
        r"""\.((?!js|css|jpg|jpeg|png|ico)[a-zA-Z]{2,})['"]"""),
    "ip": re.compile(
        r"""['"](([a-zA-Z0-9]+:)?//)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/.*?)?['"]"""),
    "ip_port": re.compile(
        r"""['"](([a-zA-Z0-9]+:)?//)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}(/.*?)?['"]"""),
    "domain": re.compile(
        r"""['"](([a-zA-Z0-9]+:)?//)?[a-zA-Z0-9\-\.]*?\.(""" + _TLD +
        r""")(:\d{1,5})?(/)?['"]"""),
    "path": re.compile(
        r"""(?:"|')"""
        r"""("""
        r"""(?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,}"""
        r"""|(?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,}"""
        r"""|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|)"""
        r"""|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|)"""
        r"""|[a-zA-Z0-9_\-]{1,}\.(?:\w)(?:[\?|#][^"|']{0,}|)"""
        r""")"""
        r"""(?:"|')"""),
    "jwt": re.compile(
        r"""['"](ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|"""
        r"""ey[A-Za-z0-9_/+-]{10,}\.[A-Za-z0-9._/+-]{10,})['"]"""),
    "algorithm": re.compile(
        r"""\W(Base64\.encode|Base64\.decode|btoa|atob|"""
        r"""CryptoJS\.AES|CryptoJS\.DES|JSEncrypt|rsa|KJUR|"""
        r"""\$\.md5|md5|sha1|sha256|sha512)[(.]""", re.IGNORECASE),
}

# ══════════════════════════════════════════
#  URL 提取正则 (8 patterns: 4 core × 2 quote styles)
# ══════════════════════════════════════════

_DANGEROUS_EXT = (
    r'php|asp|aspx|jsp|do|action|cgi|ashx|asmx|py|pl|go|rb|class|jar|war|ear|phar|'
    r'html|htm|exe|msi|bat|cmd|sh|bash|zsh|vbs|ps1|psm1|ps2|msh|msh1|msh2|mshxml|'
    r'msh1xml|msh2xml|dll|so|dylib|ocx|sys|drv|com|scr|pif|hta|vb|bas|frm|vbx|vbp|'
    r'service|desktop|application|command|tool|jspx|asa|cer|cdx|rhtml|tcl|tk|pm|rpm|'
    r'deb|apk|ipa|app|bin|elf|run|img|pkg|iso|dmg|nexe|node|wasm|clj|scala|groovy|'
    r'a|o|lib|ex_|inf|reg|lnk|scf'
)

_HOST_RE = r"""https?://[^\s'"/?#]+(?::\d+)?"""

def _build_url_patterns():
    cores = [
        # 1. single segment, no extension
        _HOST_RE + r"""/*[^'"\s./?]+/*(?:\?[^\s'"]*)?""",
        # 2. single segment, dangerous extension
        _HOST_RE + r"""/*[^'"\s/?]+\.(?:""" + _DANGEROUS_EXT + r""")/*(?:\?[^\s'"]*)?""",
        # 3. multi-segment, no extension
        _HOST_RE + r"""/*(?:/+[^'"\s/?]*)+/+[^'"\s./?]+/*(?:\?[^\s'"]*)?""",
        # 4. multi-segment, dangerous extension
        _HOST_RE + r"""/*(?:/+[^'"\s/?]*)+/+[^'"\s/?]+\.(?:""" + _DANGEROUS_EXT + r""")/*(?:\?[^\s'"]*)?""",
    ]
    pats = []
    for core in cores:
        # normal quotes
        pats.append(re.compile(r"""(?:^|[^\\])["'](""" + core + r""")["']""", re.IGNORECASE | re.MULTILINE))
        # escaped quotes
        pats.append(re.compile(r"""\\["'](""" + core + r""")\\["']""", re.IGNORECASE))
    return pats

_URL_PATTERNS = _build_url_patterns()

# ══════════════════════════════════════════
#  静态资源提取正则 (8 patterns: 4 core × 2 quote styles)
# ══════════════════════════════════════════

_STATIC_EXT = (
    r'css|js|ts|json|config|xml|vue|jsx|tsx|txt|csv|'
    r'png|jpg|jpeg|gif|webp|svg|ico|bmp|'
    r'mp3|wav|ogg|mp4|webm|mov|avi|mkv|'
    r'pdf|doc|docx|xls|xlsx|ppt|pptx|rtf|'
    r'woff|woff2|ttf|eot|svelte|'
    r'zip|rar|7z|tar|gz|bz2|xz|tgz|tbz|lz|lz4|zst|iso'
)

def _build_static_patterns():
    ext_group = r"""\.(?:""" + _STATIC_EXT + r""")/*(?:\?[^\s'"]*)?"""
    cores = [
        # 1. local path, single segment
        r"""/+[^'"\s/?]+""" + ext_group,
        # 2. local path, multi-segment
        r"""(?:/+[^'"\s/?]*)+/+[^'"\s/?]+""" + ext_group,
        # 3. full URL, single segment
        r"""https?://[^\s'"/?#]+(?::\d+)?/*[^'"\s/?]+""" + ext_group,
        # 4. full URL, multi-segment
        r"""https?://[^\s'"/?#]+(?::\d+)?/*(?:/+[^'"\s/?]*)+/+[^'"\s/?]+""" + ext_group,
    ]
    pats = []
    for core in cores:
        # normal quotes
        pats.append(re.compile(r"""(?:^|[^\\])["'](""" + core + r""")["']""", re.IGNORECASE | re.MULTILINE))
        # escaped quotes
        pats.append(re.compile(r"""\\["'](""" + core + r""")\\["']""", re.IGNORECASE))
    return pats

_STATIC_PATTERNS = _build_static_patterns()

# ══════════════════════════════════════════
#  OSS 云存储域名检测
# ══════════════════════════════════════════

_OSS_DOMAIN_RE = re.compile(
    r'(?:'
    r'[\w.-]+\.oss[\w-]*\.aliyuncs\.com|'          # 阿里云 OSS
    r'[\w.-]+\.cos\.[\w-]+\.myqcloud\.com|'         # 腾讯云 COS
    r'[\w.-]+\.file\.myqcloud\.com|'                # 腾讯云 COS legacy
    r'(?:[\w.-]+\.)?s3[\w.-]*\.amazonaws\.com|'     # AWS S3
    r'[\w.-]+\.obs\.[\w-]+\.myhuaweicloud\.com|'    # 华为云 OBS
    r'[\w.-]+\.(?:qiniucdn|qnssl)\.com|'            # 七牛 CDN
    r'[\w.-]+\.bkt\.clouddn\.com|'                  # 七牛旧域名
    r'[\w.-]+\.blob\.core\.windows\.net|'           # Azure Blob
    r'[\w.-]+\.azureedge\.net|'                     # Azure CDN
    r'storage\.googleapis\.com(?:/[\w.-]+)?|'       # Google Cloud Storage
    r'[\w.-]+\.storage\.googleapis\.com|'           # GCS alt
    r'[\w.-]+\.cdn\.bcebos\.com|'                   # 百度 BOS
    r'[\w.-]+\.vod[\w-]*\.aliyuncs\.com|'           # 阿里云 VOD
    r'[\w.-]+\.cdn\.aliyuncs\.com|'                 # 阿里云 CDN
    r'[\w.-]+\.ucloud\.cn|'                         # UCloud
    r'[\w.-]+\.ks3[\w-]*\.ksyun\.com'              # 金山云 KS3
    r')',
    re.IGNORECASE
)

# 静态资源过滤: .js 不算(排除 .jsp)
_STATIC_FILTER_EXTS = ('.ts', '.tsx', '.less', '.scss', '.sass', '.map',
                       '.d.ts', '.spec.ts', '.test.ts')

# ══════════════════════════════════════════
#  Nuclei 凭证泄露检测 — 完整移植 HeartK 的 702+24 条规则
# ══════════════════════════════════════════

# 702 个 nuclei key name (每个 key 用标准模板匹配: ["']?KEY["']? [=:] ["']?VALUE["']?)
# 直接取自 HeartK-1.1.1/js/background.js nuclei_regex 数组
_NUCLEI_KEY_NAMES = [
    r'zopim[_-]?account[_-]?key',
    r'zhuliang[_-]?gh[_-]?token',
    r'zensonatypepassword',
    r'zendesk[_-]?travis[_-]?github',
    r'yt[_-]?server[_-]?api[_-]?key',
    r'yt[_-]?partner[_-]?refresh[_-]?token',
    r'yt[_-]?partner[_-]?client[_-]?secret',
    r'yt[_-]?client[_-]?secret',
    r'yt[_-]?api[_-]?key',
    r'yt[_-]?account[_-]?refresh[_-]?token',
    r'yt[_-]?account[_-]?client[_-]?secret',
    r'yangshun[_-]?gh[_-]?token',
    r'yangshun[_-]?gh[_-]?password',
    r'www[_-]?googleapis[_-]?com',
    r'wpt[_-]?ssh[_-]?private[_-]?key[_-]?base64',
    r'wpt[_-]?ssh[_-]?connect',
    r'wpt[_-]?report[_-]?api[_-]?key',
    r'wpt[_-]?prepare[_-]?dir',
    r'wpt[_-]?db[_-]?user',
    r'wpt[_-]?db[_-]?password',
    r'wporg[_-]?password',
    r'wpjm[_-]?phpunit[_-]?google[_-]?geocode[_-]?api[_-]?key',
    r'wordpress[_-]?db[_-]?user',
    r'wordpress[_-]?db[_-]?password',
    r'wincert[_-]?password',
    r'widget[_-]?test[_-]?server',
    r'widget[_-]?fb[_-]?password[_-]?3',
    r'widget[_-]?fb[_-]?password[_-]?2',
    r'widget[_-]?fb[_-]?password',
    r'widget[_-]?basic[_-]?password[_-]?5',
    r'widget[_-]?basic[_-]?password[_-]?4',
    r'widget[_-]?basic[_-]?password[_-]?3',
    r'widget[_-]?basic[_-]?password[_-]?2',
    r'widget[_-]?basic[_-]?password',
    r'watson[_-]?password',
    r'watson[_-]?device[_-]?password',
    r'watson[_-]?conversation[_-]?password',
    r'wakatime[_-]?api[_-]?key',
    r'vscetoken',
    r'visual[_-]?recognition[_-]?api[_-]?key',
    r'virustotal[_-]?apikey',
    r'vip[_-]?github[_-]?deploy[_-]?key[_-]?pass',
    r'vip[_-]?github[_-]?deploy[_-]?key',
    r'vip[_-]?github[_-]?build[_-]?repo[_-]?deploy[_-]?key',
    r'v[_-]?sfdc[_-]?password',
    r'v[_-]?sfdc[_-]?client[_-]?secret',
    r'usertravis',
    r'user[_-]?assets[_-]?secret[_-]?access[_-]?key',
    r'user[_-]?assets[_-]?access[_-]?key[_-]?id',
    r'use[_-]?ssh',
    r'us[_-]?east[_-]?1[_-]?elb[_-]?amazonaws[_-]?com',
    r'urban[_-]?secret',
    r'urban[_-]?master[_-]?secret',
    r'urban[_-]?key',
    r'unity[_-]?serial',
    r'unity[_-]?password',
    r'twitteroauthaccesstoken',
    r'twitteroauthaccesssecret',
    r'twitter[_-]?consumer[_-]?secret',
    r'twitter[_-]?consumer[_-]?key',
    r'twine[_-]?password',
    r'twilio[_-]?token',
    r'twilio[_-]?sid',
    r'twilio[_-]?configuration[_-]?sid',
    r'twilio[_-]?chat[_-]?account[_-]?api[_-]?service',
    r'twilio[_-]?api[_-]?secret',
    r'twilio[_-]?api[_-]?key',
    r'trex[_-]?okta[_-]?client[_-]?token',
    r'trex[_-]?client[_-]?token',
    r'travis[_-]?token',
    r'travis[_-]?secure[_-]?env[_-]?vars',
    r'travis[_-]?pull[_-]?request',
    r'travis[_-]?gh[_-]?token',
    r'travis[_-]?e2e[_-]?token',
    r'travis[_-]?com[_-]?token',
    r'travis[_-]?branch',
    r'travis[_-]?api[_-]?token',
    r'travis[_-]?access[_-]?token',
    r'token[_-]?core[_-]?java',
    r'thera[_-]?oss[_-]?access[_-]?key',
    r'tester[_-]?keys[_-]?password',
    r'test[_-]?test',
    r'test[_-]?github[_-]?token',
    r'tesco[_-]?api[_-]?key',
    r'svn[_-]?pass',
    r'surge[_-]?token',
    r'surge[_-]?login',
    r'stripe[_-]?public',
    r'stripe[_-]?private',
    r'strip[_-]?secret[_-]?key',
    r'strip[_-]?publishable[_-]?key',
    r'stormpath[_-]?api[_-]?key[_-]?secret',
    r'stormpath[_-]?api[_-]?key[_-]?id',
    r'starship[_-]?auth[_-]?token',
    r'starship[_-]?account[_-]?sid',
    r'star[_-]?test[_-]?secret[_-]?access[_-]?key',
    r'star[_-]?test[_-]?location',
    r'star[_-]?test[_-]?bucket',
    r'star[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id',
    r'staging[_-]?base[_-]?url[_-]?runscope',
    r'ssmtp[_-]?config',
    r'sshpass',
    r'srcclr[_-]?api[_-]?token',
    r'square[_-]?reader[_-]?sdk[_-]?repository[_-]?password',
    r'sqssecretkey',
    r'sqsaccesskey',
    r'spring[_-]?mail[_-]?password',
    r'spotify[_-]?api[_-]?client[_-]?secret',
    r'spotify[_-]?api[_-]?access[_-]?token',
    r'spaces[_-]?secret[_-]?access[_-]?key',
    r'spaces[_-]?access[_-]?key[_-]?id',
    r'soundcloud[_-]?password',
    r'soundcloud[_-]?client[_-]?secret',
    r'sonatypepassword',
    r'sonatype[_-]?token[_-]?user',
    r'sonatype[_-]?token[_-]?password',
    r'sonatype[_-]?password',
    r'sonatype[_-]?pass',
    r'sonatype[_-]?nexus[_-]?password',
    r'sonatype[_-]?gpg[_-]?passphrase',
    r'sonatype[_-]?gpg[_-]?key[_-]?name',
    r'sonar[_-]?token',
    r'sonar[_-]?project[_-]?key',
    r'sonar[_-]?organization[_-]?key',
    r'socrata[_-]?password',
    r'socrata[_-]?app[_-]?token',
    r'snyk[_-]?token',
    r'snyk[_-]?api[_-]?token',
    r'snoowrap[_-]?refresh[_-]?token',
    r'snoowrap[_-]?password',
    r'snoowrap[_-]?client[_-]?secret',
    r'slate[_-]?user[_-]?email',
    r'slash[_-]?developer[_-]?space[_-]?key',
    r'slash[_-]?developer[_-]?space',
    r'signing[_-]?key[_-]?sid',
    r'signing[_-]?key[_-]?secret',
    r'signing[_-]?key[_-]?password',
    r'signing[_-]?key',
    r'setsecretkey',
    r'setdstsecretkey',
    r'setdstaccesskey',
    r'ses[_-]?secret[_-]?key',
    r'ses[_-]?access[_-]?key',
    r'service[_-]?account[_-]?secret',
    r'sentry[_-]?key',
    r'sentry[_-]?secret',
    r'sentry[_-]?endpoint',
    r'sentry[_-]?default[_-]?org',
    r'sentry[_-]?auth[_-]?token',
    r'sendwithus[_-]?key',
    r'sendgrid[_-]?username',
    r'sendgrid[_-]?user',
    r'sendgrid[_-]?password',
    r'sendgrid[_-]?key',
    r'sendgrid[_-]?api[_-]?key',
    r'sendgrid',
    r'selion[_-]?selenium[_-]?host',
    r'selion[_-]?log[_-]?level[_-]?dev',
    r'segment[_-]?api[_-]?key',
    r'secretid',
    r'secretkey',
    r'secretaccesskey',
    r'secret[_-]?key[_-]?base',
    r'secret[_-]?9',
    r'secret[_-]?8',
    r'secret[_-]?7',
    r'secret[_-]?6',
    r'secret[_-]?5',
    r'secret[_-]?4',
    r'secret[_-]?3',
    r'secret[_-]?2',
    r'secret[_-]?11',
    r'secret[_-]?10',
    r'secret[_-]?1',
    r'secret[_-]?0',
    r'sdr[_-]?token',
    r'scrutinizer[_-]?token',
    r'sauce[_-]?access[_-]?key',
    r'sandbox[_-]?aws[_-]?secret[_-]?access[_-]?key',
    r'sandbox[_-]?aws[_-]?access[_-]?key[_-]?id',
    r'sandbox[_-]?access[_-]?token',
    r'salesforce[_-]?bulk[_-]?test[_-]?security[_-]?token',
    r'salesforce[_-]?bulk[_-]?test[_-]?password',
    r'sacloud[_-]?api',
    r'sacloud[_-]?access[_-]?token[_-]?secret',
    r'sacloud[_-]?access[_-]?token',
    r's3[_-]?user[_-]?secret',
    r's3[_-]?secret[_-]?key',
    r's3[_-]?secret[_-]?assets',
    r's3[_-]?secret[_-]?app[_-]?logs',
    r's3[_-]?key[_-]?assets',
    r's3[_-]?key[_-]?app[_-]?logs',
    r's3[_-]?key',
    r's3[_-]?external[_-]?3[_-]?amazonaws[_-]?com',
    r's3[_-]?bucket[_-]?name[_-]?assets',
    r's3[_-]?bucket[_-]?name[_-]?app[_-]?logs',
    r's3[_-]?access[_-]?key[_-]?id',
    r's3[_-]?access[_-]?key',
    r'rubygems[_-]?auth[_-]?token',
    r'rtd[_-]?store[_-]?pass',
    r'rtd[_-]?key[_-]?pass',
    r'route53[_-]?access[_-]?key[_-]?id',
    r'ropsten[_-]?private[_-]?key',
    r'rinkeby[_-]?private[_-]?key',
    r'rest[_-]?api[_-]?key',
    r'repotoken',
    r'reporting[_-]?webdav[_-]?url',
    r'reporting[_-]?webdav[_-]?pwd',
    r'release[_-]?token',
    r'release[_-]?gh[_-]?token',
    r'registry[_-]?secure',
    r'registry[_-]?pass',
    r'refresh[_-]?token',
    r'rediscloud[_-]?url',
    r'redis[_-]?stunnel[_-]?urls',
    r'randrmusicapiaccesstoken',
    r'rabbitmq[_-]?password',
    r'quip[_-]?token',
    r'qiita[_-]?token',
    r'pypi[_-]?passowrd',
    r'pushover[_-]?token',
    r'publish[_-]?secret',
    r'publish[_-]?key',
    r'publish[_-]?access',
    r'project[_-]?config',
    r'prod[_-]?secret[_-]?key',
    r'prod[_-]?password',
    r'prod[_-]?access[_-]?key[_-]?id',
    r'private[_-]?signing[_-]?password',
    r'private[_-]?key[_-]?(id)?',
    r'pring[_-]?mail[_-]?username',
    r'preferred[_-]?username',
    r'prebuild[_-]?auth',
    r'postgresql[_-]?pass',
    r'postgresql[_-]?db',
    r'postgres[_-]?env[_-]?postgres[_-]?password',
    r'postgres[_-]?env[_-]?postgres[_-]?db',
    r'plugin[_-]?password',
    r'plotly[_-]?apikey',
    r'places[_-]?apikey',
    r'places[_-]?api[_-]?key',
    r'pg[_-]?host',
    r'pg[_-]?database',
    r'personal[_-]?secret',
    r'personal[_-]?key',
    r'percy[_-]?token',
    r'percy[_-]?project',
    r'paypal[_-]?client[_-]?secret',
    r'passwordtravis',
    r'parse[_-]?js[_-]?key',
    r'pagerduty[_-]?apikey',
    r'packagecloud[_-]?token',
    r'ossrh[_-]?username',
    r'ossrh[_-]?secret',
    r'ossrh[_-]?password',
    r'ossrh[_-]?pass',
    r'ossrh[_-]?jira[_-]?password',
    r'os[_-]?password',
    r'os[_-]?auth[_-]?url',
    r'org[_-]?project[_-]?gradle[_-]?sonatype[_-]?nexus[_-]?password',
    r'org[_-]?gradle[_-]?project[_-]?sonatype[_-]?nexus[_-]?password',
    r'openwhisk[_-]?key',
    r'open[_-]?whisk[_-]?key',
    r'onesignal[_-]?user[_-]?auth[_-]?key',
    r'onesignal[_-]?api[_-]?key',
    r'omise[_-]?skey',
    r'omise[_-]?pubkey',
    r'omise[_-]?pkey',
    r'omise[_-]?key',
    r'okta[_-]?oauth2[_-]?clientsecret',
    r'okta[_-]?oauth2[_-]?client[_-]?secret',
    r'okta[_-]?client[_-]?token',
    r'ofta[_-]?secret',
    r'ofta[_-]?region',
    r'ofta[_-]?key',
    r'octest[_-]?password',
    r'octest[_-]?app[_-]?username',
    r'octest[_-]?app[_-]?password',
    r'oc[_-]?pass',
    r'object[_-]?store[_-]?creds',
    r'object[_-]?store[_-]?bucket',
    r'object[_-]?storage[_-]?region[_-]?name',
    r'object[_-]?storage[_-]?password',
    r'oauth[_-]?token',
    r'numbers[_-]?service[_-]?pass',
    r'nuget[_-]?key',
    r'nuget[_-]?apikey',
    r'nuget[_-]?api[_-]?key',
    r'npm[_-]?token',
    r'npm[_-]?secret[_-]?key',
    r'npm[_-]?password',
    r'npm[_-]?email',
    r'npm[_-]?auth[_-]?token',
    r'npm[_-]?api[_-]?token',
    r'npm[_-]?api[_-]?key',
    r'now[_-]?token',
    r'non[_-]?token',
    r'node[_-]?pre[_-]?gyp[_-]?secretaccesskey',
    r'node[_-]?pre[_-]?gyp[_-]?github[_-]?token',
    r'node[_-]?pre[_-]?gyp[_-]?accesskeyid',
    r'node[_-]?env',
    r'ngrok[_-]?token',
    r'ngrok[_-]?auth[_-]?token',
    r'nexuspassword',
    r'nexus[_-]?password',
    r'new[_-]?relic[_-]?beta[_-]?token',
    r'netlify[_-]?api[_-]?key',
    r'nativeevents',
    r'mysqlsecret',
    r'mysqlmasteruser',
    r'mysql[_-]?username',
    r'mysql[_-]?user',
    r'mysql[_-]?root[_-]?password',
    r'mysql[_-]?password',
    r'mysql[_-]?hostname',
    r'mysql[_-]?database',
    r'my[_-]?secret[_-]?env',
    r'multi[_-]?workspace[_-]?sid',
    r'multi[_-]?workflow[_-]?sid',
    r'multi[_-]?disconnect[_-]?sid',
    r'multi[_-]?connect[_-]?sid',
    r'multi[_-]?bob[_-]?sid',
    r'minio[_-]?secret[_-]?key',
    r'minio[_-]?access[_-]?key',
    r'mile[_-]?zero[_-]?key',
    r'mh[_-]?password',
    r'mh[_-]?apikey',
    r'mg[_-]?public[_-]?api[_-]?key',
    r'mg[_-]?api[_-]?key',
    r'mapboxaccesstoken',
    r'mapbox[_-]?aws[_-]?secret[_-]?access[_-]?key',
    r'mapbox[_-]?aws[_-]?access[_-]?key[_-]?id',
    r'mapbox[_-]?api[_-]?token',
    r'mapbox[_-]?access[_-]?token',
    r'manifest[_-]?app[_-]?url',
    r'manifest[_-]?app[_-]?token',
    r'mandrill[_-]?api[_-]?key',
    r'managementapiaccesstoken',
    r'management[_-]?token',
    r'manage[_-]?secret',
    r'manage[_-]?key',
    r'mailgun[_-]?secret[_-]?api[_-]?key',
    r'mailgun[_-]?pub[_-]?key',
    r'mailgun[_-]?pub[_-]?apikey',
    r'mailgun[_-]?priv[_-]?key',
    r'mailgun[_-]?password',
    r'mailgun[_-]?apikey',
    r'mailgun[_-]?api[_-]?key',
    r'mailer[_-]?password',
    r'mailchimp[_-]?key',
    r'mailchimp[_-]?api[_-]?key',
    r'mail[_-]?password',
    r'magento[_-]?password',
    r'magento[_-]?auth[_-]?username',
    r'magento[_-]?auth[_-]?password',
    r'lottie[_-]?upload[_-]?cert[_-]?key[_-]?store[_-]?password',
    r'lottie[_-]?upload[_-]?cert[_-]?key[_-]?password',
    r'lottie[_-]?s3[_-]?secret[_-]?key',
    r'lottie[_-]?s3[_-]?api[_-]?key',
    r'lottie[_-]?happo[_-]?secret[_-]?key',
    r'lottie[_-]?happo[_-]?api[_-]?key',
    r'looker[_-]?test[_-]?runner[_-]?client[_-]?secret',
    r'll[_-]?shared[_-]?key',
    r'll[_-]?publish[_-]?url',
    r'linux[_-]?signing[_-]?key',
    r'linkedin[_-]?client[_-]?secret',
    r'lighthouse[_-]?api[_-]?key',
    r'lektor[_-]?deploy[_-]?username',
    r'lektor[_-]?deploy[_-]?password',
    r'leanplum[_-]?key',
    r'kxoltsn3vogdop92m',
    r'kubeconfig',
    r'kubecfg[_-]?s3[_-]?path',
    r'kovan[_-]?private[_-]?key',
    r'keystore[_-]?pass',
    r'kafka[_-]?rest[_-]?url',
    r'kafka[_-]?instance[_-]?name',
    r'kafka[_-]?admin[_-]?url',
    r'jwt[_-]?secret',
    r'jdbc:mysql',
    r'jdbc[_-]?host',
    r'jdbc[_-]?databaseurl',
    r'itest[_-]?gh[_-]?token',
    r'ios[_-]?docs[_-]?deploy[_-]?token',
    r'internal[_-]?secrets',
    r'integration[_-]?test[_-]?appid',
    r'integration[_-]?test[_-]?api[_-]?key',
    r'index[_-]?name',
    r'ij[_-]?repo[_-]?username',
    r'ij[_-]?repo[_-]?password',
    r'hub[_-]?dxia2[_-]?password',
    r'homebrew[_-]?github[_-]?api[_-]?token',
    r'hockeyapp[_-]?token',
    r'heroku[_-]?token',
    r'heroku[_-]?email',
    r'heroku[_-]?api[_-]?key',
    r'hb[_-]?codesign[_-]?key[_-]?pass',
    r'hb[_-]?codesign[_-]?gpg[_-]?pass',
    r'hab[_-]?key',
    r'hab[_-]?auth[_-]?token',
    r'grgit[_-]?user',
    r'gren[_-]?github[_-]?token',
    r'gradle[_-]?signing[_-]?password',
    r'gradle[_-]?signing[_-]?key[_-]?id',
    r'gradle[_-]?publish[_-]?secret',
    r'gradle[_-]?publish[_-]?key',
    r'gpg[_-]?secret[_-]?keys',
    r'gpg[_-]?private[_-]?key',
    r'gpg[_-]?passphrase',
    r'gpg[_-]?ownertrust',
    r'gpg[_-]?keyname',
    r'gpg[_-]?key[_-]?name',
    r'google[_-]?private[_-]?key[_-]?(id)?',
    r'google[_-]?maps[_-]?api[_-]?key',
    r'google[_-]?client[_-]?secret',
    r'google[_-]?client[_-]?id',
    r'google[_-]?client[_-]?email',
    r'google[_-]?account[_-]?type',
    r'gogs[_-]?password',
    r'gitlab[_-]?user[_-]?email',
    r'github[_-]?tokens',
    r'github[_-]?token',
    r'github[_-]?repo',
    r'github[_-]?release[_-]?token',
    r'github[_-]?pwd',
    r'github[_-]?password',
    r'github[_-]?oauth[_-]?token',
    r'github[_-]?oauth',
    r'github[_-]?key',
    r'github[_-]?hunter[_-]?username',
    r'github[_-]?hunter[_-]?token',
    r'github[_-]?deployment[_-]?token',
    r'github[_-]?deploy[_-]?hb[_-]?doc[_-]?pass',
    r'github[_-]?client[_-]?secret',
    r'github[_-]?auth[_-]?token',
    r'github[_-]?auth',
    r'github[_-]?api[_-]?token',
    r'github[_-]?api[_-]?key',
    r'github[_-]?access[_-]?token',
    r'git[_-]?token',
    r'git[_-]?name',
    r'git[_-]?email',
    r'git[_-]?committer[_-]?name',
    r'git[_-]?committer[_-]?email',
    r'git[_-]?author[_-]?name',
    r'git[_-]?author[_-]?email',
    r'ghost[_-]?api[_-]?key',
    r'ghb[_-]?token',
    r'gh[_-]?unstable[_-]?oauth[_-]?client[_-]?secret',
    r'gh[_-]?token',
    r'gh[_-]?repo[_-]?token',
    r'gh[_-]?oauth[_-]?token',
    r'gh[_-]?oauth[_-]?client[_-]?secret',
    r'gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?secret',
    r'gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?id',
    r'gh[_-]?next[_-]?oauth[_-]?client[_-]?secret',
    r'gh[_-]?email',
    r'gh[_-]?api[_-]?key',
    r'gcs[_-]?bucket',
    r'gcr[_-]?password',
    r'gcloud[_-]?service[_-]?key',
    r'gcloud[_-]?project',
    r'gcloud[_-]?bucket',
    r'ftp[_-]?username',
    r'ftp[_-]?user',
    r'ftp[_-]?pw',
    r'ftp[_-]?password',
    r'ftp[_-]?login',
    r'ftp[_-]?host',
    r'fossa[_-]?api[_-]?key',
    r'flickr[_-]?api[_-]?secret',
    r'flickr[_-]?api[_-]?key',
    r'flask[_-]?secret[_-]?key',
    r'firefox[_-]?secret',
    r'firebase[_-]?token',
    r'firebase[_-]?project[_-]?develop',
    r'firebase[_-]?key',
    r'firebase[_-]?api[_-]?token',
    r'firebase[_-]?api[_-]?json',
    r'file[_-]?password',
    r'exp[_-]?password',
    r'eureka[_-]?awssecretkey',
    r'env[_-]?sonatype[_-]?password',
    r'env[_-]?secret[_-]?access[_-]?key',
    r'env[_-]?secret',
    r'env[_-]?key',
    r'env[_-]?heroku[_-]?api[_-]?key',
    r'env[_-]?github[_-]?oauth[_-]?token',
    r'end[_-]?user[_-]?password',
    r'encryption[_-]?password',
    r'elasticsearch[_-]?password',
    r'elastic[_-]?cloud[_-]?auth',
    r'dsonar[_-]?projectkey',
    r'dsonar[_-]?login',
    r'droplet[_-]?travis[_-]?password',
    r'dropbox[_-]?oauth[_-]?bearer',
    r'doordash[_-]?auth[_-]?token',
    r'dockerhubpassword',
    r'dockerhub[_-]?password',
    r'docker[_-]?token',
    r'docker[_-]?postgres[_-]?url',
    r'docker[_-]?password',
    r'docker[_-]?passwd',
    r'docker[_-]?pass',
    r'docker[_-]?key',
    r'docker[_-]?hub[_-]?password',
    r'digitalocean[_-]?ssh[_-]?key[_-]?ids',
    r'digitalocean[_-]?ssh[_-]?key[_-]?body',
    r'digitalocean[_-]?access[_-]?token',
    r'dgpg[_-]?passphrase',
    r'deploy[_-]?user',
    r'deploy[_-]?token',
    r'deploy[_-]?secure',
    r'deploy[_-]?password',
    r'ddgc[_-]?github[_-]?token',
    r'ddg[_-]?test[_-]?email[_-]?pw',
    r'ddg[_-]?test[_-]?email',
    r'db[_-]?username',
    r'db[_-]?user',
    r'db[_-]?pw',
    r'db[_-]?password',
    r'db[_-]?host',
    r'db[_-]?database',
    r'db[_-]?connection',
    r'datadog[_-]?app[_-]?key',
    r'datadog[_-]?api[_-]?key',
    r'database[_-]?username',
    r'database[_-]?user',
    r'database[_-]?port',
    r'database[_-]?password',
    r'database[_-]?name',
    r'database[_-]?host',
    r'danger[_-]?github[_-]?api[_-]?token',
    r'cypress[_-]?record[_-]?key',
    r'coverity[_-]?scan[_-]?token',
    r'coveralls[_-]?token',
    r'coveralls[_-]?repo[_-]?token',
    r'coveralls[_-]?api[_-]?token',
    r'cos[_-]?secrets',
    r'conversation[_-]?username',
    r'conversation[_-]?password',
    r'contentful[_-]?v2[_-]?access[_-]?token',
    r'contentful[_-]?test[_-]?org[_-]?cma[_-]?token',
    r'contentful[_-]?php[_-]?management[_-]?test[_-]?token',
    r'contentful[_-]?management[_-]?api[_-]?access[_-]?token[_-]?new',
    r'contentful[_-]?management[_-]?api[_-]?access[_-]?token',
    r'contentful[_-]?integration[_-]?management[_-]?token',
    r'contentful[_-]?cma[_-]?test[_-]?token',
    r'contentful[_-]?access[_-]?token',
    r'consumerkey',
    r'consumer[_-]?key',
    r'conekta[_-]?apikey',
    r'coding[_-]?token',
    r'codecov[_-]?token',
    r'codeclimate[_-]?repo[_-]?token',
    r'codacy[_-]?project[_-]?token',
    r'cocoapods[_-]?trunk[_-]?token',
    r'cocoapods[_-]?trunk[_-]?email',
    r'cn[_-]?secret[_-]?access[_-]?key',
    r'cn[_-]?access[_-]?key[_-]?id',
    r'clu[_-]?ssh[_-]?private[_-]?key[_-]?base64',
    r'clu[_-]?repo[_-]?url',
    r'cloudinary[_-]?url[_-]?staging',
    r'cloudinary[_-]?url',
    r'cloudflare[_-]?email',
    r'cloudflare[_-]?auth[_-]?key',
    r'cloudflare[_-]?auth[_-]?email',
    r'cloudflare[_-]?api[_-]?key',
    r'cloudant[_-]?service[_-]?database',
    r'cloudant[_-]?processed[_-]?database',
    r'cloudant[_-]?password',
    r'cloudant[_-]?parsed[_-]?database',
    r'cloudant[_-]?order[_-]?database',
    r'cloudant[_-]?instance',
    r'cloudant[_-]?database',
    r'cloudant[_-]?audited[_-]?database',
    r'cloudant[_-]?archived[_-]?database',
    r'cloud[_-]?api[_-]?key',
    r'clojars[_-]?password',
    r'client[_-]?secret',
    r'cli[_-]?e2e[_-]?cma[_-]?token',
    r'claimr[_-]?token',
    r'claimr[_-]?superuser',
    r'claimr[_-]?db',
    r'claimr[_-]?database',
    r'ci[_-]?user[_-]?token',
    r'ci[_-]?server[_-]?name',
    r'ci[_-]?registry[_-]?user',
    r'ci[_-]?project[_-]?url',
    r'ci[_-]?deploy[_-]?password',
    r'chrome[_-]?refresh[_-]?token',
    r'chrome[_-]?client[_-]?secret',
    r'cheverny[_-]?token',
    r'cf[_-]?password',
    r'certificate[_-]?password',
    r'censys[_-]?secret',
    r'cattle[_-]?secret[_-]?key',
    r'cattle[_-]?agent[_-]?instance[_-]?auth',
    r'cattle[_-]?access[_-]?key',
    r'cargo[_-]?token',
    r'cache[_-]?s3[_-]?secret[_-]?key',
    r'bx[_-]?username',
    r'bx[_-]?password',
    r'bundlesize[_-]?github[_-]?token',
    r'built[_-]?branch[_-]?deploy[_-]?key',
    r'bucketeer[_-]?aws[_-]?secret[_-]?access[_-]?key',
    r'bucketeer[_-]?aws[_-]?access[_-]?key[_-]?id',
    r'browserstack[_-]?access[_-]?key',
    r'browser[_-]?stack[_-]?access[_-]?key',
    r'brackets[_-]?repo[_-]?oauth[_-]?token',
    r'bluemix[_-]?username',
    r'bluemix[_-]?pwd',
    r'bluemix[_-]?password',
    r'bluemix[_-]?pass[_-]?prod',
    r'bluemix[_-]?pass',
    r'bluemix[_-]?auth',
    r'bluemix[_-]?api[_-]?key',
    r'bintraykey',
    r'bintray[_-]?token',
    r'bintray[_-]?key',
    r'bintray[_-]?gpg[_-]?password',
    r'bintray[_-]?apikey',
    r'bintray[_-]?api[_-]?key',
    r'b2[_-]?bucket',
    r'b2[_-]?app[_-]?key',
    r'awssecretkey',
    r'awscn[_-]?secret[_-]?access[_-]?key',
    r'awscn[_-]?access[_-]?key[_-]?id',
    r'awsaccesskeyid',
    r'aws[_-]?ses[_-]?secret[_-]?access[_-]?key',
    r'aws[_-]?ses[_-]?access[_-]?key[_-]?id',
    r'aws[_-]?secrets',
    r'aws[_-]?secret[_-]?key',
    r'aws[_-]?secret[_-]?access[_-]?key',
    r'aws[_-]?secret',
    r'aws[_-]?key',
    r'aws[_-]?config[_-]?secretaccesskey',
    r'aws[_-]?config[_-]?accesskeyid',
    r'aws[_-]?access[_-]?key[_-]?id',
    r'aws[_-]?access[_-]?key',
    r'aws[_-]?access',
    r'author[_-]?npm[_-]?api[_-]?key',
    r'author[_-]?email[_-]?addr',
    r'auth0[_-]?client[_-]?secret',
    r'auth0[_-]?api[_-]?clientsecret',
    r'auth[_-]?token',
    r'assistant[_-]?iam[_-]?apikey',
    r'artifacts[_-]?secret',
    r'artifacts[_-]?key',
    r'artifacts[_-]?bucket',
    r'artifacts[_-]?aws[_-]?secret[_-]?access[_-]?key',
    r'artifacts[_-]?aws[_-]?access[_-]?key[_-]?id',
    r'artifactory[_-]?key',
    r'argos[_-]?token',
    r'apple[_-]?id[_-]?password',
    r'appclientsecret',
    r'app[_-]?token',
    r'app[_-]?secrete',
    r'app[_-]?report[_-]?token[_-]?key',
    r'app[_-]?bucket[_-]?perm',
    r'apigw[_-]?access[_-]?token',
    r'apiary[_-]?api[_-]?key',
    r'api[_-]?secret',
    r'api[_-]?key[_-]?sid',
    r'api[_-]?key[_-]?secret',
    r'api[_-]?key',
    r'aos[_-]?sec',
    r'aos[_-]?key',
    r'ansible[_-]?vault[_-]?password',
    r'android[_-]?docs[_-]?deploy[_-]?token',
    r'anaconda[_-]?token',
    r'amazon[_-]?secret[_-]?access[_-]?key',
    r'amazon[_-]?bucket[_-]?name',
    r'alicloud[_-]?secret[_-]?key',
    r'alicloud[_-]?access[_-]?key',
    r'alias[_-]?pass',
    r'algolia[_-]?search[_-]?key[_-]?1',
    r'algolia[_-]?search[_-]?key',
    r'algolia[_-]?search[_-]?api[_-]?key',
    r'algolia[_-]?api[_-]?key[_-]?search',
    r'algolia[_-]?api[_-]?key[_-]?mcm',
    r'algolia[_-]?api[_-]?key',
    r'algolia[_-]?admin[_-]?key[_-]?mcm',
    r'algolia[_-]?admin[_-]?key[_-]?2',
    r'algolia[_-]?admin[_-]?key[_-]?1',
    r'air[-_]?table[-_]?api[-_]?key',
    r'adzerk[_-]?api[_-]?key',
    r'admin[_-]?email',
    r'account[_-]?sid',
    r'access[_-]?token',
    r'access[_-]?secret',
    r'access[_-]?key[_-]?secret',
    r'access[_-]?key',
    r'account[_-]?(name|key)?',
    r'password',
    r'username',
    # 6 个通配符模式 (HeartK lines 703-708)
    r'[\w_-]*?password[\w_-]*?',
    r'[\w_-]*?username[\w_-]*?',
    r'[\w_-]*?accesskey[\w_-]*?',
    r'[\w_-]*?secret[\w_-]*?',
    r'[\w_-]*?bucket[\w_-]*?',
    r'[\w_-]*?token[\w_-]*?',
    # 华为 OSS (HeartK line 710)
    r'huawei\.oss\.(ak|sk|bucket\.name|endpoint|local\.path)',
]

# 编译: 把 702 个 key name 合并为一个大正则 (性能远优于逐个匹配)
# 模板: ["']?KEY["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?
_NUCLEI_COMPILED = re.compile(
    r"""["']?(?:""" + '|'.join(_NUCLEI_KEY_NAMES) + r""")["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w\-]+["']?""",
    re.IGNORECASE
)

# 24 个特殊格式凭证正则 (1:1 移植自 HeartK background.js lines 709-737)
_SPECIAL_SECRETS = [
    # 私钥头 (line 709)
    re.compile(r"""["']?[-]+BEGIN \w+ PRIVATE KEY[-]+""", re.IGNORECASE),
    # 阿里云 AK (line 713)
    re.compile(r"""LTAI[A-Za-z\d]{12,30}"""),
    # 腾讯云 SecretId (line 714)
    re.compile(r"""AKID[A-Za-z\d]{13,40}"""),
    # 京东云 AK (line 715)
    re.compile(r"""JDC_[0-9A-Z]{25,40}"""),
    # AWS AK (line 716)
    re.compile(r"""(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"""),
    # 火山引擎 AK (line 717)
    re.compile(r"""(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}"""),
    # 火山引擎 AKLT 变体 (line 718)
    re.compile(r"""AKLT[a-zA-Z0-9\-_]{16,28}"""),
    # Google API key (line 719)
    re.compile(r"""AIza[0-9A-Za-z_\-]{35}"""),
    # Bearer token (line 720)
    re.compile(r"""[Bb]earer\s+[a-zA-Z0-9\-=._+/\\]{20,500}"""),
    # Basic auth (line 721)
    re.compile(r"""[Bb]asic\s+[A-Za-z0-9+/]{18,}={0,2}"""),
    # Authorization header (line 722)
    re.compile(r"""["'\[]*[Aa]uthorization["'\]]*\s*[:=]\s*['"]?\b(?:[Tt]oken\s+)?[a-zA-Z0-9\-_+/]{20,500}['"]?"""),
    # GitLab PAT (line 723)
    re.compile(r"""glpat-[a-zA-Z0-9\-=_]{20,22}"""),
    # GitHub tokens (line 724)
    re.compile(r"""(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255}"""),
    # APID (line 725)
    re.compile(r"""APID[a-zA-Z0-9]{32,42}"""),
    # 微信 AppID (line 726)
    re.compile(r"""["'](wx[a-z0-9]{15,18})["']"""),
    # 企业微信 CorpID (line 727)
    re.compile(r"""["'](ww[a-z0-9]{15,18})["']"""),
    # 微信公众号 GH ID (line 728)
    re.compile(r"""["'](gh_[a-z0-9]{11,13})["']"""),
    # 硬编码密码 (line 729)
    re.compile(
        r"""(?:admin_?pass|password|[a-z]{3,15}_?password|user_?pass|user_?pwd|admin_?pwd)"""
        r"""\\?['"]*\s*[:=]\s*\\?['"][a-z0-9!@#$%&*]{5,20}\\?['"]""", re.IGNORECASE),
    # 企业微信 webhook (line 730)
    re.compile(r"""https://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9\-]{25,50}""", re.IGNORECASE),
    # 钉钉 webhook (line 731)
    re.compile(r"""https://oapi\.dingtalk\.com/robot/send\?access_token=[a-z0-9]{50,80}""", re.IGNORECASE),
    # 飞书 webhook (line 732)
    re.compile(r"""https://open\.feishu\.cn/open-apis/bot/v2/hook/[a-z0-9\-]{25,50}""", re.IGNORECASE),
    # Slack webhook (line 733)
    re.compile(r"""https://hooks\.slack\.com/services/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{15,24}""", re.IGNORECASE),
    # Grafana API key (line 734)
    re.compile(r"""eyJrIjoi[a-zA-Z0-9\-_+/]{50,100}={0,2}"""),
    # Grafana Cloud token (line 735)
    re.compile(r"""glc_[A-Za-z0-9\-_+/]{32,200}={0,2}"""),
    # Grafana SA token (line 736)
    re.compile(r"""glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}"""),
]


# ══════════════════════════════════════════
#  分析函数
# ══════════════════════════════════════════

def _strip_quotes(items):
    """去除匹配结果前后的引号"""
    out = []
    for s in items:
        if isinstance(s, tuple):
            s = s[0]
        s = str(s)
        if s and s[0] in ("'", '"'):
            s = s[1:]
        if s and s[-1] in ("'", '"'):
            s = s[:-1]
        if s:
            out.append(s)
    return out


def analyze_js(js_content, max_len=2_000_000):
    """
    分析单个 JS 文件内容，提取敏感信息。
    """
    if len(js_content) > max_len:
        js_content = js_content[:max_len]

    result = {}

    # 1) 提取基础信息 (sfz, mobile, mail, ip, ip_port, domain, jwt, algorithm)
    for key, pat in _PATTERNS.items():
        if key == "algorithm":
            cleaned = list({m.group(1) for m in pat.finditer(js_content)})
        else:
            matches = pat.findall(js_content)
            cleaned = list(set(_strip_quotes(matches))) if matches else []
        result[key] = sorted(cleaned) if cleaned else []

    # 2) URL 提取 — 8 组新规则 (独立于 domain)
    url_set = set()
    for pat in _URL_PATTERNS:
        for m in pat.finditer(js_content):
            url_set.add(m.group(1).strip())

    # 3) 静态资源提取 — 8 组新规则 (独立提取)
    static_set = set()
    for pat in _STATIC_PATTERNS:
        for m in pat.finditer(js_content):
            v = m.group(1).strip()
            # 过滤源码文件后缀
            if not any(v.endswith(ext) for ext in _STATIC_FILTER_EXTS):
                static_set.add(v)

    # 4) 从 URL 结果中去除已匹配为静态资源的项
    url_set -= static_set

    # 5) 路径后处理: 去除 static/url 重复项、过滤噪音后缀、去除 http(s):// 开头的
    if result.get("path"):
        result["path"] = [
            p for p in result["path"]
            if p not in static_set
            and p not in url_set
            and not any(p.endswith(ext) for ext in _STATIC_FILTER_EXTS)
            and not p.startswith(("http://", "https://", "//"))
        ]

    # 6) 合并 domain 到 url
    if result["domain"]:
        url_set.update(result["domain"])
    result["url"] = sorted(url_set)
    result["static"] = sorted(static_set)

    # 6) secret 检测 — nuclei 规则
    secrets = set()
    for m in _NUCLEI_COMPILED.finditer(js_content):
        secrets.add(m.group(0).strip())
    for pat in _SPECIAL_SECRETS:
        for m in pat.finditer(js_content):
            secrets.add(m.group(0).strip())
    result["secret"] = sorted(secrets)

    # 7) OSS 云存储检测 — 从所有 URL 类结果中提取
    oss_set = set()
    for item in list(url_set) + list(static_set) + result.get("domain", []):
        if _OSS_DOMAIN_RE.search(item):
            oss_set.add(item)
    # 也直接扫描原文中的 OSS 域名
    for m in _OSS_DOMAIN_RE.finditer(js_content):
        oss_set.add(m.group(0))
    result["oss"] = sorted(oss_set)

    return result


def merge_results(results_list):
    """合并多个 analyze_js 结果。"""
    all_keys = list(CATEGORY_INFO.keys())
    merged = {k: [] for k in all_keys}
    for r in results_list:
        for k in all_keys:
            vals = r.get(k, [])
            if vals:
                merged[k].extend(vals)
    for k in all_keys:
        merged[k] = sorted(set(merged[k]))
    return merged


# ══════════════════════════════════════════
#  类别中文名 & 图标
# ══════════════════════════════════════════

CATEGORY_INFO = {
    "sfz":       ("身份证号", "\u2b24"),
    "mobile":    ("手机号码", "\u260e"),
    "mail":      ("邮箱地址", "\u2709"),
    "ip":        ("IP 地址", "\u2316"),
    "ip_port":   ("IP:端口", "\u2316"),
    "domain":    ("域名", "\u2b21"),
    "path":      ("路径", "\u2192"),
    "url":       ("URL 链接", "\u26d3"),
    "jwt":       ("JWT Token", "\u2b24"),
    "algorithm": ("加密算法", "\u2638"),
    "secret":    ("凭证泄露", "\u26a0"),
    "static":    ("静态资源", "\u25cb"),
    "oss":       ("OSS 云存储", "\u2601"),
}


# ══════════════════════════════════════════
#  历史记录
# ══════════════════════════════════════════

def _reports_dir(base_dir):
    d = os.path.join(base_dir, "scan_reports")
    os.makedirs(d, exist_ok=True)
    return d


def save_report(base_dir, appid, result, js_count=0, total_size=0, name=""):
    """保存分析报告到 scan_reports/ 目录"""
    report = {
        "appid": appid,
        "name": name,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "timestamp": int(time.time()),
        "js_count": js_count,
        "total_size": total_size,
        "result": result,
        "summary": {k: len(v) for k, v in result.items()},
    }
    d = _reports_dir(base_dir)
    fname = f"{appid}_{int(time.time())}.json"
    path = os.path.join(d, fname)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return path


def load_reports(base_dir):
    """加载所有历史报告，按时间降序"""
    d = _reports_dir(base_dir)
    reports = []
    for f in os.listdir(d):
        if not f.endswith(".json"):
            continue
        try:
            with open(os.path.join(d, f), "r", encoding="utf-8") as fp:
                r = json.load(fp)
                r["_filename"] = f
                reports.append(r)
        except Exception:
            pass
    reports.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    return reports


def delete_report(base_dir, filename):
    """删除指定报告"""
    path = os.path.join(_reports_dir(base_dir), filename)
    if os.path.exists(path):
        os.remove(path)
