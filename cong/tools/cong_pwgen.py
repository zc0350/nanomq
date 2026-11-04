#!/usr/bin/env python3
"""
生成与校验 cong 插件的 JSONL 规则文件。

这台开发机没有 C 编译器，但规则里要求的摘要必须算得出来、设备侧也必须能复现，
所以设备口令由本工具生成，插件侧由同一套规则的 C 实现校验。

  ./cong_pwgen.py digest --username dashboard --salt c0ng-2026 --alg sha256 --scheme salt+username
  ./cong_pwgen.py digest --username pump_0007 --clientid PUMP-0007 --salt pl4nt \
        --alg sha256 --scheme username+clientid+salt
  ./cong_pwgen.py digest --username abcde_device1 --salt d3v1c3 --alg sha256 \
        --scheme '%u1_%u2+salt' --username-regex '^([a-z]+)_([a-z0-9]+)$'
  ./cong_pwgen.py validate rules/auth.jsonl rules/acl.jsonl

"scheme" 是 username / clientid / salt 的任意有序组合，可重复，最长 8 段，
所以最早的三种拼法只是这个列表里的三个特例。加号是保留的分隔符，段内允许
下划线等任意字符；不是关键字的段按模板处理，%uN / %cN 引用 username / clientid
正则的第 N 个捕获组（%% 是字面百分号），分组值单独参与摘要。
摘要算法与拼接方式跟 C 侧 src/cong_digest.c、src/cong_auth.c 一一对应；
身份清洗跟 cong_sanitize_identity() 一一对应：sanitize=true 同时清洗 username
与 clientid，模板里替换进来的分组值也受同一个开关管，字面文本则不清洗。

validate 的判定口径就是"C 侧会不会加载这份文件"：重复键、有 "match" 却没有主体
字段、POSIX ERE 编译不过的正则，都会在这里报错误，因为它们都会让插件拒绝整份
文件。字符串 "true"/"false" 这类 C 侧接受的写法不算错误。正则引擎差异分两档：
ere_problems() 报的是任何 ERE 引擎都拒绝的写法，ere_advice() 提示的是能编译但
两边意思不同的写法（实测依据见 ere_problems() 的注释）。
"""

import argparse
import hashlib
import ipaddress
import json
import re
import sys

ALGORITHMS = {
	"md5": hashlib.md5,
	"sha1": hashlib.sha1,
	"sha256": hashlib.sha256,
	"sha512": hashlib.sha512,
}

# C 侧 enum cong_scheme_part 里整段就是关键字的三个因子，以及 CONG_SCHEME_MAX_PARTS。
FACTORS = ("username", "clientid", "salt")
MAX_SCHEME_PARTS = 8

AUTH_KEYS = {"username", "match", "clientid", "clientid_match", "ip",
		"salt", "alg", "scheme", "sanitize"}
ACL_KEYS = {"effect", "user", "match", "clientid", "clientid_match", "ip",
		"action", "topics"}
MATCH_KINDS = ("exact", "regex", "any")
ACTIONS = ("publish", "subscribe", "all")

# 与 C 侧 cong_sanitize_identity() 保持一致：只保留 [A-Za-z0-9]。
STRIPPED_RE = re.compile(r"[^A-Za-z0-9]+")

# C 侧 CONG_MAX_GROUPS - 1：捕获组 0 是整段匹配，%1..%9 才是分组。
MAX_REGEX_GROUPS = 9

# POSIX 的字符类名。写进规则的其他名字（"[[:word:]]" 之类）在 C 侧 regcomp() 会被拒。
POSIX_CLASSES = ("alnum", "alpha", "blank", "cntrl", "digit", "graph", "lower",
		"print", "punct", "space", "upper", "xdigit")

# "{n,m}" 区间：只有下限和上限同时存在时才谈得上谁大谁小。
INTERVAL_RE = re.compile(r"\{(\d+),(\d+)\}")


def scan_bracket(pattern, start):
	"""扫描一个 "[...]"，返回 (右括号之后的位置, 问题列表)；start 指向 "["。

	方括号里反斜杠不是转义符，所以按字面走位（C 侧同样是字面："[\\\\d]" 是反斜杠和
	d 两个字符）。紧跟 "[" 或 "[^" 的那个 "]" 也是字面右括号，不能当成结束。
	"""
	reasons = []
	i = start + 1
	if i < len(pattern) and pattern[i] == "^":
		i += 1
	if i < len(pattern) and pattern[i] == "]":
		i += 1
	while i < len(pattern):
		char = pattern[i]
		if char == "]":
			return i + 1, reasons
		if char == "[" and pattern.startswith(":", i + 1):
			end = pattern.find(":]", i + 2)
			if end < 0:
				break
			name = pattern[i + 2:end]
			if name not in POSIX_CLASSES:
				reasons.append('"[[:%s:]]" 不是 POSIX 字符类（可选 %s）'
						% (name, "/".join(POSIX_CLASSES)))
			i = end + 2
			continue
		if (pattern[i + 1:i + 2] == "-" and pattern[i + 2:i + 3] not in ("", "]")
				and ord(char) > ord(pattern[i + 2])):
			reasons.append('"[%s-%s]" 是倒序范围' % (char, pattern[i + 2]))
		i += 1
	# 没有右括号时 POSIX 把 "[" 当字面字符，两边一致，不算问题。
	return len(pattern), reasons


def ere_problems(pattern):
	"""POSIX ERE 里任何引擎都编译不过的写法，逐条对应 C 侧的整份文件拒绝。

	判定只收"合规 ERE 就不合法"的形状，不猜某个引擎的扩展。实测依据是目标机上
	.so 真正调用的那个 regcomp()（Ubuntu glibc 2.43，用 GNU find 的 -regex 走同一
	条路验证）：它拒绝 "(?" 系列（REG_BADRPT）、"{2,1}"（Invalid content of \\{\\}）、
	"[z-a]"（Invalid range end）、"[[:foo:]]"（Invalid character class name），
	而 "\\\\d"、"*?"、"++" 这类它照样编译通过（只是意思和 Python 不一样），
	所以那些归 ere_advice() 提示，不在这里报错。
	"""
	problems = []
	seen = set()

	def add(reason):
		if reason not in seen:
			seen.add(reason)
			problems.append(reason)

	i = 0
	while i < len(pattern):
		char = pattern[i]
		if char == "\\":
			# 反斜杠后面的字符按字面处理："\(" 不是分组，"\{" 也不是区间。
			i += 2
			continue
		if char == "[":
			i, reasons = scan_bracket(pattern, i)
			for reason in reasons:
				add(reason)
			continue
		if char == "(" and pattern[i + 1:i + 2] == "?":
			add('括号后面紧跟问号（%r）是 Perl/Python 的分组扩展，POSIX ERE 没有这种写法' % pattern[i:i + 3])
			i += 1
			continue
		match = INTERVAL_RE.match(pattern, i) if char == "{" else None
		if match:
			if int(match.group(1)) > int(match.group(2)):
				add('区间 %r 的下限大于上限' % match.group(0))
			i = match.end()
			continue
		i += 1
	return problems


def scan_topic_template(text):
	"""按 C 侧 topic_classify() / cong_topic_expand() 的同一套走法扫描主题模板。

	返回 (用到捕获组, 最高组号, 未识别的 %x 片段)。%% 是字面百分号，所以 "%%1"
	不算分组引用——这一点必须和 C 侧一致，否则校验器和插件的结论会分叉。
	"""
	needs_captures = False
	max_group = 0
	unknown = []
	i = 0
	while i < len(text):
		if text[i] != "%":
			i += 1
			continue
		nxt = text[i + 1] if i + 1 < len(text) else ""
		if nxt == "%":
			i += 2
			continue
		if nxt in ("c", "u"):
			i += 2
			continue
		if nxt and nxt in "0123456789":
			group = int(nxt)
			needs_captures = True
			if group > max_group:
				max_group = group
			i += 2
			continue
		unknown.append(text[i:i + 2])
		i += 1
	return needs_captures, max_group, unknown


def sanitize(text):
	return STRIPPED_RE.sub("", text)


def parse_scheme(text):
	"""把 "scheme" 拆成有序段，判定标准与 C 侧 cong_scheme_parse() 逐条对齐。

	加号是保留的分隔符，所以字面量里表达不出加号。每段要么是 username/clientid/salt
	关键字，要么是模板；空段（"username++salt"、结尾多写一个 +）、空串、超过 8 段，
	以及 %%、%uN、%cN 之外的百分号写法（"%u"、"%u0"、"%1"、"%x"）在 C 侧都会让
	整个文件加载失败，这里同样报错。
	"""
	if not isinstance(text, str):
		raise ValueError("\"scheme\" 必须是字符串")
	segments = text.split("+")
	if len(segments) > MAX_SCHEME_PARTS:
		raise ValueError("\"scheme\" 有 %d 段，C 侧上限是 %d 段" % (len(segments), MAX_SCHEME_PARTS))
	for seg in segments:
		if not seg:
			raise ValueError("\"scheme\" 里有空段（连续的加号或结尾多写一个）：%r" % text)
		if seg in FACTORS:
			continue
		_user, _client, bad = scan_scheme_template(seg)
		if bad:
			raise ValueError("\"scheme\" 段 %r 里的 %r 不是合法记号：模板只认百分号转义和 %%u1..%%u%d、%%c1..%%c%d"
					% (seg, bad[0], MAX_REGEX_GROUPS, MAX_REGEX_GROUPS))
	return segments


def scan_scheme_template(text):
	"""按 C 侧 scheme_token_at() 的同一套走法扫描一个 scheme 模板段。

	返回 (最高 %uN 组号, 最高 %cN 组号, 认不出的片段)。组号只有一位，所以 "%u12"
	是第 1 组后面跟着字面 "2"，与 C 侧一致；未参与的分组按空字符串拼接。
	"""
	max_user = 0
	max_client = 0
	bad = []
	i = 0
	while i < len(text):
		if text[i] != "%":
			i += 1
			continue
		if text[i + 1:i + 2] == "%":
			i += 2
			continue
		source = text[i + 1:i + 2]
		digit = text[i + 2:i + 3]
		# C 侧只认 ASCII 的 1..9，组号一位；isdigit() 会把 "²"、"٣" 这类字符也算数字，
		# 所以按字符表判定，别用一个 Python 的宽泛定义去代替它。
		if source not in ("u", "c") or digit not in "123456789":
			bad.append(text[i:i + 3])
			i += 1
			continue
		if source == "u":
			max_user = max(max_user, int(digit))
		else:
			max_client = max(max_client, int(digit))
		i += 3
	return max_user, max_client, bad


def scheme_usage(segments):
	"""与 C 侧 cong_scheme_usage() 对应：这条规则的摘要需要哪些身份、需要第几组。"""
	use = {"username": False, "clientid": False, "salt": False,
			"username_groups": 0, "clientid_groups": 0}
	for seg in segments:
		if seg in FACTORS:
			use[seg] = True
			continue
		max_user, max_client, _bad = scan_scheme_template(seg)
		if max_user:
			use["username"] = True
			use["username_groups"] = max(use["username_groups"], max_user)
		if max_client:
			use["clientid"] = True
			use["clientid_groups"] = max(use["clientid_groups"], max_client)
	return use


def factor_typo(seg):
	"""C 侧 scheme_text_factor_typo() 的同款判断：以因子名开头、但整段不是那个因子。
	"salt_x" 读作字面量而不是 salt 加下划线，"usernamee" 也一样只是个常量，所以只看
	前缀，不要求关键字后面紧跟分隔符。两边都只是告警，不拒文件：到底想写哪个，
	只有规则作者本人知道。"""
	for name in FACTORS:
		if seg.startswith(name) and len(seg) > len(name):
			return name
	return None


def ere_advice(pattern):
	r"""Python re 与 C 侧 POSIX ERE 的语义差异提示（写不写得出来归 ere_problems()）。

	下面这些形状在目标机的 regcomp() 上实测「能编译，但意思不一样」，所以只提示、
	不报错；但本工具算出的口令在这些规则上不等于插件认的那串字节，遇到就别当真：
	  \d \D      —— glibc 没有这个数字类，按字面字母 d / D 处理（Python 按数字处理）；
	  \w \W \s \S —— glibc 认这套 GNU 字符类，ASCII 范围内与 Python 一致，非 ASCII 不同；
	  \b \B \< \> \A \Z —— 边界类两边不是一套实现；
	  *? +? ?? }? 和 *+ ++ ?+ —— 能编译，但没有贪婪/非贪婪之分；
	  |          —— POSIX 取最左最长，Python 取最左最先，分组结果可能不同。
	"""
	notes = []
	if any(esc in pattern for esc in ("\\d", "\\D")):
		notes.append("\\d \\D 在 C 侧（glibc 实测）就是字面字母 d 和 D，不是数字类；"
				"要匹配数字请写 [0-9]，否则本工具算出的口令与插件算的不是同一条")
	elif any(esc in pattern for esc in ("\\w", "\\W", "\\s", "\\S", "\\b", "\\B", "\\A", "\\Z")):
		notes.append("\\w \\s \\b \\A 这类反斜杠写法不是 POSIX ERE 的标准部分，"
				"C 侧按哪种引擎的实现解释取决于目标机，上机前用 C 侧单测复核一次")
	if any(tok in pattern for tok in ("*?", "+?", "??", "}?")):
		notes.append("非贪婪量词不是 POSIX ERE，C 侧只有最左最长")
	if any(tok in pattern for tok in ("*+", "++", "?+")):
		notes.append("独占量词（*+ ++ ?+）不是 POSIX ERE，C 侧没有这个概念")
	if "|" in pattern:
		notes.append("含选择符 |：POSIX 取最左最长，Python re 取最左最先，分组结果可能不同，"
				"上机前用 C 侧单测复核一次")
	return notes


def capture_groups(pattern, value, flag):
	"""按规则里的正则把身份切成分组，对应 C 侧的 regexec()。"""
	if pattern is None:
		return None
	if value is None:
		return None
	match = re.compile(pattern).search(value)
	if match is None:
		raise ValueError("--%s=%r 匹配不上 %r：这条规则在 C 侧连候选都排不上，口令无从算起"
				% (flag.strip("-"), value, pattern))
	return (pattern, match.groups())


def render_segment(seg, do_sanitize, captures):
	"""按 C 侧 cong_scheme_text_build() 渲染一个模板段，返回 (文本, 人话说明)。

	清洗只作用于替换进来的分组值：字面文本里写下划线是为了当分隔符，一起清洗就把
	自己删掉了。可选分组没有参与匹配时按空字符串拼接，与 C 侧同一口径。
	"""
	out = ""
	shapes = []
	i = 0
	while i < len(seg):
		if seg[i] != "%":
			out += seg[i]
			i += 1
			continue
		if seg[i + 1:i + 2] == "%":
			out += "%"
			i += 2
			continue
		source = seg[i + 1:i + 2]
		group = int(seg[i + 2:i + 3])
		who = "username" if source == "u" else "clientid"
		token = "%s%d" % (source, group)
		if captures[source] is None:
			raise ValueError("模板 %r 用了 %%%s，但没有给出 --%s-regex（分组只能来自规则里的正则）"
					% (seg, token, who))
		pattern, values = captures[source]
		if group > len(values):
			raise ValueError("模板 %r 引用了第 %d 组，%r 只有 %d 个捕获组" % (seg, group, pattern, len(values)))
		text = values[group - 1]
		if text is None:
			text = ""
		kept = sanitize(text) if do_sanitize else text
		out += kept
		shapes.append("%%%s=%r" % (token, kept))
		i += 3
	return out, "%s -> %r" % (seg, out)


def identity(text, do_sanitize):
	"""清洗一个身份字段；None 表示连接上根本没带这个字段。"""
	if text is None:
		return None
	return sanitize(text) if do_sanitize else text


def preimage(segments, username, clientid, salt, do_sanitize,
		username_regex=None, clientid_regex=None):
	"""按 C 侧 auth_rule_verifies() 的同一顺序拼出待摘要字节串，附带一段人话说明。

	salt 永远按字面参与摘要，sanitize 只作用于身份：整段身份是 username/clientid 关键字，
	分组值在模板里，字面文本不清洗。
	"""
	values = {"username": identity(username, do_sanitize),
			"clientid": identity(clientid, do_sanitize),
			"salt": salt}
	captures = {"u": capture_groups(username_regex, username, "--username-regex"),
			"c": capture_groups(clientid_regex, clientid, "--clientid-regex")}
	data = b""
	shapes = []
	for seg in segments:
		if seg in FACTORS:
			value = values[seg]
			if value is None:
				raise ValueError("scheme 用了 %s，但没有给出它的值" % seg)
			data += value.encode("utf-8")
			shapes.append("%s=%r" % (seg, value))
			continue
		text, shape = render_segment(seg, do_sanitize, captures)
		data += text.encode("utf-8")
		shapes.append(shape)
	return data, "H(" + " + ".join(shapes) + ")"


def no_duplicate_keys(pairs):
	"""json.loads 的 object_pairs_hook：一行规则里同名的键出现两次就报错。

	重复键是合法 JSON，但两边读法不同：C 侧 cJSON_GetObjectItem() 取第一个，Python
	取最后一个。于是"加载进去的规则"和"校验器算口令的规则"可能不是同一条，所以 C 侧
	现在直接拒绝这种记录（src/cong_util.c 的 cong_json_check_keys()），这里同步拒绝。
	"""
	seen = set()
	for key, _value in pairs:
		if key in seen:
			raise ValueError('键 "%s" 在这条规则里出现了两次：C 侧读第一个、常规解析器读最后一个，'
					'两边看到的不是同一条规则，C 侧会拒绝加载整个文件' % key)
		seen.add(key)
	return dict(pairs)


def json_bool(value):
	"""C 侧 cong_json_bool() 的同款判定：JSON 布尔值，以及字符串 "true"/"false"。

	插件对这两种写法一视同仁，所以校验器也不能把 "sanitize": "false" 判成错误。
	"""
	if isinstance(value, bool):
		return value
	if value == "true":
		return True
	if value == "false":
		return False
	return None


def read_records(path):
	"""一行一个 JSON 对象；空行与 # 开头的行跳过，与 C 侧一致。"""
	records = []
	with open(path, "r", encoding="utf-8") as handle:
		for lineno, line in enumerate(handle, start=1):
			stripped = line.strip()
			if not stripped or stripped.startswith("#"):
				continue
			try:
				record = json.loads(stripped, object_pairs_hook=no_duplicate_keys)
			except json.JSONDecodeError as exc:
				raise SystemExit("%s:%d: 不是合法 JSON：%s" % (path, lineno, exc))
			except ValueError as exc:
				raise SystemExit("%s:%d: %s" % (path, lineno, exc))
			if not isinstance(record, dict):
				raise SystemExit("%s:%d: 每行必须是一个 JSON 对象" % (path, lineno))
			records.append((lineno, record))
	return records


def check_ip(value, path, lineno, errors):
	try:
		if "/" in value:
			ipaddress.ip_network(value, strict=False)
		else:
			ipaddress.ip_address(value)
	except ValueError:
		errors.append('%s:%d: "ip" 不是合法 IP 或 CIDR：%r（C 侧会拒绝加载整个文件）' % (path, lineno, value))


def check_subjects(record, keys, path, lineno, errors, notes):
	"""身份字段与它的 "match"，判定与 C 侧 cong_subject_from_json() 逐条对齐。

	C 侧那边一个字段的两条硬规则都在这里镜像：有 "match" 却没有主体字段是"不知道该
	把 match 用在谁身上"，直接拒整份文件；"match": "regex" 的值要过 regcomp()，编译
	不过同样拒整份文件。Python 能编译不等于 ERE 能编译，所以两边各自查一遍。
	"""
	for key, match_key in keys:
		value = record.get(key)
		if value is None:
			if match_key in record:
				errors.append('%s:%d: 有 "%s" 却没有 "%s"：这个 match 无处可用'
						'（C 侧会拒绝加载整个文件）' % (path, lineno, match_key, key))
			continue
		if not isinstance(value, str):
			errors.append('%s:%d: "%s" 必须是字符串' % (path, lineno, key))
			continue
		kind = record.get(match_key, "exact")
		if kind not in MATCH_KINDS:
			errors.append('%s:%d: "%s" 只能是 exact/regex/any，实际是 %r' % (path, lineno, match_key, kind))
		elif kind == "regex":
			try:
				re.compile(value)
			except re.error as exc:
				# C 侧用 POSIX ERE（regcomp REG_EXTENDED），这里只能借 Python 近似检查：
				# 两边不严格等价（POSIX 允许紧跟 "[" 的 "]"，Python 不允许），所以真机上
				# 能不能加载要以 C 侧为准。
				errors.append('%s:%d: "%s" 无法编译为正则（本工具借 Python re 检查 C 侧的 POSIX ERE，'
						'要确认可用 make check 或上机加载）：%s' % (path, lineno, key, exc))
			else:
				for problem in ere_problems(value):
					errors.append('%s:%d: "%s" %s，C 侧的 POSIX ERE 同样不接受（会拒绝加载整个文件）'
							% (path, lineno, key, problem))
				for advice in ere_advice(value):
					notes.append('%s:%d: 提示："%s" %s' % (path, lineno, key, advice))
		elif kind == "any" and value != "*":
			notes.append('%s:%d: 提示："%s": "any" 已经放行任意身份，"%s" 的值在 C 侧不参与匹配'
					% (path, lineno, match_key, key))
		if match_key in record and value == "*":
			errors.append('%s:%d: "%s" 是 "*" 已经表示任意，"%s" 会被 C 侧忽略' % (path, lineno, key, match_key))


def literal_subject(record, key, match_key):
	"""规则里写成字面量的身份字段，否则返回 None。

	只有字面量才预先算得出设备口令：正则要等真实连接上来才知道参与摘要的到底是哪段文本。
	"""
	value = record.get(key)
	if not isinstance(value, str) or value == "*":
		return None
	if record.get(match_key, "exact") != "exact":
		return None
	return value


def account_label(use, literals):
	return " ".join("%s=%r" % (name, literals[name]) for name in ("username", "clientid") if use[name])


def subject_groups(record, key, match_key):
	"""规则里这个身份字段的捕获组数；不是 "match": "regex" 时返回 None。"""
	value = record.get(key)
	if not isinstance(value, str) or record.get(match_key, "exact") != "regex":
		return None
	try:
		return re.compile(value).groups
	except re.error:
		return None  # check_subjects 已经报过语法错


def scheme_group_problems(record, segments, path, lineno):
	"""模板对身份字段的要求，与 C 侧 auth_rule_cb() 的装载期校验一一对应：
	引用了 %uN / %cN 就必须是捕获组足够的正则，否则插件拒绝加载整个文件。

	返回 (硬错误, 提示)。分组口令只能按真实连接值算，所以正则本身没问题时只提示。
	"""
	errors = []
	notes = []
	use = scheme_usage(segments)
	for who, key, match_key, groups, regex_flag in (
			("username", "username", "match", use["username_groups"], "username-regex"),
			("clientid", "clientid", "clientid_match", use["clientid_groups"], "clientid-regex")):
		if not groups:
			continue
		available = subject_groups(record, key, match_key)
		token = "%%%s%d" % ("u" if who == "username" else "c", groups)
		if available is None:
			errors.append('%s:%d: "scheme" 用了 %s，但 "%s" 不是 "match": "regex"，没有可捕获的内容（C 侧会拒绝加载整个文件）'
					% (path, lineno, token, key))
		elif available > MAX_REGEX_GROUPS:
			# 引用了分组 = C 侧编译这个正则时要保留捕获信息，那里同样有 9 组上限。
			errors.append('%s:%d: "scheme" 用了 %s，"%s" 正则有 %d 个捕获组，C 侧上限是 %d（会拒绝加载整个文件）'
					% (path, lineno, token, key, available, MAX_REGEX_GROUPS))
		elif groups > available:
			errors.append('%s:%d: "scheme" 用了 %s，但 "%s" 正则只有 %d 个捕获组（C 侧会拒绝加载整个文件）'
					% (path, lineno, token, key, available))
		else:
			notes.append('%s:%d: 提示：scheme 按分组拼接，设备口令取决于连接上报的 %s；用真实值跑 '
					'digest --scheme %s --%s <真实值> --%s %r'
					% (path, lineno, who, shell_quote_scheme(record.get("scheme")), who, regex_flag,
						record.get(key)))
	for seg in segments:
		if seg in FACTORS:
			continue
		# 与 C 侧同一道闸门：段里已经引用了分组，就不再猜它是「关键字混进字面段」。
		max_user, max_client, _bad = scan_scheme_template(seg)
		if not max_user and not max_client:
			typo = factor_typo(seg)
			if typo:
				notes.append('%s:%d: 提示："scheme" 段 %r 是字面文本，不是它开头的那个因子；想表达 %s 再加其余内容'
						'就拆成两段（%s+%s）。C 侧装载时同样会告警'
						% (path, lineno, seg, typo, typo, seg[len(typo):]))
	# 模板段本身是字面文本，不进 regcomp()：正则风险只来自提供分组的那个
	# "username"/"clientid" 字段，那两个字段由 check_subjects() 负责提示。
	return errors, notes


def shell_quote_scheme(scheme):
	"""把 scheme 原样回显成一条能直接粘的命令行参数（模板里带 % 和下划线）。"""
	return "'%s'" % scheme if any(c in scheme for c in "%_") else scheme


def validate_auth(path):
	errors = []
	notes = []
	records = read_records(path)
	seen = {}

	for lineno, record in records:
		unknown = sorted(set(record) - AUTH_KEYS)
		if unknown:
			errors.append('%s:%d: 未知字段 %s（拼错的字段会让 C 侧拒绝加载）' % (path, lineno, unknown))

		check_subjects(record, (("username", "match"), ("clientid", "clientid_match")),
				path, lineno, errors, notes)
		if "ip" in record:
			if not isinstance(record["ip"], str):
				errors.append('%s:%d: "ip" 必须是字符串' % (path, lineno))
			else:
				check_ip(record["ip"], path, lineno, errors)

		for key in ("salt", "alg", "scheme"):
			if key not in record:
				errors.append('%s:%d: 缺少必填字段 "%s"' % (path, lineno, key))

		alg = record.get("alg")
		if alg is not None and alg not in ALGORITHMS:
			errors.append('%s:%d: "alg" 必须是 %s，实际是 %r' % (path, lineno, "/".join(sorted(ALGORITHMS)), alg))
		segments = None
		scheme = record.get("scheme")
		if scheme is not None:
			try:
				segments = parse_scheme(scheme)
			except ValueError as exc:
				errors.append('%s:%d: %s（C 侧会拒绝加载整个文件）' % (path, lineno, exc))
		if segments is not None:
			group_errors, group_notes = scheme_group_problems(record, segments, path, lineno)
			errors.extend(group_errors)
			notes.extend(group_notes)
		use = scheme_usage(segments) if segments is not None else None
		do_sanitize = json_bool(record.get("sanitize", True))
		if do_sanitize is None:
			errors.append('%s:%d: "sanitize" 只能是 true、false 或字符串 "true"/"false"，实际是 %r'
					% (path, lineno, record.get("sanitize")))
			do_sanitize = True
		if not isinstance(record.get("salt"), str):
			continue
		if use is not None and not use["salt"]:
			notes.append('%s:%d: 提示："scheme" 里没有 salt，这条规则的 "salt" 是死配置（C 侧装载时同样会告警）' % (path, lineno))
		if use is not None and not use["username"] and not use["clientid"]:
			notes.append('%s:%d: 提示："scheme" 既不含 username 也不含 clientid，这条规则下所有设备共用同一个口令'
					'（C 侧装载时同样会告警）' % (path, lineno))

		if alg not in ALGORITHMS or segments is None:
			continue
		literals = {"username": literal_subject(record, "username", "match"),
				"clientid": literal_subject(record, "clientid", "clientid_match")}
		# C 侧对参与摘要的身份只认「非空」：连接没带这个字段、或带上来的是空串，都算没上报，
		# 规则到不了摘要比较那一步（cong_auth.c 的 auth_factor_present()）。
		dead_factors = [name for name in ("username", "clientid")
				if use[name] and literals[name] == ""]
		if dead_factors:
			for name in dead_factors:
				notes.append('%s:%d: 提示："%s" 是空串，而 "scheme" 又要用它算摘要：C 侧把空身份当作'
						'「连接没上报」，这条规则永远验不过，所以这里不打印口令' % (path, lineno, name))
			continue
		unknown_factors = [name for name in ("username", "clientid")
				if use[name] and literals[name] is None]
		if unknown_factors:
			# 正则 username 是本插件的常规用法，过去也不打印口令，不必每次提示；
			# clientid 参与摘要时才有必要说明它取决于连接上报的值。分组拼接的情况
			# scheme_group_problems() 已经给出更具体的命令，不重复提示。
			if "clientid" in unknown_factors and not use["clientid_groups"]:
				notes.append('%s:%d: 提示：scheme 用了 clientid，但它不是字面量，设备口令取决于连接上报的 client_id；'
						'要用真实值跑 digest --scheme %s --clientid ...' % (path, lineno, scheme))
			continue
		try:
			data, shape = preimage(segments, literals["username"], literals["clientid"],
					record["salt"], do_sanitize)
		except ValueError as exc:
			errors.append('%s:%d: %s' % (path, lineno, exc))
			continue
		digest = ALGORITHMS[alg](data).hexdigest()
		notes.append("%s:%d  %s  ->  设备口令 %s   [%s]" % (
				path, lineno, account_label(use, literals), digest, shape))

		username = record.get("username")
		if isinstance(username, str) and username != "*" and record.get("match", "exact") == "exact":
			if username in seen:
				notes.append("%s:%d  提示：%s 与第 %d 行同名，登录时两条都会试，任一摘要命中即通过" % (
						path, lineno, username, seen[username]))
			else:
				seen[username] = lineno

	if not records:
		errors.append("%s: 没有任何规则，所有登录都会被拒绝" % path)
	return errors, notes


def validate_acl(path):
	errors = []
	notes = []
	records = read_records(path)
	catch_all_line = None

	for index, (lineno, record) in enumerate(records):
		unknown = sorted(set(record) - ACL_KEYS)
		if unknown:
			errors.append('%s:%d: 未知字段 %s' % (path, lineno, unknown))

		effect = record.get("effect")
		if effect not in ("allow", "deny"):
			errors.append('%s:%d: "effect" 必须是 allow 或 deny，实际是 %r' % (path, lineno, effect))

		check_subjects(record, (("user", "match"), ("clientid", "clientid_match")),
				path, lineno, errors, notes)
		if "ip" in record:
			if not isinstance(record["ip"], str):
				errors.append('%s:%d: "ip" 必须是字符串' % (path, lineno))
			else:
				check_ip(record["ip"], path, lineno, errors)

		action = record.get("action", "all")
		if action not in ACTIONS:
			errors.append('%s:%d: "action" 必须是 %s，实际是 %r' % (path, lineno, "/".join(ACTIONS), action))

		topics = record.get("topics")
		needs_captures = False
		max_group = 0
		if topics is not None:
			if not isinstance(topics, list) or not topics:
				errors.append('%s:%d: "topics" 必须是非空数组；要表达"任意主题"请删掉该字段' % (path, lineno))
			else:
				for topic in topics:
					if isinstance(topic, str):
						topic_texts = [topic]
					elif isinstance(topic, dict) and set(topic) == {"eq"} and isinstance(topic.get("eq"), str):
						topic_texts = [topic["eq"]]
					else:
						errors.append('%s:%d: "topics" 元素必须是字符串或 {"eq": "..."}，实际是 %r' % (path, lineno, topic))
						continue
					for text in topic_texts:
						captures, group, unknown = scan_topic_template(text)
						needs_captures = needs_captures or captures
						if group > max_group:
							max_group = group
						for token in unknown:
							notes.append('%s:%d: 提示：主题 %r 里的 "%s" 不是本插件认识的记号，会按字面保留（要表达百分号请写%%%%）' % (
									path, lineno, text, token))

		# 模板记号对 "user" 的要求，与 C 侧 acl_rule_cb() 的装载期校验一一对应：
		# 引用了 %0..%9 就必须是带分组（或整体匹配）的正则，否则插件拒绝加载整个文件。
		if needs_captures:
			user = record.get("user")
			if record.get("match", "exact") != "regex" or not isinstance(user, str):
				errors.append('%s:%d: "topics" 用了 %%0..%%9 分组引用，但 "user" 不是 "match": "regex"，没有可捕获的内容' % (path, lineno))
			else:
				try:
					group_count = re.compile(user).groups
				except re.error:
					group_count = None  # check_subjects 已经报过语法错
				if group_count is not None:
					if group_count > MAX_REGEX_GROUPS:
						errors.append('%s:%d: "user" 正则有 %d 个捕获组，C 侧上限是 %d（会拒绝加载）' % (
								path, lineno, group_count, MAX_REGEX_GROUPS))
					if max_group > group_count:
						errors.append('%s:%d: "topics" 引用了 %%%d，但 "user" 正则（%r）只有 %d 个捕获组' % (
								path, lineno, max_group, user, group_count))

		catch_all = (effect in ("allow", "deny")
				and not ({"user", "clientid", "ip", "topics"} & set(record))
				and action == "all")
		if catch_all:
			if catch_all_line is None:
				catch_all_line = lineno
			if index != len(records) - 1:
				errors.append("%s:%d: 这条无条件 %s 兜底规则使得它之后 %d 条规则永远不可能命中" % (
						path, lineno, effect, len(records) - index - 1))

	if not records:
		errors.append("%s: 没有任何规则，所有发布与订阅都会被拒绝" % path)
	elif catch_all_line is None:
		notes.append("%s: 提示：没有兜底规则，未命中任何规则时插件一律拒绝" % path)
	return errors, notes


def command_digest(args):
	try:
		segments = parse_scheme(args.scheme)
	except ValueError as exc:
		raise SystemExit(exc)
	do_sanitize = not args.no_sanitize
	use = scheme_usage(segments)
	values = {"username": args.username, "clientid": args.clientid, "salt": args.salt}
	regexes = {"username": args.username_regex, "clientid": args.clientid_regex}

	for name in FACTORS:
		if use[name] and values[name] is None:
			raise SystemExit("scheme 用了 %s，但命令行没有给出 --%s" % (name, name))
	for name in ("username", "clientid"):
		# 空串在 C 侧等同「连接没上报」，按它算出来的口令插件永远不会认。
		if use[name] and values[name] == "":
			raise SystemExit("scheme 用了 %s，但 --%s 是空串：C 侧把空身份当作「连接没上报」，"
					"这条口令在插件那边验不过" % (name, name))
	for name in ("username", "clientid"):
		if regexes[name] is not None:
			for problem in ere_problems(regexes[name]):
				print("注意: %s 的正则%s，C 侧的 POSIX ERE 不接受（插件会拒绝加载整份规则文件）" % (name, problem))
			for note in ere_advice(regexes[name]):
				print("注意: %s 的正则%s" % (name, note))
			try:
				group_count = re.compile(regexes[name]).groups
			except re.error:
				group_count = None  # 再往下 capture_groups() 会给出这条正则的错
			if group_count is not None and use[name + "_groups"] and group_count > MAX_REGEX_GROUPS:
				print("注意: %s 的正则有 %d 个捕获组，C 侧上限是 %d（scheme 按分组引用了它，"
						"插件会拒绝加载整份规则文件）" % (name, group_count, MAX_REGEX_GROUPS))
		elif use[name + "_groups"]:
			raise SystemExit("scheme 按分组引用了 %s，必须给出 --%s-regex：它就是规则里那个字段的正则"
					% (name, name))

	try:
		for name in FACTORS:
			if not use[name]:
				continue
			raw = values[name]
			if name == "salt":
				# C 侧直接用 rule->salt，sanitize 从不碰它。
				print("salt 原文     : %r（salt 不参与清洗）" % raw)
				continue
			if any(seg == name for seg in segments):
				cleaned = identity(raw, do_sanitize)
				note = "  (sanitize=true，特殊字符已删除)" if do_sanitize and cleaned != raw else ""
				print("%s 原文    : %r -> %r%s" % (name, raw, cleaned, note))
			else:
				print("%s 原文    : %r（只按分组参与摘要，整段原文不进摘要）" % (name, raw))
			if regexes[name] is not None:
				_captures, groups = capture_groups(regexes[name], raw, "--%s-regex" % name)
				print("%s 分组    : %s" % (name, ", ".join("%%%s%d=%r" % ("u" if name == "username" else "c", i, v)
						for i, v in enumerate(groups, start=1))))
		data, shape = preimage(segments, args.username, args.clientid, args.salt, do_sanitize,
				regexes["username"], regexes["clientid"])
	except ValueError as exc:
		raise SystemExit(exc)
	digest = ALGORITHMS[args.alg](data).hexdigest()

	print("摘要输入     : %s" % shape)
	print("设备口令     : %s" % digest)
	print("大写也可     : %s" % digest.upper())
	print("hex 长度     : %d 字符 = %d 字节" % (len(digest), len(digest) // 2))


def main():
	parser = argparse.ArgumentParser(description="cong mosquitto 插件的规则生成与校验")
	sub = parser.add_subparsers(dest="command", required=True)

	digest = sub.add_parser("digest", help="算出设备应该上报的口令")
	digest.add_argument("--username", help="CONNECT 报文里的 username 原文；scheme 不含 username 时可省略")
	digest.add_argument("--clientid", help="CONNECT 报文里的 client_id 原文；scheme 含 clientid 时必填")
	digest.add_argument("--username-regex",
			help='规则里 "username" 的正则；scheme 用 %%uN 分组时必填，取它的第 N 个捕获组')
	digest.add_argument("--clientid-regex",
			help='规则里 "clientid" 的正则；scheme 用 %%cN 分组时必填')
	digest.add_argument("--salt", required=True)
	digest.add_argument("--alg", required=True, choices=sorted(ALGORITHMS))
	digest.add_argument("--scheme", required=True,
			help="username / clientid / salt 的有序组合，例如 salt+username、username+clientid+salt，"
				"或按分组拼接的模板，例如 %%u1_%%u2+salt、%%c2+%%c1+salt")
	digest.add_argument("--no-sanitize", action="store_true",
			help='等同规则里的 "sanitize": false，username 与 clientid 都保留特殊字符')
	digest.set_defaults(handler=command_digest)

	check = sub.add_parser("validate", help="校验规则文件，并打印字面账号应有的设备口令")
	check.add_argument("files", nargs="+")
	check.set_defaults(handler=None)

	args = parser.parse_args()

	if args.handler is not None:
		args.handler(args)
		return

	errors = []
	notes = []
	for path in args.files:
		if "acl" in path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]:
			these_errors, these_notes = validate_acl(path)
		else:
			these_errors, these_notes = validate_auth(path)
		errors += these_errors
		notes += these_notes

	for note in notes:
		print(note)
	if errors:
		for message in errors:
			print("错误: " + message, file=sys.stderr)
		raise SystemExit(1)
	print("OK: %d 个文件全部通过" % len(args.files))


main()
