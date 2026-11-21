//
//  IPOpsec.swift — 单文件版（方便直接在 GitHub 网页新建后上传）
//  代理配置 / 出口自检 / 泄漏检测 / 代理池健康检查 / 报告导出
//  目标: iOS 15.0+，可被 TrollStore 以 ldid 伪签名安装
//

import SwiftUI
import UIKit
import Foundation
import Darwin

// MARK: - 模型

enum ProxyKind: String, Codable, CaseIterable, Identifiable {
    case direct, http, socks5
    var id: String { rawValue }
    var label: String {
        switch self {
        case .direct: return "直连（基线）"
        case .http:   return "HTTP / HTTPS"
        case .socks5: return "SOCKS5"
        }
    }
    var short: String {
        switch self {
        case .direct: return "DIRECT"
        case .http:   return "HTTP"
        case .socks5: return "SOCKS5"
        }
    }
}

struct ProxyEntry: Identifiable, Codable, Hashable {
    var id: UUID = UUID()
    var name: String = ""
    var kind: ProxyKind = .socks5
    var host: String = ""
    var port: Int = 1080
    var username: String = ""
    var password: String = ""
    var enabled: Bool = true

    var lastLatency: Int? = nil
    var lastEgress: String? = nil
    var lastOK: Bool? = nil

    var endpoint: String {
        guard kind != .direct else { return "direct" }
        let auth = username.isEmpty ? "" : "\(username)@"
        return "\(kind.short.lowercased())://\(auth)\(host):\(port)"
    }

    static func == (l: ProxyEntry, r: ProxyEntry) -> Bool { l.id == r.id }
    func hash(into h: inout Hasher) { h.combine(id) }
}

struct ProbeResult: Identifiable, Codable {
    var id: UUID = UUID()
    var time: Date = Date()
    var kind: String
    var proxy: String
    var ok: Bool
    var headline: String
    var detail: [String] = []
    var latencyMs: Int? = nil

    var summaryLine: String { "\(ok ? "OK " : "FAIL ")\(kind) · \(proxy) · \(headline)" }
}

struct ReportBundle: Codable {
    var generatedAt: Date = Date()
    var device: String
    var results: [ProbeResult]
    var proxies: [ProxyEntry]

    func markdown() -> String {
        var out = "# IP Opsec 自检报告\n\n"
        out += "- 生成时间: \(ISO8601DateFormatter().string(from: generatedAt))\n"
        out += "- 设备: \(device)\n"
        out += "- 条目: \(results.count)\n\n"
        out += "## 代理配置\n\n"
        if proxies.isEmpty {
            out += "_无_\n\n"
        } else {
            out += "| 名称 | 类型 | 端点 | 状态 | 出口 | 延迟 |\n|---|---|---|---|---|---|\n"
            for p in proxies {
                let st: String
                switch p.lastOK {
                case .some(true): st = "可用"
                case .some(false): st = "失败"
                case .none: st = "未测"
                }
                out += "| \(p.name) | \(p.kind.short) | \(p.host):\(p.port) | \(st) | \(p.lastEgress ?? "-") | \(p.lastLatency.map { "\($0) ms" } ?? "-") |\n"
            }
            out += "\n"
        }
        out += "## 探测结果\n\n"
        for r in results {
            out += "### \(r.ok ? "✅" : "❌") \(r.kind) — \(r.proxy)\n\n**\(r.headline)**\n\n"
            for d in r.detail { out += "- \(d)\n" }
            out += "\n"
        }
        out += "## 判读要点\n\n"
        out += "1. 出口 IP 必须与直连基线不同，相同说明代理未生效。\n"
        out += "2. 请求头出现 X-Forwarded-For / X-Real-IP / Client-IP 即为主动上报。\n"
        out += "3. 同一出口 IP 反复出现 = 代理池复用，抗封禁能力差。\n"
        out += "4. 时区/语言与出口国家不一致会被指纹聚类。\n"
        return out
    }
}

enum Fmt {
    static let time: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()
    static func now() -> String { time.string(from: Date()) }
    static func bytes(_ n: Int) -> String {
        if n < 1024 { return "\(n) B" }
        if n < 1024 * 1024 { return String(format: "%.1f KB", Double(n) / 1024) }
        return String(format: "%.1f MB", Double(n) / 1048576)
    }
}

// MARK: - 存储

@MainActor
final class ProxyStore: ObservableObject {
    @Published var entries: [ProxyEntry] = [] { didSet { persist() } }

    private let defaultsKey = "ipopsec.proxies.single.v1"
    private var loading = false

    init() {
        load()
        if entries.isEmpty { entries = [Self.baseline] }
    }

    static var baseline: ProxyEntry {
        ProxyEntry(name: "直连基线", kind: .direct, host: "", port: 0)
    }

    private func load() {
        loading = true
        defer { loading = false }
        guard let data = UserDefaults.standard.data(forKey: defaultsKey),
              let list = try? JSONDecoder().decode([ProxyEntry].self, from: data) else { return }
        entries = list
    }

    private func persist() {
        guard !loading else { return }
        if let data = try? JSONEncoder().encode(entries) {
            UserDefaults.standard.set(data, forKey: defaultsKey)
        }
    }

    func add(_ e: ProxyEntry) { entries.append(e) }

    func update(_ e: ProxyEntry) {
        if let i = entries.firstIndex(where: { $0.id == e.id }) {
            entries[i] = e
        } else {
            entries.append(e)
        }
    }

    func remove(_ e: ProxyEntry) { entries.removeAll { $0.id == e.id } }

    func mark(_ id: UUID, latency: Int?, egress: String?, ok: Bool?) {
        guard let i = entries.firstIndex(where: { $0.id == id }) else { return }
        if let v = latency { entries[i].lastLatency = v }
        if let v = egress { entries[i].lastEgress = v }
        if let v = ok { entries[i].lastOK = v }
    }

    var enabledOnly: [ProxyEntry] {
        entries.filter { $0.enabled && !($0.kind != .direct && $0.host.isEmpty) }
    }

    var active: ProxyEntry? { enabledOnly.first { $0.kind != .direct } }

    func importList(_ text: String) {
        for raw in text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            var line = String(raw).trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            var kind: ProxyKind = .socks5
            if line.hasPrefix("http://") || line.hasPrefix("https://") {
                kind = .http
                line = line.replacingOccurrences(of: "https://", with: "")
                           .replacingOccurrences(of: "http://", with: "")
            } else if line.hasPrefix("socks5h://") {
                line = line.replacingOccurrences(of: "socks5h://", with: "")
            } else if line.hasPrefix("socks5://") {
                line = line.replacingOccurrences(of: "socks5://", with: "")
            }
            var user = "", pass = ""
            if let at = line.lastIndex(of: "@") {
                let cred = String(line[line.startIndex..<at])
                line = String(line[line.index(after: at)...])
                let parts = cred.split(separator: ":", maxSplits: 1)
                user = String(parts.first ?? "")
                if parts.count > 1 { pass = String(parts[1]) }
            }
            let hp = line.split(separator: ":")
            guard hp.count >= 2, let p = Int(hp[1]) else { continue }
            add(ProxyEntry(name: "\(hp[0]):\(p)", kind: kind,
                           host: String(hp[0]), port: p,
                           username: user, password: pass))
        }
    }
}

// MARK: - 探测引擎

@MainActor
final class ProbeEngine: ObservableObject {
    @Published var logs: [String] = []
    @Published var results: [ProbeResult] = []
    @Published var busy = false
    @Published var progress = ""

    private let store: ProxyStore

    init(store: ProxyStore) { self.store = store }

    func log(_ s: String) {
        logs.append("[\(Fmt.now())] \(s)")
        if logs.count > 600 { logs.removeFirst(logs.count - 600) }
    }
    func clearLog() { logs.removeAll() }

    private func record(_ r: ProbeResult) {
        results.insert(r, at: 0)
        log(r.summaryLine)
    }

    private func remember(_ e: ProxyEntry, latency: Int?, egress: String?, ok: Bool) {
        store.mark(e.id, latency: latency, egress: egress, ok: ok)
    }

    /// 系统代理字典：HTTP/HTTPS 代理与无认证 SOCKS5。
    /// SOCKS5 的用户名口令这个字典不支持，带认证的代理请用明文目标＋自建隧道方案。
    static func session(for entry: ProxyEntry) -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 15
        cfg.timeoutIntervalForResource = 25
        cfg.httpShouldSetCookies = false
        cfg.httpCookieStorage = nil
        cfg.urlCache = nil
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.waitsForConnectivity = false

        if entry.kind != .direct && !entry.host.isEmpty && entry.port > 0 {
            var d: [AnyHashable: Any] = [:]
            switch entry.kind {
            case .http:
                d["HTTPEnable"] = 1
                d["HTTPProxy"] = entry.host
                d["HTTPPort"] = entry.port
                d["HTTPSEnable"] = 1
                d["HTTPSProxy"] = entry.host
                d["HTTPSPort"] = entry.port
            case .socks5:
                d["SOCKSEnable"] = 1
                d["SOCKSProxy"] = entry.host
                d["SOCKSPort"] = entry.port
            case .direct:
                break
            }
            if !d.isEmpty { cfg.connectionProxyDictionary = d }
        }
        return URLSession(configuration: cfg)
    }

    private func fetch(_ urlString: String, entry: ProxyEntry,
                       headers: [String: String] = [:]) async throws -> (Data, Int, Int) {
        guard let url = URL(string: urlString) else {
            throw NSError(domain: "ipopsec", code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "URL 非法"])
        }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.setValue("IPOpsec/1.0", forHTTPHeaderField: "User-Agent")
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }

        let s = Self.session(for: entry)
        defer { s.finishTasksAndInvalidate() }
        let started = Date()
        let (data, resp) = try await s.data(for: req)
        let ms = Int(Date().timeIntervalSince(started) * 1000)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        return (data, code, ms)
    }

    // 1. 出口
    func checkEgress(_ entry: ProxyEntry) async -> ProbeResult {
        progress = "出口自检 · \(entry.name)"
        do {
            let (data, code, ms) = try await fetch("https://api.ipify.org", entry: entry)
            let ip = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard code == 200, !ip.isEmpty else {
                let r = ProbeResult(kind: "出口", proxy: entry.name, ok: false,
                                    headline: "HTTP \(code)，未取到出口 IP", latencyMs: ms)
                remember(entry, latency: ms, egress: nil, ok: false)
                record(r); return r
            }
            var detail = ["出口 IP: \(ip)", "耗时: \(ms) ms"]
            if let info = await ipInfo(ip, entry: entry) { detail.append(contentsOf: info) }
            let r = ProbeResult(kind: "出口", proxy: entry.name, ok: true,
                                headline: ip, detail: detail, latencyMs: ms)
            remember(entry, latency: ms, egress: ip, ok: true)
            record(r); return r
        } catch {
            let r = ProbeResult(kind: "出口", proxy: entry.name, ok: false,
                                headline: error.localizedDescription,
                                detail: ["代理: \(entry.endpoint)"])
            remember(entry, latency: nil, egress: nil, ok: false)
            record(r); return r
        }
    }

    private func ipInfo(_ ip: String, entry: ProxyEntry) async -> [String]? {
        let q = "http://ip-api.com/json/\(ip)?fields=status,country,regionName,city,isp,org,as,proxy,hosting"
        guard let resp = try? await fetch(q, entry: entry), resp.1 == 200,
              let obj = try? JSONSerialization.jsonObject(with: resp.0) as? [String: Any],
              (obj["status"] as? String) == "success" else { return nil }
        var out: [String] = []
        out.append("归属: \(obj["country"] as? String ?? "-") / \(obj["regionName"] as? String ?? "-") / \(obj["city"] as? String ?? "-")")
        if let isp = obj["isp"] as? String { out.append("ISP: \(isp)") }
        if let org = obj["org"] as? String { out.append("ORG: \(org)") }
        if let asn = obj["as"] as? String { out.append("AS: \(asn)") }
        let isProxy = (obj["proxy"] as? Bool) ?? false
        let isHosting = (obj["hosting"] as? Bool) ?? false
        out.append("标记: proxy=\(isProxy ? "是" : "否"), hosting=\(isHosting ? "是" : "否")")
        if isHosting && !isProxy { out.append("提示: 数据中心 IP，风控通常给更高评分") }
        return out
    }

    func checkBaseline() async -> ProbeResult {
        progress = "直连基线"
        let r = await checkEgress(ProxyStore.baseline)
        log("基线出口 \(r.headline) —— 仅用于对照")
        return r
    }

    // 2. 泄漏
    func checkHeaderLeak(_ entry: ProxyEntry) async -> ProbeResult {
        progress = "请求头泄漏 · \(entry.name)"
        do {
            let (data, code, ms) = try await fetch("https://httpbin.org/headers", entry: entry)
            guard code == 200,
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let headers = obj["headers"] as? [String: Any] else {
                let r = ProbeResult(kind: "泄漏", proxy: entry.name, ok: false,
                                    headline: "HTTP \(code)，响应无法解析", latencyMs: ms)
                record(r); return r
            }
            let suspicious = ["x-forwarded-for", "x-real-ip", "client-ip",
                              "x-client-ip", "x-originating-ip", "x-remote-ip",
                              "forwarded", "via", "x-proxy-id"]
            var hits: [String] = []
            var all: [String] = []
            for (k, v) in headers {
                let lk = k.lowercased()
                all.append("\(k): \(v)")
                if suspicious.contains(lk) { hits.append("\(k): \(v)") }
            }
            var detail = ["共收到 \(headers.count) 个头"]
            detail.append(contentsOf: all.sorted().prefix(25))
            detail.append(hits.isEmpty ? "未发现主动上报地址的头" : "⚠️ 发现上报头")
            let r = ProbeResult(kind: "泄漏", proxy: entry.name, ok: hits.isEmpty,
                                headline: hits.isEmpty ? "无地址类请求头" : "发现 \(hits.count) 个上报头",
                                detail: detail, latencyMs: ms)
            record(r); return r
        } catch {
            let r = ProbeResult(kind: "泄漏", proxy: entry.name, ok: false,
                                headline: error.localizedDescription)
            record(r); return r
        }
    }

    // 3. Tor
    func checkTor(_ entry: ProxyEntry) async -> ProbeResult {
        progress = "Tor 检测 · \(entry.name)"
        do {
            let (data, code, ms) = try await fetch("https://check.torproject.org/api/ip", entry: entry)
            guard code == 200,
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                let r = ProbeResult(kind: "Tor", proxy: entry.name, ok: false,
                                    headline: "HTTP \(code)", latencyMs: ms)
                record(r); return r
            }
            let isTor = (obj["IsTor"] as? Bool) ?? false
            let ip = obj["IP"] as? String ?? "-"
            let r = ProbeResult(kind: "Tor", proxy: entry.name, ok: true,
                                headline: isTor ? "是 Tor 出口" : "不是 Tor 出口（IP \(ip)）",
                                detail: ["IsTor=\(isTor)", "IP=\(ip)"], latencyMs: ms)
            record(r); return r
        } catch {
            let r = ProbeResult(kind: "Tor", proxy: entry.name, ok: false,
                                headline: error.localizedDescription)
            record(r); return r
        }
    }

    // 4. DNS
    func checkDNS(_ entry: ProxyEntry) async -> ProbeResult {
        progress = "DNS 通路 · \(entry.name)"
        do {
            let (data, code, ms) = try await fetch(
                "https://cloudflare-dns.com/dns-query?name=example.com&type=A",
                entry: entry, headers: ["accept": "application/dns-json"])
            guard code == 200,
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let ans = obj["Answer"] as? [[String: Any]] else {
                let r = ProbeResult(kind: "DNS", proxy: entry.name, ok: false,
                                    headline: "HTTP \(code)，DoH 无应答", latencyMs: ms)
                record(r); return r
            }
            let ips = ans.compactMap { $0["data"] as? String }
            let r = ProbeResult(kind: "DNS", proxy: entry.name, ok: !ips.isEmpty,
                                headline: "DoH 正常，\(ips.count) 条 A 记录",
                                detail: ["via cloudflare-dns.com",
                                         "example.com → \(ips.joined(separator: ", "))"],
                                latencyMs: ms)
            record(r); return r
        } catch {
            let r = ProbeResult(kind: "DNS", proxy: entry.name, ok: false,
                                headline: error.localizedDescription)
            record(r); return r
        }
    }

    // 5. 目标
    func checkTarget(_ entry: ProxyEntry, urlText: String) async -> ProbeResult {
        progress = "目标探测 · \(entry.name)"
        do {
            let (data, code, ms) = try await fetch(urlText, entry: entry)
            var detail = ["状态码: \(code)", "响应体: \(Fmt.bytes(data.count))", "耗时: \(ms) ms"]
            if data.count < 2048 && code == 200 {
                detail.append("提示: 200 但内容很小，可能是挑战页")
            }
            if [403, 429, 503].contains(code) {
                detail.append("提示: 被 WAF 或风控拦截，降频或换出口")
            }
            let r = ProbeResult(kind: "目标", proxy: entry.name,
                                ok: code >= 200 && code < 400,
                                headline: "HTTP \(code)", detail: detail, latencyMs: ms)
            record(r); return r
        } catch {
            let r = ProbeResult(kind: "目标", proxy: entry.name, ok: false,
                                headline: error.localizedDescription,
                                detail: ["URL: \(urlText)"])
            record(r); return r
        }
    }

    // 6. 池健康
    func healthCheckAll() async {
        guard !busy else { return }
        busy = true
        defer { busy = false; progress = "" }
        let list = store.enabledOnly
        log("开始健康检查，共 \(list.count) 个代理")
        var i = 0
        for e in list {
            i += 1
            progress = "健康检查 \(i)/\(list.count) · \(e.name)"
            _ = await checkEgress(e)
        }
        let okCount = store.enabledOnly.filter { $0.lastOK == true }.count
        log("健康检查完成：\(okCount)/\(list.count) 可用")
    }

    // 7. 报告
    func makeReport() -> ReportBundle {
        ReportBundle(device: "\(deviceModel()) · \(ProcessInfo.processInfo.operatingSystemVersionString)",
                     results: results, proxies: store.entries)
    }

    private func deviceModel() -> String {
        var sys = utsname()
        uname(&sys)
        return withUnsafePointer(to: &sys.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 256) {
                String(validatingUTF8: $0) ?? "iOS"
            }
        }
    }

    func exportReport(format: ReportFormat) -> URL? {
        let bundle = makeReport()
        let stamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let name: String
        let data: Data?
        switch format {
        case .markdown:
            name = "ipopsec-\(stamp).md"
            data = bundle.markdown().data(using: .utf8)
        case .json:
            name = "ipopsec-\(stamp).json"
            let enc = JSONEncoder()
            enc.outputFormatting = [.prettyPrinted, .sortedKeys]
            enc.dateEncodingStrategy = .iso8601
            data = try? enc.encode(bundle)
        }
        guard let d = data else { return nil }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        do {
            try d.write(to: url)
            log("报告已导出: \(url.lastPathComponent)")
            return url
        } catch {
            log("导出失败: \(error.localizedDescription)")
            return nil
        }
    }
}

enum ReportFormat: String, CaseIterable, Identifiable {
    case markdown, json
    var id: String { rawValue }
    var label: String { self == .markdown ? "Markdown" : "JSON" }
}

// MARK: - 分享面板（ShareLink 需 iOS 16，这里用 UIKit 版本兼容 15）

struct ActivityView: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}

// MARK: - App

@main
struct IPOpsecApp: App {
    @StateObject private var store: ProxyStore
    @StateObject private var engine: ProbeEngine

    init() {
        let s = ProxyStore()
        _store = StateObject(wrappedValue: s)
        _engine = StateObject(wrappedValue: ProbeEngine(store: s))
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(store)
                .environmentObject(engine)
                .preferredColorScheme(.dark)
        }
    }
}

struct RootView: View {
    var body: some View {
        TabView {
            ProxyListView()
                .tabItem { Label("代理", systemImage: "network") }
            ProbeView()
                .tabItem { Label("自检", systemImage: "magnifyingglass") }
            ReportView()
                .tabItem { Label("报告", systemImage: "doc.text") }
            LogView()
                .tabItem { Label("日志", systemImage: "terminal") }
        }
    }
}

// MARK: - 代理列表

struct ProxyListView: View {
    @EnvironmentObject var store: ProxyStore
    @EnvironmentObject var engine: ProbeEngine

    @State private var editing: ProxyEntry?
    @State private var showImport = false
    @State private var importText = ""

    var body: some View {
        NavigationView {
            List {
                Section {
                    ForEach(store.entries) { e in
                        ProxyRow(entry: e)
                            .contentShape(Rectangle())
                            .onTapGesture { editing = e }
                            .swipeActions(edge: .trailing) {
                                Button(role: .destructive) { store.remove(e) } label: {
                                    Label("删除", systemImage: "trash")
                                }
                            }
                            .swipeActions(edge: .leading) {
                                Button {
                                    var m = e
                                    m.enabled.toggle()
                                    store.update(m)
                                } label: {
                                    Label(e.enabled ? "停用" : "启用",
                                          systemImage: e.enabled ? "pause" : "play")
                                }
                                .tint(.orange)
                            }
                    }
                } header: {
                    Text("代理（\(store.entries.count)）")
                } footer: {
                    Text("点条目编辑，左滑启停。带账号口令的 SOCKS5 只能用于明文目标，HTTPS 探测请用无认证代理或 HTTP 代理。")
                }
            }
            .navigationTitle("代理配置")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button {
                            editing = ProxyEntry(name: "", kind: .socks5, host: "", port: 1080)
                        } label: { Label("新建", systemImage: "plus") }
                        Button { showImport = true } label: {
                            Label("批量导入", systemImage: "doc.on.clipboard")
                        }
                        Divider()
                        Button { Task { await engine.healthCheckAll() } } label: {
                            Label("全部健康检查", systemImage: "heart.text.square")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
            .sheet(item: $editing) { e in
                ProxyEditView(entry: e) { saved in
                    store.update(saved)
                    editing = nil
                } onCancel: { editing = nil }
            }
            .sheet(isPresented: $showImport) {
                ImportSheet(text: $importText) {
                    store.importList(importText)
                    importText = ""
                    showImport = false
                } onCancel: { showImport = false }
            }
        }
    }
}

struct ProxyRow: View {
    let entry: ProxyEntry

    var body: some View {
        HStack(spacing: 10) {
            Circle().fill(color).frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(entry.name.isEmpty ? "(未命名)" : entry.name)
                        .font(.body.weight(.medium))
                    Text(entry.kind.short)
                        .font(.caption2.weight(.bold))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Color.secondary.opacity(0.2))
                        .clipShape(Capsule())
                }
                HStack(spacing: 8) {
                    if entry.kind != .direct {
                        Text("\(entry.host):\(entry.port)")
                            .font(.system(.caption, design: .monospaced))
                    } else {
                        Text("不经代理，用于基线对照").font(.caption)
                    }
                    if let eg = entry.lastEgress {
                        Text("→ \(eg)")
                            .font(.system(.caption2, design: .monospaced))
                    }
                }
                .foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                if let lat = entry.lastLatency {
                    Text("\(lat) ms")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                if !entry.enabled {
                    Text("停用").font(.caption2).foregroundStyle(.orange)
                }
            }
        }
        .padding(.vertical, 2)
    }

    private var color: Color {
        if !entry.enabled { return .gray }
        switch entry.lastOK {
        case .some(true): return .green
        case .some(false): return .red
        case .none: return .secondary
        }
    }
}

struct ProxyEditView: View {
    @State var entry: ProxyEntry
    var onSave: (ProxyEntry) -> Void
    var onCancel: () -> Void

    var body: some View {
        NavigationView {
            Form {
                Section("标识") {
                    TextField("名称", text: $entry.name)
                    Picker("类型", selection: $entry.kind) {
                        ForEach(ProxyKind.allCases) { k in Text(k.label).tag(k) }
                    }
                    Toggle("启用", isOn: $entry.enabled)
                }
                if entry.kind != .direct {
                    Section("端点") {
                        TextField("主机 / IP", text: $entry.host)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        TextField("端口", value: $entry.port, format: .number)
                            .keyboardType(.numberPad)
                    }
                    Section {
                        TextField("用户名（可空）", text: $entry.username)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        TextField("口令", text: $entry.password)
                    } header: {
                        Text("认证")
                    } footer: {
                        Text("单文件版把配置存在 UserDefaults（TrollStore 下 Keychain 可能不可用）。口令仅本机保存。")
                    }
                }
            }
            .navigationTitle(entry.name.isEmpty ? "新建代理" : "编辑代理")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { onCancel() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") { onSave(entry) }
                        .disabled(entry.kind != .direct && entry.host.isEmpty)
                }
            }
        }
    }
}

struct ImportSheet: View {
    @Binding var text: String
    var onImport: () -> Void
    var onCancel: () -> Void

    var body: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 10) {
                Text("每行一个：host:port / socks5h://user:pass@host:port / http://host:port，# 为注释")
                    .font(.caption).foregroundStyle(.secondary)
                TextEditor(text: $text)
                    .font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 240)
                    .overlay(RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.secondary.opacity(0.3)))
                Spacer()
            }
            .padding()
            .navigationTitle("批量导入")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { onCancel() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("导入") { onImport() }
                }
            }
        }
    }
}

// MARK: - 自检

struct ProbeView: View {
    @EnvironmentObject var store: ProxyStore
    @EnvironmentObject var engine: ProbeEngine

    @State private var selectedID: UUID?
    @State private var targetURL = "https://example.com/"

    private var current: ProxyEntry {
        if let id = selectedID, let e = store.entries.first(where: { $0.id == id }) { return e }
        return store.active ?? store.entries.first ?? ProxyStore.baseline
    }

    var body: some View {
        NavigationView {
            Form {
                Section {
                    Picker("使用代理", selection: $selectedID) {
                        Text("自动（第一个可用）").tag(UUID?.none)
                        ForEach(store.entries) { e in
                            Text("\(e.name.isEmpty ? "(未命名)" : e.name) · \(e.kind.short)")
                                .tag(UUID?.some(e.id))
                        }
                    }
                    HStack {
                        Text("端点")
                        Spacer()
                        Text(current.kind == .direct ? "direct" : "\(current.host):\(current.port)")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    if !current.username.isEmpty {
                        Label("该代理需认证，HTTPS 探测不可用", systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                } header: { Text("通道") }

                Section {
                    Button { run { _ = await engine.checkEgress(current) } } label: {
                        row("出口 IP", "network")
                    }
                    Button { run { _ = await engine.checkHeaderLeak(current) } } label: {
                        row("请求头泄漏", "list.bullet.rectangle")
                    }
                    Button { run { _ = await engine.checkTor(current) } } label: {
                        row("Tor 出口", "shield.lefthalf.filled")
                    }
                    Button { run { _ = await engine.checkDNS(current) } } label: {
                        row("DNS 通路", "globe")
                    }
                    Button { run { _ = await engine.checkBaseline() } } label: {
                        row("直连基线对照", "arrow.triangle.branch")
                    }
                    Button { run { await engine.healthCheckAll() } } label: {
                        row("整池健康检查", "heart.text.square")
                    }
                } header: { Text("自检") }
                  footer: { Text("每项都是你主动发起的单次请求，不会自动扫描任何站点。") }

                Section {
                    TextField("目标 URL", text: $targetURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                    Button { run { _ = await engine.checkTarget(current, urlText: targetURL) } } label: {
                        row("探测该目标", "scope")
                    }
                } header: { Text("目标探测") }
                  footer: { Text("只统计状态码、响应体大小、耗时。") }

                if let latest = engine.results.first {
                    Section("最近一次") { ResultCard(r: latest) }
                }
            }
            .navigationTitle("自检")
            .safeAreaInset(edge: .bottom) {
                if engine.busy {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text(engine.progress.isEmpty ? "执行中…" : engine.progress)
                            .font(.caption)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity)
                    .background(.ultraThinMaterial)
                }
            }
        }
    }

    private func row(_ title: String, _ icon: String) -> some View {
        HStack {
            Image(systemName: icon).frame(width: 22)
            Text(title)
            Spacer()
            if engine.busy { ProgressView().scaleEffect(0.7) }
        }
    }

    private func run(_ block: @escaping () async -> Void) {
        Task { await block() }
    }
}

struct ResultCard: View {
    let r: ProbeResult
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: r.ok ? "checkmark.circle.fill" : "xmark.octagon.fill")
                    .foregroundStyle(r.ok ? .green : .red)
                Text(r.kind).font(.subheadline.weight(.semibold))
                Spacer()
                if let ms = r.latencyMs, ms > 0 {
                    Text("\(ms) ms")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
            Text(r.headline).font(.callout)
            ForEach(Array(r.detail.enumerated()), id: \.offset) { _, d in
                Text(d)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - 报告

struct ReportView: View {
    @EnvironmentObject var engine: ProbeEngine
    @State private var exportURL: URL?
    @State private var format: ReportFormat = .markdown
    @State private var showShare = false

    var body: some View {
        NavigationView {
            List {
                Section {
                    HStack {
                        stat("条目", "\(engine.results.count)")
                        Divider()
                        stat("通过", "\(engine.results.filter { $0.ok }.count)")
                        Divider()
                        stat("失败", "\(engine.results.filter { !$0.ok }.count)")
                    }
                    .padding(.vertical, 4)
                }
                Section {
                    Picker("格式", selection: $format) {
                        ForEach(ReportFormat.allCases) { f in Text(f.label).tag(f) }
                    }
                    .pickerStyle(.segmented)

                    Button { exportURL = engine.exportReport(format: format) } label: {
                        Label("生成报告", systemImage: "square.and.arrow.up.on.square")
                    }
                    if let url = exportURL {
                        Button { showShare = true } label: {
                            Label("分享 \(url.lastPathComponent)", systemImage: "square.and.arrow.up")
                        }
                    }
                } header: { Text("导出") }
                  footer: { Text("Markdown 可直接贴进交付文档。") }

                Section {
                    if engine.results.isEmpty {
                        Text("还没有探测结果").foregroundStyle(.secondary)
                    } else {
                        ForEach(engine.results) { r in ResultCard(r: r) }
                    }
                } header: { Text("明细") }

                Section {
                    Button(role: .destructive) {
                        engine.results.removeAll()
                        exportURL = nil
                    } label: { Label("清空结果", systemImage: "trash") }
                }
            }
            .navigationTitle("报告")
            .sheet(isPresented: $showShare) {
                if let url = exportURL { ActivityView(items: [url]) }
            }
        }
    }

    private func stat(_ title: String, _ value: String) -> some View {
        VStack(spacing: 2) {
            Text(value).font(.title3.weight(.semibold).monospacedDigit())
            Text(title).font(.caption2).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}

struct LogView: View {
    @EnvironmentObject var engine: ProbeEngine
    var body: some View {
        NavigationView {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(engine.logs.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(12)
            }
            .navigationTitle("日志")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("清空") { engine.clearLog() }
                }
            }
        }
    }
}
