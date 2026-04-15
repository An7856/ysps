import { connect } from 'cloudflare:sockets';
let p = 'dylj';
let fdc = [''];
let uid = '';
let yx = ['ip.sb', 'time.is', 'cdns.doon.eu.org'];
let dns = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg=';
let dyhd = atob('aHR0cHM6Ly9hcGkudjEubWsvc3ViPw==');
let dypz = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX0Z1bGxfTXVsdGlNb2RlLmluaQ==');
let stp = '';
const KP = 'admin_password', KU = 'user_uuid', K_SETTINGS = 'SYSTEM_CONFIG';
let cc = null, ct = 0, CD = 60 * 1000;
const STALE_CD = 60 * 60 * 1000;
const loginAttempts = new Map();
const SESSION_DURATION = 8 * 60 * 60 * 1000;
let ev = true, et = false, tp = '';
let protocolConfig = { ev, et, tp };
let globalTimeout = 8000;
let cachedUsage = null;
let lastUsageTime = 0;
let cachedAdminPwd = null;
const FAILED_IP_CACHE = new Map();
const FAILED_TTL = 10 * 60 * 1000;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
let cachedTrojanHash = null;
let cachedTrojanPwd = null;
let parsedSocks5Address = {};
let cachedProxyIPList = [];
let cachedProxyIP = '';

function uniqueIPList(list) {
    const seen = new Set();
    return list.filter(item => {
        if (!item) return false;
        const key = item.split('#')[0].trim();
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}
const UUIDUtils = {
    generateStandardUUID() { return crypto.randomUUID(); },
    isValidUUID(uuid) { return UUID_REGEX.test(uuid); }
};
const IPParser = {
    parsePreferredIP(input) {
        if (!input) return null;
        let hostname = input.trim();
        let countryName = '';
        let countryCode = '';
        let comment = '';
        if (hostname.includes('#')) {
            const parts = hostname.split('#');
            hostname = parts[0].trim();
            comment = parts[1].trim();
            if (comment.includes('|')) {
                const countryParts = comment.split('|');
                countryName = countryParts[0].trim();
                countryCode = countryParts[1]?.trim() || '';
            } else {
                countryName = comment;
            }
        }
        const { hostname: cleanHost, port: cleanPort } = this.parseConnectionAddress(hostname);
        if (!cleanHost) return null;
        return {
            hostname: cleanHost,
            port: cleanPort,
            countryName,
            countryCode,
            original: input,
            displayName: this.generateDisplayName(cleanHost, cleanPort, countryName, countryCode)
        };
    },
    parseConnectionAddress(input) {
        const defPort = 443;
        let hostname = input.trim();
        let port = defPort;
        if (hostname.includes('#')) hostname = hostname.split('#')[0].trim();
        if (hostname.includes('.tp')) {
            const match = hostname.match(/\.tp(\d+)\./);
            if (match) port = parseInt(match[1]);
        } else if (hostname.includes('[') && hostname.includes(']:')) {
            const portParts = hostname.split(']:');
            port = parseInt(portParts[1]);
            hostname = portParts[0] + ']';
        } else if (hostname.includes(':') && !hostname.startsWith('[')) {
            const portParts = hostname.split(':');
            port = parseInt(portParts.pop());
            hostname = portParts.join(':');
        }
        return { hostname, port };
    },
    generateDisplayName(hostname, port, countryName, countryCode) {
        let displayName = hostname;
        if (countryCode) {
            const flag = getFlagEmoji(countryCode);
            displayName = `${flag} ${countryName} ${hostname}:${port}`;
        } else if (countryName) displayName = `${countryName} ${hostname}:${port}`;
        else if (port !== 443) displayName = `${hostname}:${port}`;
        return displayName;
    }
};
const ResponseBuilder = {
    html(content, status = 200, extraHeaders = {}) { return new Response(content, { status, headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-cache, no-store, must-revalidate', ...extraHeaders } }); },
    text(content, status = 200, extraHeaders = {}) { return new Response(content, { status, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Cache-Control': 'no-cache, no-store, must-revalidate', ...extraHeaders } }); },
    json(data, status = 200, extraHeaders = {}) { return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json;charset=utf-8', ...extraHeaders } }); },
    redirect(url, status = 302, extraHeaders = {}) { return new Response(null, { status, headers: { 'Location': url, ...extraHeaders } }); }
};
const ConfigUtils = {
    async loadAllConfig(env) {
        const kv = env.SJ || env.sj;
        const defaultConfig = {
            yx: yx, fdc: fdc, uid: uid, dyhd: dyhd, dypz: dypz, stp: '', dns: dns,
            ev: true, et: false, tp: '',
            klp: 'login', uuidSet: new Set(uid.split(',').map(s => s.trim().toLowerCase())),
            cfConfig: {}, proxyConfig: {}, transConfig: { grpc: false, xhttp: false, ech: false, ech_sni: '' }
        };
        if (!kv) return defaultConfig;
        try {
            const unifiedConfig = await kv.get(K_SETTINGS, 'json');
            if (unifiedConfig) {
                const configUid = unifiedConfig.uid || uid;
                return {
                    yx: unifiedConfig.yx || yx, fdc: unifiedConfig.fdc || fdc, uid: configUid,
                    dyhd: unifiedConfig.dyhd || dyhd, dypz: unifiedConfig.dypz || dypz, stp: unifiedConfig.stp || '', dns: unifiedConfig.dns || dns,
                    ev: unifiedConfig.protocolConfig?.ev ?? true, et: unifiedConfig.protocolConfig?.et ?? false, tp: unifiedConfig.protocolConfig?.tp ?? '',
                    cfConfig: unifiedConfig.cfConfig || {}, proxyConfig: unifiedConfig.proxyConfig || {}, transConfig: unifiedConfig.transConfig || { grpc: false, xhttp: false, ech: false, ech_sni: '' },
                    klp: unifiedConfig.klp || 'login', uuidSet: new Set(configUid.split(',').map(s => s.trim().toLowerCase()))
                };
            }
        } catch (e) {}
        return defaultConfig;
    }
};
const ErrorHandler = {
    internalError(message = 'Internal Server Error') { return ResponseBuilder.text(message, 500); },
    unauthorized(message = 'Unauthorized') { return ResponseBuilder.text(message, 401); }
};
async function gP(env) {
    if (cachedAdminPwd) return cachedAdminPwd;
    const kv = env.SJ || env.sj;
    cachedAdminPwd = kv ? await kv.get(KP) : null;
    return cachedAdminPwd;
}
async function sP(env, pw) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;
    await kv.put(KP, pw);
    cachedAdminPwd = pw;
    return true;
}
async function gU(env) {
    const kv = env.SJ || env.sj;
    return kv ? await kv.get(KU) : null;
}
async function sU(env, u) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;
    await kv.put(KU, u);
    return true;
}
async function signToken(env, exp) {
    const pwd = await gP(env) || 'default';
    const msg = `${exp}:${pwd}`;
    const msgUint8 = new TextEncoder().encode(msg);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return btoa(`${exp}:${hashHex}`);
}
async function validateAndRefreshSession(env, token) {
    if (!token) return { valid: false };
    try {
        const decoded = atob(token);
        const [expStr, hashHex] = decoded.split(':');
        const exp = parseInt(expStr);
        const now = Date.now();
        if (now > exp) return { valid: false };
        const pwd = await gP(env) || 'default';
        const msg = `${exp}:${pwd}`;
        const msgUint8 = new TextEncoder().encode(msg);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
        const expectedHash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        if (hashHex !== expectedHash) return { valid: false };
        if (exp - now < 30 * 60 * 1000) {
            const newExp = now + SESSION_DURATION;
            const newToken = await signToken(env, newExp);
            return { valid: true, refreshed: true, newToken };
        }
        return { valid: true, refreshed: false, newToken: token };
    } catch (e) { return { valid: false }; }
}
function getSessionCookie(cookieHeader) {
    if (!cookieHeader) return null;
    const cookies = cookieHeader.split(';');
    for (const cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'cf_worker_session' && value) return value;
    }
    return null;
}
function setSessionCookie(token) {
    const expires = new Date(Date.now() + SESSION_DURATION).toUTCString();
    return `cf_worker_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=${expires}`;
}
function clearSessionCookie() { return `cf_worker_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT`; }
async function requireAuth(req, env, handler) {
    const token = getSessionCookie(req.headers.get('Cookie'));
    const sessionResult = await validateAndRefreshSession(env, token);
    if (!sessionResult.valid) return getPoemPage();
    if (sessionResult.refreshed) {
        const response = await handler(req, env);
        response.headers.set('Set-Cookie', setSessionCookie(sessionResult.newToken));
        return response;
    }
    return handler(req, env);
}
async function handleLogin(req, env) {
    const host = req.headers.get('Host');
    const base = `https://${host}`;
    const url = new URL(req.url);
    const passwordChanged = url.searchParams.get('password_changed') === 'true';
    const clientIp = req.headers.get('CF-Connecting-IP') || 'unknown';
    const now = Date.now();
    for (const [ip, data] of loginAttempts) {
        if (now - data.time > 60000) loginAttempts.delete(ip);
    }
    if (loginAttempts.size > 1000) loginAttempts.delete(loginAttempts.keys().next().value);
    const attempt = loginAttempts.get(clientIp) || { count: 0, time: 0 };
    if (attempt.count > 5 && (now - attempt.time) < 60000) return ResponseBuilder.text('尝试次数过多，请稍后再试', 429);
    if (req.method === 'POST') {
        const form = await req.formData();
        const password = form.get('password');
        const storedPassword = await gP(env);
        if (password === storedPassword) {
            loginAttempts.delete(clientIp);
            const newToken = await signToken(env, Date.now() + SESSION_DURATION);
            const response = await getMainPageContent(host, base, storedPassword, await gU(env), env);
            response.headers.set('Set-Cookie', setSessionCookie(newToken));
            return response;
        } else {
            loginAttempts.set(clientIp, { count: attempt.count + 1, time: now });
            await new Promise(resolve => setTimeout(resolve, 2000));
            return getLoginPage(host, base, true, false);
        }
    } else return getLoginPage(host, base, false, passwordChanged);
}
async function handleLogout(req, env) {
    const host = req.headers.get('Host');
    const base = `https://${host}`;
    return ResponseBuilder.redirect(`${base}/`, 302, { 'Set-Cookie': clearSessionCookie() });
}
async function optimizeConfigLoading(env, ctx) {
    const now = Date.now();
    if (cc && (now - ct) < CD) return cc;
    const loadConfigTask = async () => {
        try {
            if (env.CONNECT_TIMEOUT) globalTimeout = parseInt(env.CONNECT_TIMEOUT) || 8000;
            const config = await ConfigUtils.loadAllConfig(env);
            const newConfig = {
                ...config,
                timestamp: now,
                parsedIPs: config.yx.map(ip => IPParser.parsePreferredIP(ip)),
                validFDCs: config.fdc.filter(s => s && s.trim() !== '')
            };
            cc = newConfig;
            ct = now;
            yx = cc.yx; fdc = cc.fdc; uid = cc.uid; dyhd = cc.dyhd; dypz = cc.dypz; stp = cc.stp; dns = cc.dns || dns;
            ev = cc.ev; et = cc.et; tp = cc.tp;
            protocolConfig = { ev, et, tp };
            return cc;
        } catch (error) {
            if (cc) return cc;
            return {
                yx: yx, fdc: fdc, uid: uid, dyhd: dyhd, dypz: dypz, stp: stp, dns: dns,
                ev: ev, et: et, tp: tp,
                parsedIPs: yx.map(ip => IPParser.parsePreferredIP(ip)),
                validFDCs: fdc.filter(s => s && s.trim() !== ''),
                uuidSet: new Set(uid.split(',').map(s => s.trim().toLowerCase())),
                proxyConfig: {}, transConfig: { grpc: false, xhttp: false, ech: false, ech_sni: '' }
            };
        }
    };
    if (cc && (now - ct) < STALE_CD && ctx) {
        ctx.waitUntil(loadConfigTask().catch(console.error));
        return cc;
    }
    return await loadConfigTask();
}
async function saveConfigToKV(env, cfipArr, fdipArr, u = null, protocolCfg = null, cfCfg = null, proxyCfg = null, klp = null, newDyhd = null, newDypz = null, newStp = null, newDns = null, transCfg = null) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;
    const unifiedConfig = {
        yx: cfipArr, fdc: fdipArr, uid: u || uid, dyhd: newDyhd || dyhd, dypz: newDypz || dypz, stp: newStp || stp, dns: newDns || dns,
        protocolConfig: protocolCfg || { ev, et, tp },
        cfConfig: cfCfg || {}, proxyConfig: proxyCfg || {}, transConfig: transCfg || { grpc: false, xhttp: false, ech: false, ech_sni: '' },
        klp: klp || 'login'
    };
    const ps = [kv.put(K_SETTINGS, JSON.stringify(unifiedConfig))];
    if (u) ps.push(kv.put(KU, u));
    if (klp) ps.push(kv.put(KP, await gP(env)));
    await Promise.all(ps);
    const uuidSet = new Set((u || uid).split(',').map(s => s.trim().toLowerCase()));
    cc = {
        ...unifiedConfig, timestamp: Date.now(),
        ev: unifiedConfig.protocolConfig.ev, et: unifiedConfig.protocolConfig.et, tp: unifiedConfig.protocolConfig.tp,
        parsedIPs: cfipArr.map(ip => IPParser.parsePreferredIP(ip)), validFDCs: fdipArr.filter(s => s && s.trim() !== ''), uuidSet: uuidSet
    };
    ct = Date.now();
    return true;
}
async function DoH查询(domain, type, doh = cc?.dns || 'https://cloudflare-dns.com/dns-query') {
    try {
        const typeMap = { 'A': 1, 'NS': 2, 'CNAME': 5, 'MX': 15, 'TXT': 16, 'AAAA': 28, 'SRV': 33, 'HTTPS': 65 };
        const qtype = typeMap[type.toUpperCase()] || 1;
        const encodeDomain = (name) => {
            const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
            const bufs = [];
            for (const label of parts) {
                const enc = new TextEncoder().encode(label);
                bufs.push(new Uint8Array([enc.length]), enc);
            }
            bufs.push(new Uint8Array([0]));
            const total = bufs.reduce((s, b) => s + b.length, 0);
            const result = new Uint8Array(total);
            let off = 0;
            for (const b of bufs) { result.set(b, off); off += b.length }
            return result;
        };
        const qname = encodeDomain(domain);
        const query = new Uint8Array(12 + qname.length + 4);
        const qview = new DataView(query.buffer);
        qview.setUint16(0, 0); qview.setUint16(2, 0x0100); qview.setUint16(4, 1);
        query.set(qname, 12);
        qview.setUint16(12 + qname.length, qtype); qview.setUint16(12 + qname.length + 2, 1);
        const response = await fetch(doh, { method: 'POST', headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' }, body: query });
        if (!response.ok) return [];
        const buf = new Uint8Array(await response.arrayBuffer());
        const dv = new DataView(buf.buffer);
        const qdcount = dv.getUint16(4); const ancount = dv.getUint16(6);
        const parseDomain = (pos) => {
            const labels = [];
            let p = pos, jumped = false, endPos = -1, safe = 128;
            while (p < buf.length && safe-- > 0) {
                const len = buf[p];
                if (len === 0) { if (!jumped) endPos = p + 1; break; }
                if ((len & 0xC0) === 0xC0) {
                    if (!jumped) endPos = p + 2;
                    p = ((len & 0x3F) << 8) | buf[p + 1];
                    jumped = true; continue;
                }
                labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
                p += len + 1;
            }
            if (endPos === -1) endPos = p + 1;
            return [labels.join('.'), endPos];
        };
        let offset = 12;
        for (let i = 0; i < qdcount; i++) {
            const [, end] = parseDomain(offset);
            offset = end + 4;
        }
        const answers = [];
        for (let i = 0; i < ancount && offset < buf.length; i++) {
            const [name, nameEnd] = parseDomain(offset);
            offset = nameEnd;
            const rtype = dv.getUint16(offset); offset += 2; offset += 2;
            const ttl = dv.getUint32(offset); offset += 4;
            const rdlen = dv.getUint16(offset); offset += 2;
            const rdata = buf.slice(offset, offset + rdlen);
            offset += rdlen;
            let data;
            if (rtype === 1 && rdlen === 4) data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
            else if (rtype === 28 && rdlen === 16) {
                const segs = [];
                for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
                data = segs.join(':');
            } else if (rtype === 16) {
                let tOff = 0; const parts = [];
                while (tOff < rdlen) {
                    const tLen = rdata[tOff++];
                    parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
                    tOff += tLen;
                }
                data = parts.join('');
            } else if (rtype === 5) {
                const [cname] = parseDomain(offset - rdlen);
                data = cname;
            } else data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
            answers.push({ name, type: rtype, TTL: ttl, data, rdata });
        }
        return answers;
    } catch (e) { return []; }
}
async function getECH(host) {
    try {
        const answers = await DoH查询(host, 'HTTPS');
        if (!answers.length) return '';
        for (const ans of answers) {
            if (ans.type !== 65 || !ans.rdata) continue;
            const bytes = ans.rdata;
            let offset = 2;
            while (offset < bytes.length) {
                const len = bytes[offset];
                if (len === 0) { offset++; break; }
                offset += len + 1;
            }
            while (offset + 4 <= bytes.length) {
                const key = (bytes[offset] << 8) | bytes[offset + 1];
                const len = (bytes[offset + 2] << 8) | bytes[offset + 3];
                offset += 4;
                if (key === 5) return btoa(String.fromCharCode(...bytes.slice(offset, offset + len)));
                offset += len;
            }
        }
        return '';
    } catch { return ''; }
}
async function resolveAddressAndPort(proxyIP, targetHost, UUID) {
    if (!cachedProxyIPList || cachedProxyIPList.length === 0 || cachedProxyIP !== proxyIP) {
        proxyIP = proxyIP.toLowerCase();
        function parseStr(str) {
            let addr = str, port = 443;
            if (str.includes(']:')) {
                const parts = str.split(']:');
                addr = parts[0] + ']';
                port = parseInt(parts[1], 10) || port;
            } else if (str.includes(':') && !str.startsWith('[')) {
                const colonIndex = str.lastIndexOf(':');
                addr = str.slice(0, colonIndex);
                port = parseInt(str.slice(colonIndex + 1), 10) || port;
            }
            return [addr, port];
        }
        const ipArr = proxyIP.split(',').map(s => s.trim()).filter(Boolean);
        let allArr = [];
        for (const sip of ipArr) {
            if (sip.includes('.william')) {
                try {
                    let txtRecords = await DoH查询(sip, 'TXT');
                    let txtData = txtRecords.filter(r => r.type === 16).map(r => r.data);
                    if (txtData.length === 0) {
                        txtRecords = await DoH查询(sip, 'TXT', 'https://dns.google/dns-query');
                        txtData = txtRecords.filter(r => r.type === 16).map(r => r.data);
                    }
                    if (txtData.length > 0) {
                        let data = txtData[0];
                        if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
                        const prefixes = data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
                        allArr.push(...prefixes.map(prefix => parseStr(prefix)));
                    }
                } catch (e) {}
            } else {
                let [addr, port] = parseStr(sip);
                if (sip.includes('.tp')) {
                    const tpMatch = sip.match(/\.tp(\d+)/);
                    if (tpMatch) port = parseInt(tpMatch[1], 10);
                }
                const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
                const ipv6Regex = /^\[?([a-fA-F0-9:]+)\]?$/;
                if (!ipv4Regex.test(addr) && !ipv6Regex.test(addr)) {
                    let [aRecords, aaaaRecords] = await Promise.all([DoH查询(addr, 'A'), DoH查询(addr, 'AAAA')]);
                    let ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
                    let ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
                    let ipAddresses = [...ipv4List, ...ipv6List];
                    if (ipAddresses.length === 0) {
                        [aRecords, aaaaRecords] = await Promise.all([DoH查询(addr, 'A', 'https://dns.google/dns-query'), DoH查询(addr, 'AAAA', 'https://dns.google/dns-query')]);
                        ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
                        ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
                        ipAddresses = [...ipv4List, ...ipv6List];
                    }
                    if (ipAddresses.length > 0) allArr.push(...ipAddresses.map(ip => [ip, port]));
                    else allArr.push([addr, port]);
                } else {
                    allArr.push([addr, port]);
                }
            }
        }
        const sorted = allArr.sort((a, b) => a[0].localeCompare(b[0]));
        const rootHost = targetHost.includes('.') ? targetHost.split('.').slice(-2).join('.') : targetHost;
        let seed = [...(rootHost + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
        const shuffled = [...sorted].sort(() => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
        cachedProxyIPList = shuffled.slice(0, 8);
        cachedProxyIP = proxyIP;
    }
    return cachedProxyIPList;
}
async function connectWithTimeout(host, port, timeoutMs) {
    const socket = connect({ hostname: host, port: port, allowHalfOpen: true, noDelay: true });
    let timer = null;
    const timeoutPromise = new Promise((_, reject) => {
        timer = setTimeout(() => { try { socket.close(); } catch(e) {} reject(new Error(`Connect timeout`)); }, timeoutMs);
    });
    try {
        await Promise.race([socket.opened, timeoutPromise]);
        return socket;
    } catch (error) {
        try { socket.close(); } catch(e) {}
        throw error;
    } finally {
        if (timer) clearTimeout(timer);
    }
}
async function universalConnectWithFailover(targetHost, targetPort) {
    let valid = cc?.validFDCs || fdc.filter(s => s && s.trim() !== '');
    if (valid.length === 0) valid = ['www.visa.com.sg'];
    const resolvedList = await resolveAddressAndPort(valid.join(','), targetHost, uid);
    if(resolvedList.length === 0) resolvedList.push([valid[0], 443]);
    const PRIMARY_TIMEOUT = 3000, BACKUP_TIMEOUT = 2000;
    const now = Date.now();
    for (const [ip, time] of FAILED_IP_CACHE) { if (now - time > FAILED_TTL) FAILED_IP_CACHE.delete(ip); }
    if (FAILED_IP_CACHE.size > 500) FAILED_IP_CACHE.delete(FAILED_IP_CACHE.keys().next().value);
    
    for (let i = 0; i < resolvedList.length; i++) {
        const [hostname, port] = resolvedList[i];
        const cacheKey = `${hostname}:${port}`;
        if (!FAILED_IP_CACHE.has(cacheKey)) {
             try {
                const socket = await connectWithTimeout(hostname, port, i === 0 ? PRIMARY_TIMEOUT : BACKUP_TIMEOUT);
                return { socket, server: { hostname, port, original: cacheKey } };
            } catch (e) {
                FAILED_IP_CACHE.set(cacheKey, Date.now());
            }
        }
    }
    throw new Error(`所有节点连接失败`);
}
function safeCloseWebSocket(socket) { try { if (socket.readyState === 1 || socket.readyState === 2) socket.close(); } catch (e) { } }
function safeCloseSocket(socket) { try { if (socket) socket.close(); } catch (e) { } }
function sha224(s) {
	const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8; s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
	s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
	const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++)x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
			h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) {
		for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
	}
	return hex;
}
function formatIdentifier(arr, offset = 0) {
	const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
function 解析木马请求(buffer, passwordPlainText) {
	const sha224Password = sha224(passwordPlainText);
	if (buffer.byteLength < 56) return { hasError: true, message: "invalid data" };
	let crLfIndex = 56;
	if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) return { hasError: true, message: "invalid header format" };
	const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
	if (password !== sha224Password) return { hasError: true, message: "invalid password" };
	const socks5DataBuffer = buffer.slice(crLfIndex + 2);
	if (socks5DataBuffer.byteLength < 6) return { hasError: true, message: "invalid S5 request data" };
	const view = new DataView(socks5DataBuffer);
	const cmd = view.getUint8(0);
	if (cmd !== 1) return { hasError: true, message: "unsupported command" };
	const atype = view.getUint8(1);
	let addressLength = 0, addressIndex = 2, address = "";
	switch (atype) {
		case 1: addressLength = 4; address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join("."); break;
		case 3: addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0]; addressIndex += 1; address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)); break;
		case 4: addressLength = 16; const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)); const ipv6 = []; for (let i = 0; i < 8; i++) { ipv6.push(dataView.getUint16(i * 2).toString(16)); } address = ipv6.join(":"); break;
		default: return { hasError: true, message: `invalid addressType is ${atype}` };
	}
	if (!address) return { hasError: true, message: `address is empty` };
	const portIndex = addressIndex + addressLength;
	const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
	const portRemote = new DataView(portBuffer).getUint16(0);
	return { hasError: false, addressType: atype, port: portRemote, hostname: address, rawClientData: socks5DataBuffer.slice(portIndex + 4) };
}
function 解析魏烈思请求(chunk, token) {
	if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };
	const version = new Uint8Array(chunk.slice(0, 1));
	if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: 'Invalid uuid' };
	const optLen = new Uint8Array(chunk.slice(17, 18))[0];
	const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
	let isUDP = false;
	if (cmd === 1) { } else if (cmd === 2) { isUDP = true } else { return { hasError: true, message: 'Invalid command' } }
	const portIdx = 19 + optLen;
	const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
	let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
	const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
	switch (addressType) {
		case 1: addrLen = 4; hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.'); break;
		case 2: addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0]; addrValIdx += 1; hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen)); break;
		case 3: addrLen = 16; const ipv6 = []; const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen)); for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16)); hostname = ipv6.join(':'); break;
		default: return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address` };
	return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version };
}
async function forwardataudp(udpChunk, webSocket, respHeader) {
	try {
		const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(udpChunk);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				if (webSocket.readyState === 1) {
					if (vlessHeader) {
						const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
						response.set(vlessHeader, 0);
						response.set(chunk, vlessHeader.length);
						webSocket.send(response.buffer);
						vlessHeader = null;
					} else webSocket.send(chunk);
				}
			},
		}));
	} catch (error) {}
}
async function socks5Connect(targetHost, targetPort, initialData) {
	const { username, password, hostname, port } = parsedSocks5Address;
	const socket = connect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	try {
		const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
		await writer.write(authMethods);
		let response = await reader.read();
		if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');
		const selectedMethod = new Uint8Array(response.value)[1];
		if (selectedMethod === 0x02) {
			if (!username || !password) throw new Error('S5 requires authentication');
			const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password);
			const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
			await writer.write(authPacket);
			response = await reader.read();
			if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed');
		} else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method`);
		const hostBytes = new TextEncoder().encode(targetHost);
		const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
		await writer.write(connectPacket);
		response = await reader.read();
		if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed');
		if (initialData && initialData.byteLength > 0) await writer.write(initialData);
		writer.releaseLock(); reader.releaseLock();
		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}
async function httpConnect(targetHost, targetPort, initialData, HTTPS代理 = false) {
	const { username, password, hostname, port } = parsedSocks5Address;
	const socket = HTTPS代理 ? connect({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false }) : connect({ hostname, port });
	const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	const encoder = new TextEncoder(), decoder = new TextDecoder();
	try {
		if (HTTPS代理) await socket.opened;
		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(encoder.encode(request));
		writer.releaseLock();
		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const { done, value } = await reader.read();
			if (done || !value) throw new Error(`HTTP 代理在返回 CONNECT 响应前关闭连接`);
			responseBuffer = new Uint8Array([...responseBuffer, ...value]);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}
		if (headerEndIndex === -1) throw new Error('代理 CONNECT 响应头无效');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);
		reader.releaseLock();
		if (initialData && initialData.byteLength > 0) {
			const rw = socket.writable.getWriter();
			await rw.write(initialData);
			rw.releaseLock();
		}
		if (bytesRead > headerEndIndex) {
			const { readable, writable } = new TransformStream();
			const transformWriter = writable.getWriter();
			await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
			transformWriter.releaseLock();
			socket.readable.pipeTo(writable).catch(() => { });
			return { readable, writable: socket.writable, closed: socket.closed, close: () => socket.close() };
		}
		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}
async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID) {
	const 连接超时毫秒 = 3000;
	let 已通过代理发送首包 = false;
	async function 等待连接建立(remoteSock, timeoutMs = 连接超时毫秒) {
		await Promise.race([ remoteSock.opened, new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), timeoutMs)) ]);
	}
	async function connectDirect(address, port, data = null, fallback = true) {
		let remoteSock;
        if(fallback) {
            const { socket } = await universalConnectWithFailover(address, port);
            remoteSock = socket;
        } else {
            remoteSock = connect({ hostname: address, port: port });
            await 等待连接建立(remoteSock);
        }
		if (data && data.byteLength > 0) {
			const writer = remoteSock.writable.getWriter();
			await writer.write(data);
			writer.releaseLock();
		}
		return remoteSock;
	}
	async function connecttoPry(允许发送首包 = true) {
		if (remoteConnWrapper.connectingPromise) { await remoteConnWrapper.connectingPromise; return; }
		const 本次发送首包 = 允许发送首包 && !已通过代理发送首包 && rawData && rawData.byteLength > 0;
		const 本次首包数据 = 本次发送首包 ? rawData : null;
		const 当前连接任务 = (async () => {
			let newSocket;
			if (cc?.proxyConfig?.type === 'socks5') newSocket = await socks5Connect(host, portNum, 本次首包数据);
			else if (cc?.proxyConfig?.type === 'http') newSocket = await httpConnect(host, portNum, 本次首包数据);
            else if (cc?.proxyConfig?.type === 'https') newSocket = await httpConnect(host, portNum, 本次首包数据, true);
			else newSocket = await connectDirect(host, portNum, 本次首包数据, true);
			if (本次发送首包) 已通过代理发送首包 = true;
			remoteConnWrapper.socket = newSocket;
			newSocket.closed.catch(() => { }).finally(() => safeCloseSocket(ws));
			connectStreams(newSocket, ws, respHeader, null);
		})();
		remoteConnWrapper.connectingPromise = 当前连接任务;
		try { await 当前连接任务; } finally { if (remoteConnWrapper.connectingPromise === 当前连接任务) remoteConnWrapper.connectingPromise = null; }
	}
	remoteConnWrapper.retryConnect = async () => connecttoPry(!已通过代理发送首包);
	if (cc?.proxyConfig?.enabled && cc?.proxyConfig?.global) {
		try { await connecttoPry(); } catch (err) { throw err; }
	} else {
		try {
			const initialSocket = await connectDirect(host, portNum, rawData, false);
			remoteConnWrapper.socket = initialSocket;
			connectStreams(initialSocket, ws, respHeader, async () => {
				if (remoteConnWrapper.socket !== initialSocket) return;
				await connecttoPry();
			});
		} catch (err) { await connecttoPry(); }
	}
}
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
	let header = headerData, hasData = false, reader, useBYOB = false;
	const 发送块 = async (chunk) => {
		if (webSocket.readyState !== 1) throw new Error('ws.readyState is not open');
		if (header) {
			const merged = new Uint8Array(header.length + chunk.byteLength);
			merged.set(header, 0); merged.set(chunk, header.length);
			webSocket.send(merged.buffer);
			header = null;
		} else webSocket.send(chunk);
	};
	try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true } catch (e) { reader = remoteSocket.readable.getReader() }
	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				await 发送块(value instanceof Uint8Array ? value : new Uint8Array(value));
			}
		} else {
			let mainBuf = new ArrayBuffer(512 * 1024), offset = 0;
			while (true) {
				const { done, value } = await reader.read(new Uint8Array(mainBuf, offset, 64 * 1024));
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				mainBuf = value.buffer;
				const len = value.byteLength;
				offset += len;
				if (offset > 0) { const p = new Uint8Array(mainBuf.slice(0, offset)); offset = 0; await 发送块(p); }
			}
		}
	} catch (err) { safeCloseSocket(webSocket) }
	finally { try { reader.cancel() } catch (e) { } try { reader.releaseLock() } catch (e) { } }
	if (!hasData && retryFunc) await retryFunc();
}
function isSpeedTestSite(hostname) {
	const speedTestDomains = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
	if (speedTestDomains.includes(hostname)) return true;
	for (const domain of speedTestDomains) {
		if (hostname.endsWith('.' + domain) || hostname === domain) return true;
	}
	return false;
}
async function handleWSRequest(request, yourUUID, url) {
	const WS套接字对 = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(WS套接字对);
	serverSock.accept();
	serverSock.binaryType = 'arraybuffer';
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let isDnsQuery = false;
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	let 已取消读取 = false, 可读流已结束 = false;
	const readable = new ReadableStream({
		start(controller) {
			const 安全入队 = (data) => { if (已取消读取 || 可读流已结束) return; try { controller.enqueue(data); } catch (err) { 可读流已结束 = true; } };
			const 安全关闭流 = () => { if (已取消读取 || 可读流已结束) return; 可读流已结束 = true; try { controller.close(); } catch (err) { } };
			serverSock.addEventListener('message', (event) => { 安全入队(event.data); });
			serverSock.addEventListener('close', () => { safeCloseWebSocket(serverSock); 安全关闭流(); });
			serverSock.addEventListener('error', (err) => { safeCloseWebSocket(serverSock); 安全关闭流(); });
			if (!earlyDataHeader) return;
			try {
				const binaryString = atob(earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/'));
				const bytes = new Uint8Array(binaryString.length);
				for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
				安全入队(bytes.buffer);
			} catch (error) {}
		},
		cancel() { 已取消读取 = true; 可读流已结束 = true; safeCloseWebSocket(serverSock); }
	});
	let 判断协议类型 = null, 当前写入Socket = null, 远端写入器 = null;
	const 释放远端写入器 = () => { if (远端写入器) { try { 远端写入器.releaseLock() } catch (e) { } 远端写入器 = null; } 当前写入Socket = null; };
	const 写入远端 = async (chunk, allowRetry = true) => {
		const socket = remoteConnWrapper.socket;
		if (!socket) return false;
		if (socket !== 当前写入Socket) { 释放远端写入器(); 当前写入Socket = socket; 远端写入器 = socket.writable.getWriter(); }
		try { await 远端写入器.write(chunk); return true; } catch (err) {
			释放远端写入器();
			if (allowRetry && typeof remoteConnWrapper.retryConnect === 'function') { await remoteConnWrapper.retryConnect(); return await 写入远端(chunk, false); }
			throw err;
		}
	};
	readable.pipeTo(new WritableStream({
		async write(chunk) {
			if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
			if (await 写入远端(chunk)) return;
			if (判断协议类型 === null) {
                const bytes = new Uint8Array(chunk);
                判断协议类型 = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a ? '木马' : '魏烈思';
			}
			if (await 写入远端(chunk)) return;
			if (判断协议类型 === '木马') {
				const 解析结果 = 解析木马请求(chunk, tp || yourUUID);
				if (解析结果?.hasError) throw new Error(解析结果.message);
				const { port, hostname, rawClientData } = 解析结果;
				if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
				await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID);
			} else {
				const 解析结果 = 解析魏烈思请求(chunk, yourUUID);
				if (解析结果?.hasError) throw new Error(解析结果.message);
				const { port, hostname, rawIndex, version, isUDP } = 解析结果;
				if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
				if (isUDP) { if (port === 53) isDnsQuery = true; else throw new Error('UDP is not supported'); }
				const respHeader = new Uint8Array([version[0], 0]);
				const rawData = chunk.slice(rawIndex);
				if (isDnsQuery) return forwardataudp(rawData, serverSock, respHeader);
				await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID);
			}
		},
		close() { 释放远端写入器(); }, abort() { 释放远端写入器(); }
	})).catch(() => { 释放远端写入器(); safeCloseWebSocket(serverSock); });
	return new Response(null, { status: 101, webSocket: clientSock });
}
async function handleGRPCRequest(request, yourUUID) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let isDnsQuery = false, 判断是否是木马 = null, 当前写入Socket = null, 远端写入器 = null;
	const grpcHeaders = new Headers({ 'Content-Type': 'application/grpc', 'grpc-status': '0', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' });
	return new Response(new ReadableStream({
		async start(controller) {
			let 已关闭 = false, 发送队列 = [], 队列字节数 = 0, 刷新定时器 = null;
			const grpcBridge = {
				readyState: 1,
				send(data) {
					if (已关闭) return;
					const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
					const lenBytes数组 = [];
					let remaining = chunk.byteLength >>> 0;
					while (remaining > 127) { lenBytes数组.push((remaining & 0x7f) | 0x80); remaining >>>= 7; }
					lenBytes数组.push(remaining);
					const lenBytes = new Uint8Array(lenBytes数组);
					const protobufLen = 1 + lenBytes.length + chunk.byteLength;
					const frame = new Uint8Array(5 + protobufLen);
					frame[0] = 0; frame[1] = (protobufLen >>> 24) & 0xff; frame[2] = (protobufLen >>> 16) & 0xff; frame[3] = (protobufLen >>> 8) & 0xff; frame[4] = protobufLen & 0xff; frame[5] = 0x0a;
					frame.set(lenBytes, 6); frame.set(chunk, 6 + lenBytes.length);
					发送队列.push(frame); 队列字节数 += frame.byteLength;
					if (队列字节数 >= 64 * 1024) 刷新发送队列(); else if (!刷新定时器) 刷新定时器 = setTimeout(刷新发送队列, 20);
				},
				close() {
					if (this.readyState === 3) return;
					刷新发送队列(true); 已关闭 = true; this.readyState = 3; try { controller.close() } catch (e) { }
				}
			};
			const 刷新发送队列 = (force = false) => {
				if (刷新定时器) { clearTimeout(刷新定时器); 刷新定时器 = null; }
				if ((!force && 已关闭) || 队列字节数 === 0) return;
				const out = new Uint8Array(队列字节数);
				let offset = 0;
				for (const item of 发送队列) { out.set(item, offset); offset += item.byteLength; }
				发送队列 = []; 队列字节数 = 0;
				try { controller.enqueue(out); } catch (e) { 已关闭 = true; grpcBridge.readyState = 3; }
			};
			const 关闭连接 = () => {
				if (已关闭) return; 刷新发送队列(true); 已关闭 = true; grpcBridge.readyState = 3;
				if (刷新定时器) clearTimeout(刷新定时器);
				if (远端写入器) { try { 远端写入器.releaseLock() } catch (e) { } 远端写入器 = null; }
				当前写入Socket = null; try { reader.releaseLock() } catch (e) { } try { remoteConnWrapper.socket?.close() } catch (e) { } try { controller.close() } catch (e) { }
			};
			const 释放远端写入器 = () => { if (远端写入器) { try { 远端写入器.releaseLock() } catch (e) { } 远端写入器 = null; } 当前写入Socket = null; };
			const 写入远端 = async (payload, allowRetry = true) => {
				const socket = remoteConnWrapper.socket; if (!socket) return false;
				if (socket !== 当前写入Socket) { 释放远端写入器(); 当前写入Socket = socket; 远端写入器 = socket.writable.getWriter(); }
				try { await 远端写入器.write(payload); return true; } catch (err) {
					释放远端写入器();
					if (allowRetry && typeof remoteConnWrapper.retryConnect === 'function') { await remoteConnWrapper.retryConnect(); return await 写入远端(payload, false); }
					throw err;
				}
			};
			try {
				let pending = new Uint8Array(0);
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					const 当前块 = value instanceof Uint8Array ? value : new Uint8Array(value);
					const merged = new Uint8Array(pending.length + 当前块.length);
					merged.set(pending, 0); merged.set(当前块, pending.length); pending = merged;
					while (pending.byteLength >= 5) {
						const grpcLen = ((pending[1] << 24) >>> 0) | (pending[2] << 16) | (pending[3] << 8) | pending[4];
						const frameSize = 5 + grpcLen;
						if (pending.byteLength < frameSize) break;
						const grpcPayload = pending.slice(5, frameSize); pending = pending.slice(frameSize);
						if (!grpcPayload.byteLength) continue;
						let payload = grpcPayload;
						if (payload.byteLength >= 2 && payload[0] === 0x0a) {
							let shift = 0, offset = 1, varint有效 = false;
							while (offset < payload.length) {
								const current = payload[offset++];
								if ((current & 0x80) === 0) { varint有效 = true; break; }
								shift += 7; if (shift > 35) break;
							}
							if (varint有效) payload = payload.slice(offset);
						}
						if (!payload.byteLength) continue;
						if (isDnsQuery) { await forwardataudp(payload, grpcBridge, null); continue; }
						if (remoteConnWrapper.socket) { if (!(await 写入远端(payload))) throw new Error('Remote socket is not ready'); }
						else {
							let 首包buffer;
							if (payload instanceof ArrayBuffer) 首包buffer = payload;
							else if (ArrayBuffer.isView(payload)) 首包buffer = payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength);
							else 首包buffer = new Uint8Array(payload).buffer;
							const 首包bytes = new Uint8Array(首包buffer);
							if (判断是否是木马 === null) 判断是否是木马 = 首包bytes.byteLength >= 58 && 首包bytes[56] === 0x0d && 首包bytes[57] === 0x0a;
							if (判断是否是木马) {
								const 解析结果 = 解析木马请求(首包buffer, tp || yourUUID);
								if (解析结果?.hasError) throw new Error(解析结果.message);
								const { port, hostname, rawClientData } = 解析结果;
								if (isSpeedTestSite(hostname)) throw new Error('Speedtest blocked');
								await forwardataTCP(hostname, port, rawClientData, grpcBridge, null, remoteConnWrapper, yourUUID);
							} else {
								const 解析结果 = 解析魏烈思请求(首包buffer, yourUUID);
								if (解析结果?.hasError) throw new Error(解析结果.message);
								const { port, hostname, rawIndex, version, isUDP } = 解析结果;
								if (isSpeedTestSite(hostname)) throw new Error('Speedtest blocked');
								if (isUDP) { if (port !== 53) throw new Error('UDP not supported'); isDnsQuery = true; }
								const respHeader = new Uint8Array([version[0], 0]);
								grpcBridge.send(respHeader);
								const rawData = 首包buffer.slice(rawIndex);
								if (isDnsQuery) await forwardataudp(rawData, grpcBridge, null);
								else await forwardataTCP(hostname, port, rawData, grpcBridge, null, remoteConnWrapper, yourUUID);
							}
						}
					}
					刷新发送队列();
				}
			} catch (err) {} finally { 释放远端写入器(); 关闭连接(); }
		},
		cancel() { try { remoteConnWrapper.socket?.close() } catch (e) { } try { reader.releaseLock() } catch (e) { } }
	}), { status: 200, headers: grpcHeaders });
}
async function 读取XHTTP首包(reader, token) {
	const decoder = new TextDecoder();
	const 密码哈希 = sha224(tp || token);
	const 密码哈希字节 = new TextEncoder().encode(密码哈希);
	const 尝试解析VLESS首包 = (data) => {
		const length = data.byteLength;
		if (length < 18) return { 状态: 'need_more' };
		if (formatIdentifier(data.subarray(1, 17)) !== token) return { 状态: 'invalid' };
		const optLen = data[17]; const cmdIndex = 18 + optLen;
		if (length < cmdIndex + 1) return { 状态: 'need_more' };
		const cmd = data[cmdIndex]; if (cmd !== 1 && cmd !== 2) return { 状态: 'invalid' };
		const portIndex = cmdIndex + 1; if (length < portIndex + 3) return { 状态: 'need_more' };
		const port = (data[portIndex] << 8) | data[portIndex + 1]; const addressType = data[portIndex + 2];
		const addressIndex = portIndex + 3; let headerLen = -1, hostname = '';
		if (addressType === 1) { if (length < addressIndex + 4) return { 状态: 'need_more' }; hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`; headerLen = addressIndex + 4; }
		else if (addressType === 2) { if (length < addressIndex + 1) return { 状态: 'need_more' }; const domainLen = data[addressIndex]; if (length < addressIndex + 1 + domainLen) return { 状态: 'need_more' }; hostname = decoder.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen)); headerLen = addressIndex + 1 + domainLen; }
		else if (addressType === 3) { if (length < addressIndex + 16) return { 状态: 'need_more' }; const ipv6 = []; for (let i = 0; i < 8; i++) { const base = addressIndex + i * 2; ipv6.push(((data[base] << 8) | data[base + 1]).toString(16)); } hostname = ipv6.join(':'); headerLen = addressIndex + 16; }
		else return { 状态: 'invalid' };
		if (!hostname) return { 状态: 'invalid' };
		return { 状态: 'ok', 结果: { 协议: 'vless', hostname, port, isUDP: cmd === 2, rawData: data.subarray(headerLen), respHeader: new Uint8Array([data[0], 0]) } };
	};
	const 尝试解析木马首包 = (data) => {
		const length = data.byteLength;
		if (length < 58) return { 状态: 'need_more' };
		if (data[56] !== 0x0d || data[57] !== 0x0a) return { 状态: 'invalid' };
		for (let i = 0; i < 56; i++) { if (data[i] !== 密码哈希字节[i]) return { 状态: 'invalid' }; }
		const socksStart = 58; if (length < socksStart + 2) return { 状态: 'need_more' };
		const cmd = data[socksStart]; if (cmd !== 1) return { 状态: 'invalid' };
		const atype = data[socksStart + 1]; let cursor = socksStart + 2, hostname = '';
		if (atype === 1) { if (length < cursor + 4) return { 状态: 'need_more' }; hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`; cursor += 4; }
		else if (atype === 3) { if (length < cursor + 1) return { 状态: 'need_more' }; const domainLen = data[cursor]; if (length < cursor + 1 + domainLen) return { 状态: 'need_more' }; hostname = decoder.decode(data.subarray(cursor + 1, cursor + 1 + domainLen)); cursor += 1 + domainLen; }
		else if (atype === 4) { if (length < cursor + 16) return { 状态: 'need_more' }; const ipv6 = []; for (let i = 0; i < 8; i++) { const base = cursor + i * 2; ipv6.push(((data[base] << 8) | data[base + 1]).toString(16)); } hostname = ipv6.join(':'); cursor += 16; }
		else return { 状态: 'invalid' };
		if (!hostname) return { 状态: 'invalid' };
		if (length < cursor + 4) return { 状态: 'need_more' };
		const port = (data[cursor] << 8) | data[cursor + 1];
		if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { 状态: 'invalid' };
		return { 状态: 'ok', 结果: { 协议: 'trojan', hostname, port, isUDP: false, rawData: data.subarray(cursor + 4), respHeader: null } };
	};
	let buffer = new Uint8Array(1024), offset = 0;
	while (true) {
		const { value, done } = await reader.read();
		if (done) { if (offset === 0) return null; break; }
		const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
		if (offset + chunk.byteLength > buffer.byteLength) { const newBuffer = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength)); newBuffer.set(buffer.subarray(0, offset)); buffer = newBuffer; }
		buffer.set(chunk, offset); offset += chunk.byteLength;
		const 当前数据 = buffer.subarray(0, offset);
		const 木马结果 = 尝试解析木马首包(当前数据); if (木马结果.状态 === 'ok') return { ...木马结果.结果, reader };
		const vless结果 = 尝试解析VLESS首包(当前数据); if (vless结果.状态 === 'ok') return { ...vless结果.结果, reader };
		if (木马结果.状态 === 'invalid' && vless结果.状态 === 'invalid') return null;
	}
	const 最终数据 = buffer.subarray(0, offset);
	const 最终木马结果 = 尝试解析木马首包(最终数据); if (最终木马结果.状态 === 'ok') return { ...最终木马结果.结果, reader };
	const 最终VLESS结果 = 尝试解析VLESS首包(最终数据); if (最终VLESS结果.状态 === 'ok') return { ...最终VLESS结果.结果, reader };
	return null;
}
async function handleXHTTPRequest(request, yourUUID) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const 首包 = await 读取XHTTP首包(reader, yourUUID);
	if (!首包) { try { reader.releaseLock() } catch (e) { } return new Response('Invalid request', { status: 400 }); }
	if (isSpeedTestSite(首包.hostname)) { try { reader.releaseLock() } catch (e) { } return new Response('Forbidden', { status: 403 }); }
	if (首包.isUDP && 首包.port !== 53) { try { reader.releaseLock() } catch (e) { } return new Response('UDP is not supported', { status: 400 }); }
	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let 当前写入Socket = null, 远端写入器 = null;
	const responseHeaders = new Headers({ 'Content-Type': 'application/octet-stream', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' });
	const 释放远端写入器 = () => { if (远端写入器) { try { 远端写入器.releaseLock() } catch (e) { } 远端写入器 = null; } 当前写入Socket = null; };
	const 获取远端写入器 = () => { const socket = remoteConnWrapper.socket; if (!socket) return null; if (socket !== 当前写入Socket) { 释放远端写入器(); 当前写入Socket = socket; 远端写入器 = socket.writable.getWriter(); } return 远端写入器; };
	return new Response(new ReadableStream({
		async start(controller) {
			let 已关闭 = false, udpRespHeader = 首包.respHeader;
			const xhttpBridge = {
				readyState: 1,
				send(data) {
					if (已关闭) return;
					try { const chunk = data instanceof Uint8Array ? data : data instanceof ArrayBuffer ? new Uint8Array(data) : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data); controller.enqueue(chunk); }
					catch (e) { 已关闭 = true; this.readyState = 3; }
				},
				close() { if (已关闭) return; 已关闭 = true; this.readyState = 3; try { controller.close() } catch (e) { } }
			};
			const 写入远端 = async (payload, allowRetry = true) => {
				const writer = 获取远端写入器(); if (!writer) return false;
				try { await writer.write(payload); return true; } catch (err) {
					释放远端写入器();
					if (allowRetry && typeof remoteConnWrapper.retryConnect === 'function') { await remoteConnWrapper.retryConnect(); return await 写入远端(payload, false); }
					throw err;
				}
			};
			try {
				if (首包.isUDP) { if (首包.rawData?.byteLength) { await forwardataudp(首包.rawData, xhttpBridge, udpRespHeader); udpRespHeader = null; } }
				else await forwardataTCP(首包.hostname, 首包.port, 首包.rawData, xhttpBridge, 首包.respHeader, remoteConnWrapper, yourUUID);
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					if (首包.isUDP) { await forwardataudp(value, xhttpBridge, udpRespHeader); udpRespHeader = null; }
					else if (!(await 写入远端(value))) throw new Error('Remote socket is not ready');
				}
				if (!首包.isUDP) { const writer = 获取远端写入器(); if (writer) { try { await writer.close() } catch (e) { } } }
			} catch (err) { safeCloseSocket(xhttpBridge); }
			finally { 释放远端写入器(); try { reader.releaseLock() } catch (e) { } }
		},
		cancel() { 释放远端写入器(); try { remoteConnWrapper.socket?.close() } catch (e) { } try { reader.releaseLock() } catch (e) { } }
	}), { status: 200, headers: responseHeaders });
}
function Clash订阅配置文件热补丁(Clash_原始订阅内容, config_JSON) {
	const uuid = config_JSON.uid;
	const ECH启用 = config_JSON.transConfig?.ech;
	const HOSTS = [config_JSON.host];
	const ECH_SNI = config_JSON.transConfig?.ech_sni || null;
	const ECH_DNS = "https://dns.alidns.com/dns-query";
	const gRPCUserAgent = "Mozilla/5.0";
	const 需要处理gRPC = config_JSON.transConfig?.grpc;
	const gRPCUserAgentYAML = JSON.stringify(gRPCUserAgent);
	let clash_yaml = Clash_原始订阅内容.replace(/mode:\s*Rule\b/g, 'mode: rule');
	const baseDnsBlock = `dns:\n  enable: true\n  default-nameserver:\n    - 223.5.5.5\n    - 114.114.114.114\n  use-hosts: true\n  nameserver:\n    - https://sm2.doh.pub/dns-query\n    - https://dns.alidns.com/dns-query\n  fallback:\n    - 8.8.4.4\n`;
	const 添加InlineGrpcUserAgent = (text) => text.replace(/grpc-opts:\s*\{([\s\S]*?)\}/i, (all, inner) => {
		if (/grpc-user-agent\s*:/i.test(inner)) return all;
		let content = inner.trim(); if (content.endsWith(',')) content = content.slice(0, -1).trim();
		return `grpc-opts: {${content ? `${content}, grpc-user-agent: ${gRPCUserAgentYAML}` : `grpc-user-agent: ${gRPCUserAgentYAML}`}}`;
	});
	const 匹配到gRPC网络 = (text) => /(?:^|[,{])\s*network:\s*(?:"grpc"|'grpc'|grpc)(?=\s*(?:[,}\n#]|$))/mi.test(text);
	const 获取代理类型 = (nodeText) => nodeText.match(/type:\s*(\w+)/)?.[1] || 'vless';
	const 获取凭据值 = (nodeText, isFlowStyle) => {
		const credentialField = 获取代理类型(nodeText) === 'trojan' ? 'password' : 'uuid';
		const pattern = new RegExp(`${credentialField}:\\s*${isFlowStyle ? '([^,}\\n]+)' : '([^\\n]+)'}`);
		return nodeText.match(pattern)?.[1]?.trim() || null;
	};
	const 插入NameserverPolicy = (yaml, hostsEntries) => {
		if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yaml)) return yaml.replace(/^(\s{2}nameserver-policy:\s*\n)/m, `$1${hostsEntries}\n`);
		const lines = yaml.split('\n'); let dnsBlockEndIndex = -1, inDnsBlock = false;
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (/^dns:\s*$/.test(line)) { inDnsBlock = true; continue; }
			if (inDnsBlock && /^[a-zA-Z]/.test(line)) { dnsBlockEndIndex = i; break; }
		}
		const nameserverPolicyBlock = `  nameserver-policy:\n${hostsEntries}`;
		if (dnsBlockEndIndex !== -1) lines.splice(dnsBlockEndIndex, 0, nameserverPolicyBlock); else lines.push(nameserverPolicyBlock);
		return lines.join('\n');
	};
	const 添加Flow格式gRPCUserAgent = (nodeText) => {
		if (!匹配到gRPC网络(nodeText) || /grpc-user-agent\s*:/i.test(nodeText)) return nodeText;
		if (/grpc-opts:\s*\{/i.test(nodeText)) return 添加InlineGrpcUserAgent(nodeText);
		return nodeText.replace(/\}(\s*)$/, `, grpc-opts: {grpc-user-agent: ${gRPCUserAgentYAML}}}$1`);
	};
	const 添加Block格式gRPCUserAgent = (nodeLines, topLevelIndent) => {
		const 顶级缩进 = ' '.repeat(topLevelIndent); let grpcOptsIndex = -1;
		for (let idx = 0; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx]; if (!line.trim()) continue;
			const indent = line.search(/\S/); if (indent !== topLevelIndent) continue;
			if (/^\s*grpc-opts:\s*(?:#.*)?$/.test(line) || /^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(line)) { grpcOptsIndex = idx; break; }
		}
		if (grpcOptsIndex === -1) {
			let insertIndex = -1;
			for (let j = nodeLines.length - 1; j >= 0; j--) { if (nodeLines[j].trim()) { insertIndex = j; break; } }
			if (insertIndex >= 0) nodeLines.splice(insertIndex + 1, 0, `${顶级缩进}grpc-opts:`, `${顶级缩进}  grpc-user-agent: ${gRPCUserAgentYAML}`);
			return nodeLines;
		}
		const grpcLine = nodeLines[grpcOptsIndex];
		if (/^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(grpcLine)) { if (!/grpc-user-agent\s*:/i.test(grpcLine)) nodeLines[grpcOptsIndex] = 添加InlineGrpcUserAgent(grpcLine); return nodeLines; }
		let blockEndIndex = nodeLines.length, 子级缩进 = topLevelIndent + 2, 已有gRPCUserAgent = false;
		for (let idx = grpcOptsIndex + 1; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx], trimmed = line.trim(); if (!trimmed) continue;
			const indent = line.search(/\S/); if (indent <= topLevelIndent) { blockEndIndex = idx; break; }
			if (indent > topLevelIndent && 子级缩进 === topLevelIndent + 2) 子级缩进 = indent;
			if (/^grpc-user-agent\s*:/.test(trimmed)) { 已有gRPCUserAgent = true; break; }
		}
		if (!已有gRPCUserAgent) nodeLines.splice(blockEndIndex, 0, `${' '.repeat(子级缩进)}grpc-user-agent: ${gRPCUserAgentYAML}`);
		return nodeLines;
	};
	const 添加Block格式ECHOpts = (nodeLines, topLevelIndent) => {
		let insertIndex = -1;
		for (let j = nodeLines.length - 1; j >= 0; j--) { if (nodeLines[j].trim()) { insertIndex = j; break; } }
		if (insertIndex < 0) return nodeLines;
		const indent = ' '.repeat(topLevelIndent);
		const echOptsLines = [`${indent}ech-opts:`, `${indent}  enable: true`];
		if (ECH_SNI) echOptsLines.push(`${indent}  query-server-name: ${ECH_SNI}`);
		nodeLines.splice(insertIndex + 1, 0, ...echOptsLines);
		return nodeLines;
	};
	if (!/^dns:\s*(?:\n|$)/m.test(clash_yaml)) clash_yaml = baseDnsBlock + clash_yaml;
	if (ECH_SNI && !HOSTS.includes(ECH_SNI)) HOSTS.push(ECH_SNI);
	if (ECH启用 && HOSTS.length > 0) {
		const hostsEntries = HOSTS.map(host => `    "${host}":\n      - ${ECH_DNS}\n      - https://doh.cm.edu.kg/CMLiussss`).join('\n');
		clash_yaml = 插入NameserverPolicy(clash_yaml, hostsEntries);
	}
	if (!ECH启用 && !需要处理gRPC) return clash_yaml;
	const lines = clash_yaml.split('\n'); const processedLines = []; let i = 0;
	while (i < lines.length) {
		const line = lines[i], trimmedLine = line.trim();
		if (trimmedLine.startsWith('- {')) {
			let fullNode = line, braceCount = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
			while (braceCount > 0 && i + 1 < lines.length) { i++; fullNode += '\n' + lines[i]; braceCount += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length; }
			if (需要处理gRPC) fullNode = 添加Flow格式gRPCUserAgent(fullNode);
			if (ECH启用 && 获取凭据值(fullNode, true) === uuid.trim()) { fullNode = fullNode.replace(/\}(\s*)$/, `, ech-opts: {enable: true${ECH_SNI ? `, query-server-name: ${ECH_SNI}` : ''}}}$1`); }
			processedLines.push(fullNode); i++;
		} else if (trimmedLine.startsWith('- name:')) {
			let nodeLines = [line], baseIndent = line.search(/\S/), topLevelIndent = baseIndent + 2; i++;
			while (i < lines.length) {
				const nextLine = lines[i], nextTrimmed = nextLine.trim();
				if (!nextTrimmed) { nodeLines.push(nextLine); i++; break; }
				const nextIndent = nextLine.search(/\S/);
				if (nextIndent <= baseIndent && nextTrimmed.startsWith('- ')) break;
				if (nextIndent < baseIndent && nextTrimmed) break;
				nodeLines.push(nextLine); i++;
			}
			let nodeText = nodeLines.join('\n');
			if (需要处理gRPC && 匹配到gRPC网络(nodeText)) { nodeLines = 添加Block格式gRPCUserAgent(nodeLines, topLevelIndent); nodeText = nodeLines.join('\n'); }
			if (ECH启用 && 获取凭据值(nodeText, false) === uuid.trim()) nodeLines = 添加Block格式ECHOpts(nodeLines, topLevelIndent);
			processedLines.push(...nodeLines);
		} else { processedLines.push(line); i++; }
	}
	return processedLines.join('\n');
}
async function Singbox订阅配置文件热补丁(SingBox_原始订阅内容, config_JSON) {
	const uuid = config_JSON.uid;
	const fingerprint = "chrome";
	const ECH_SNI = config_JSON.transConfig?.ech_sni || config_JSON.host || null;
	const ech_config = config_JSON.transConfig?.ech && ECH_SNI ? await getECH(ECH_SNI) : null;
	const sb_json_text = SingBox_原始订阅内容.replace('1.1.1.1', '8.8.8.8').replace('1.0.0.1', '8.8.4.4');
	try {
		let config = JSON.parse(sb_json_text);
		if (Array.isArray(config.inbounds)) {
			config.inbounds.forEach(inbound => {
				if (inbound.type === 'tun') {
					const addresses = [];
					if (inbound.inet4_address) addresses.push(inbound.inet4_address);
					if (inbound.inet6_address) addresses.push(inbound.inet6_address);
					if (addresses.length > 0) { inbound.address = addresses; delete inbound.inet4_address; delete inbound.inet6_address; }
					const route_addresses = [];
					if (Array.isArray(inbound.inet4_route_address)) route_addresses.push(...inbound.inet4_route_address);
					if (Array.isArray(inbound.inet6_route_address)) route_addresses.push(...inbound.inet6_route_address);
					if (route_addresses.length > 0) { inbound.route_address = route_addresses; delete inbound.inet4_route_address; delete inbound.inet6_route_address; }
					const route_exclude_addresses = [];
					if (Array.isArray(inbound.inet4_route_exclude_address)) route_exclude_addresses.push(...inbound.inet4_route_exclude_address);
					if (Array.isArray(inbound.inet6_route_exclude_address)) route_exclude_addresses.push(...inbound.inet6_route_exclude_address);
					if (route_exclude_addresses.length > 0) { inbound.route_exclude_address = route_exclude_addresses; delete inbound.inet4_route_exclude_address; delete inbound.inet6_route_exclude_address; }
				}
			});
		}
		const ruleSetsDefinitions = new Map();
		const processRules = (rules, isDns = false) => {
			if (!Array.isArray(rules)) return;
			rules.forEach(rule => {
				if (rule.geosite) {
					const geositeList = Array.isArray(rule.geosite) ? rule.geosite : [rule.geosite];
					rule.rule_set = geositeList.map(name => {
						const tag = `geosite-${name}`;
						if (!ruleSetsDefinitions.has(tag)) ruleSetsDefinitions.set(tag, { tag: tag, type: "remote", format: "binary", url: `https://gh.090227.xyz/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-${name}.srs`, download_detour: "DIRECT" });
						return tag;
					});
					delete rule.geosite;
				}
				if (rule.geoip) {
					const geoipList = Array.isArray(rule.geoip) ? rule.geoip : [rule.geoip];
					rule.rule_set = rule.rule_set || [];
					geoipList.forEach(name => {
						const tag = `geoip-${name}`;
						if (!ruleSetsDefinitions.has(tag)) ruleSetsDefinitions.set(tag, { tag: tag, type: "remote", format: "binary", url: `https://gh.090227.xyz/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-${name}.srs`, download_detour: "DIRECT" });
						rule.rule_set.push(tag);
					});
					delete rule.geoip;
				}
				const targetField = isDns ? 'server' : 'outbound';
				const actionValue = String(rule[targetField]).toUpperCase();
				if (actionValue === 'REJECT' || actionValue === 'BLOCK') { rule.action = 'reject'; rule.method = 'drop'; delete rule[targetField]; }
			});
		};
		if (config.dns && config.dns.rules) processRules(config.dns.rules, true);
		if (config.route && config.route.rules) processRules(config.route.rules, false);
		if (ruleSetsDefinitions.size > 0) { if (!config.route) config.route = {}; config.route.rule_set = Array.from(ruleSetsDefinitions.values()); }
		if (!config.outbounds) config.outbounds = [];
		config.outbounds = config.outbounds.filter(o => o.tag !== 'REJECT' && o.tag !== 'block');
		const existingOutboundTags = new Set(config.outbounds.map(o => o.tag));
		if (!existingOutboundTags.has('DIRECT')) { config.outbounds.push({ "type": "direct", "tag": "DIRECT" }); existingOutboundTags.add('DIRECT'); }
		if (config.dns && config.dns.servers) {
			const dnsServerTags = new Set(config.dns.servers.map(s => s.tag));
			if (config.dns.rules) {
				config.dns.rules.forEach(rule => {
					if (rule.server && !dnsServerTags.has(rule.server)) {
						if (rule.server === 'dns_block' && dnsServerTags.has('block')) rule.server = 'block';
						else if (rule.server.toLowerCase().includes('block') && !dnsServerTags.has(rule.server)) { config.dns.servers.push({ "tag": rule.server, "address": "rcode://success" }); dnsServerTags.add(rule.server); }
					}
				});
			}
		}
		config.outbounds.forEach(outbound => {
			if (outbound.type === 'selector' || outbound.type === 'urltest') {
				if (Array.isArray(outbound.outbounds)) {
					outbound.outbounds = outbound.outbounds.filter(tag => { const upperTag = tag.toUpperCase(); return existingOutboundTags.has(tag) && upperTag !== 'REJECT' && upperTag !== 'BLOCK'; });
					if (outbound.outbounds.length === 0) outbound.outbounds.push("DIRECT");
				}
			}
		});
		if (uuid) {
			config.outbounds.forEach(outbound => {
				if ((outbound.uuid && outbound.uuid === uuid) || (outbound.password && outbound.password === uuid) || (outbound.method && String(outbound.password).includes(uuid))) {
					if (!outbound.tls) outbound.tls = { enabled: true };
					if (fingerprint) outbound.tls.utls = { enabled: true, fingerprint: fingerprint };
					if (ech_config) outbound.tls.ech = { enabled: true, config: `-----BEGIN ECH CONFIGS-----\n${ech_config}\n-----END ECH CONFIGS-----` };
				}
			});
		}
		return JSON.stringify(config, null, 2);
	} catch (e) { return JSON.stringify(JSON.parse(sb_json_text), null, 2); }
}
async function genSurgeConfig(u, url) {
    if (!u) return '';
    const wp = '/?ed=2560';
    const nodes = []; const nodeNames = [];
    if (et) {
        const password = tp || u;
        yx.forEach(item => {
            const ipData = IPParser.parsePreferredIP(item);
            if (!ipData) return;
            const { hostname, port, displayName } = ipData;
            const nodeConfig = `${displayName} = trojan, ${hostname}, ${port}, password=${password}, sni=${url}, skip-cert-verify=true, ws=true, ws-path=${wp}, ws-headers=Host:"${url}", tfo=true`;
            nodes.push(nodeConfig); nodeNames.push(displayName);
        });
    }
    if (nodes.length === 0) return '未启用Trojan协议';
    if (stp) {
        try {
            const response = await fetch(stp);
            if (response.ok) {
                let templateContent = await response.text();
                templateContent = templateContent.replace(/\{nodes\}/g, nodes.join('\n'));
                templateContent = templateContent.replace(/\{names\}/g, nodeNames.join(', '));
                return templateContent;
            }
        } catch (e) {}
    }
    return `#!MANAGED-CONFIG https://${url}/${u}?format=surge interval=86400 strict=true\n\n[General]\nskip-proxy = 192.168.0.0/24, 10.0.0.0/8, 172.16.0.0/12, 127.0.0.1, localhost, *.local\nexclude-simple-hostnames = true\ndns-server = 223.5.5.5, 114.114.114.114\nwifi-assist = true\nipv6 = false\n\n[Proxy]\n${nodes.join('\n')}\n[Proxy Group]\n🌎 节点选择 = select, ${nodeNames.join(', ')}\n\n[Rule]\nRULE-SET,https://github.com/Blankwonder/surge-list/raw/master/blocked.list,🌎 节点选择\nRULE-SET,https://github.com/Blankwonder/surge-list/raw/master/cn.list,DIRECT\nRULE-SET,SYSTEM,🌎 节点选择\nRULE-SET,LAN,DIRECT\nGEOIP,CN,DIRECT\nFINAL, 🌎 节点选择,dns-failed`;
}
function genConfig(u, url) {
    if (!u) return '';
    const wp = '/?ed=2560', ep = encodeURIComponent(wp);
    const links = [];
    if (ev) {
        const hd = 'vless';
        links.push(...yx.map(item => {
            const ipData = IPParser.parsePreferredIP(item);
            if (!ipData) return null;
            const tps = cc?.transConfig?.grpc ? `type=grpc&serviceName=` : (cc?.transConfig?.xhttp ? `type=xhttp&path=${ep}` : `type=ws&path=${ep}`);
            return `${hd}://${u}@${ipData.hostname}:${ipData.port}?encryption=none&security=tls&sni=${url}&fp=chrome&${tps}&host=${url}&tfo=1#${encodeURIComponent('Vless-' + ipData.displayName)}`;
        }).filter(Boolean));
    }
    if (et) {
        const hd = 'trojan', password = tp || u;
        links.push(...yx.map(item => {
            const ipData = IPParser.parsePreferredIP(item);
            if (!ipData) return null;
            const tps = cc?.transConfig?.grpc ? `type=grpc&serviceName=` : (cc?.transConfig?.xhttp ? `type=xhttp&path=${ep}` : `type=ws&path=${ep}`);
            return `${hd}://${password}@${ipData.hostname}:${ipData.port}?security=tls&sni=${url}&fp=chrome&${tps}&host=${url}&tfo=1#${encodeURIComponent('Trojan-' + ipData.displayName)}`;
        }).filter(Boolean));
    }
    return links.join('\n');
}
async function sub(req) {
    const url = new URL(req.url);
    const host = req.headers.get('Host');
    const format = url.searchParams.get('format') || url.searchParams.get('target');
    const target = format;
    const cfg = genConfig(uid, host);
    if (target === 'surge') return ResponseBuilder.text(await genSurgeConfig(uid, host));
    if (target === 'clash' || target === 'singbox') {
        const backend = cc?.dyhd || dyhd;
        const config = cc?.dypz || dypz;
        const rawSubUrl = `https://${host}/${uid}`;
        const subApi = `${backend}?target=${target}&url=${encodeURIComponent(rawSubUrl)}&config=${encodeURIComponent(config)}&emoji=true&scv=false`;
        try {
            const res = await fetch(subApi, { headers: { 'User-Agent': 'Subconverter edge' }});
            if (res.ok) {
                let content = await res.text();
                if (target === 'clash') content = Clash订阅配置文件热补丁(content, { uid, host, transConfig: cc?.transConfig });
                if (target === 'singbox') content = await Singbox订阅配置文件热补丁(content, { uid, host, transConfig: cc?.transConfig });
                return ResponseBuilder.text(content);
            }
        } catch(e) {}
    }
    return ResponseBuilder.text(btoa(cfg));
}
async function getCloudflareUsageAPI(env) {
    const now = Date.now();
    if (cachedUsage && (now - lastUsageTime < 300000)) return cachedUsage;
    if (!cc?.cfConfig) return { success: false, pages: 0, workers: 0, total: 0 };
    const { accountId, apiToken } = cc.cfConfig;
    if (!apiToken) return { success: false, pages: 0, workers: 0, total: 0 };
    const API = "https://api.cloudflare.com/client/v4";
    const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
    const headers = { "Authorization": `Bearer ${apiToken}`, "Content-Type": "application/json" };
    try {
        let AccountID = accountId;
        if (!AccountID) {
            const r = await fetch(`${API}/accounts`, { method: "GET", headers });
            if (r.ok) { const d = await r.json(); if (d?.result?.length > 0) AccountID = d.result[0].id; }
        }
        if (!AccountID) return { success: false, pages: 0, workers: 0, total: 0 };
        const dateNow = new Date(); dateNow.setUTCHours(0, 0, 0, 0);
        const res = await fetch(`${API}/graphql`, { method: "POST", headers, body: JSON.stringify({ query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) { viewer { accounts(filter: {accountTag: $AccountID}) { pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } } workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } } } } }`, variables: { AccountID, filter: { datetime_geq: dateNow.toISOString(), datetime_leq: new Date().toISOString() } } }) });
        if (!res.ok) return { success: false, pages: 0, workers: 0, total: 0 };
        const result = await res.json();
        const acc = result?.data?.viewer?.accounts?.[0];
        if (!acc) return { success: false, pages: 0, workers: 0, total: 0 };
        const usageResult = { success: true, pages: sum(acc.pagesFunctionsInvocationsAdaptiveGroups), workers: sum(acc.workersInvocationsAdaptive), total: sum(acc.pagesFunctionsInvocationsAdaptiveGroups) + sum(acc.workersInvocationsAdaptive) };
        cachedUsage = usageResult; lastUsageTime = now;
        return usageResult;
    } catch (error) { return { success: false, pages: 0, workers: 0, total: 0 }; }
}
function getCommonCSS() {
    return `:root { --primary: #4f46e5; --primary-hover: #4338ca; --secondary: #64748b; --bg-grad-1: hsla(253,16%,7%,1); --bg-grad-2: hsla(225,39%,30%,1); --bg-grad-3: hsla(339,49%,30%,1); --surface: rgba(255, 255, 255, 0.9); --glass: blur(12px) saturate(180%); --text: #1e293b; --text-light: #64748b; --border: rgba(226, 232, 240, 0.8); --shadow: 0 10px 30px -10px rgba(0,0,0,0.1); --radius: 16px; } @media (prefers-color-scheme: dark) { :root { --primary: #818cf8; --primary-hover: #6366f1; --secondary: #94a3b8; --surface: rgba(30, 41, 59, 0.85); --text: #f1f5f9; --text-light: #94a3b8; --border: rgba(51, 65, 85, 0.8); --shadow: 0 10px 30px -10px rgba(0,0,0,0.5); } } * { box-sizing: border-box; } body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #0f172a; background-image: radial-gradient(at 0% 0%, var(--bg-grad-1) 0, transparent 50%), radial-gradient(at 50% 0%, var(--bg-grad-2) 0, transparent 50%), radial-gradient(at 100% 0%, var(--bg-grad-3) 0, transparent 50%); background-attachment: fixed; color: var(--text); margin: 0; min-height: 100vh; width: 100vw; overflow-x: hidden; display: flex; flex-direction: column; align-items: center; justify-content: center; -webkit-font-smoothing: antialiased; padding: 1rem; } .card { background: var(--surface); backdrop-filter: var(--glass); -webkit-backdrop-filter: var(--glass); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); padding: 2.5rem; width: 100%; max-width: 100%; transition: transform 0.2s ease; } .logo { font-size: 3rem; margin-bottom: 1rem; background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; display: inline-block; filter: drop-shadow(0 2px 4px rgba(99, 102, 241, 0.3)); } h1 { font-size: 1.75rem; font-weight: 700; margin: 0 0 0.5rem 0; letter-spacing: -0.025em; } p { color: var(--text-light); line-height: 1.6; margin-bottom: 1.5rem; } .form-group { margin-bottom: 1.25rem; text-align: left; } label { display: block; font-size: 0.875rem; font-weight: 500; margin-bottom: 0.5rem; color: var(--text); } input, select, textarea { width: 100%; max-width: 100%; padding: 0.75rem 1rem; border-radius: 0.75rem; border: 1px solid var(--border); background: rgba(255,255,255,0.05); color: var(--text); font-size: 1rem; transition: all 0.2s; } input:focus, select:focus, textarea:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2); background: rgba(255,255,255,0.1); } .btn { display: inline-flex; align-items: center; justify-content: center; width: 100%; padding: 0.875rem 1.5rem; border-radius: 0.75rem; background: linear-gradient(135deg, var(--primary) 0%, #a855f7 100%); color: white; font-weight: 600; border: none; cursor: pointer; transition: all 0.2s; text-decoration: none; box-shadow: 0 4px 6px -1px rgba(99, 102, 241, 0.4); gap: 0.5rem; white-space: nowrap; font-size: 1rem; } .btn:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(99, 102, 241, 0.5); filter: brightness(1.1); } .btn-secondary { background: transparent; border: 1px solid var(--border); color: var(--text); box-shadow: none; font-size: 1rem; padding: 0.875rem 1.5rem; } .btn-secondary:hover { background: rgba(255,255,255,0.05); box-shadow: none; } .error-msg { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); color: #ef4444; padding: 0.75rem; border-radius: 0.5rem; font-size: 0.875rem; margin-bottom: 1.5rem; } .success-msg { background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.2); color: #22c55e; padding: 0.75rem; border-radius: 0.5rem; font-size: 0.875rem; margin-bottom: 1.5rem; } .footer { margin-top: 2rem; font-size: 0.875rem; color: var(--text-light); opacity: 0.8; } .toggle-switch { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; user-select: none; } .toggle-switch input { appearance: none; -webkit-appearance: none; width: 1.2rem; height: 1.2rem; border: 2px solid var(--border); background: rgba(255,255,255,0.05); cursor: pointer; position: relative; display: flex; align-items: center; justify-content: center; transition: all 0.2s ease; flex-shrink: 0; } .toggle-switch input:checked { background: var(--primary); border-color: var(--primary); } .toggle-switch input[type="checkbox"] { border-radius: 6px; } .toggle-switch input[type="radio"] { border-radius: 50%; } .toggle-switch input::after { content: ''; position: absolute; opacity: 0; transition: opacity 0.2s; } .toggle-switch input[type="checkbox"]::after { width: 4px; height: 8px; border: solid white; border-width: 0 2px 2px 0; transform: rotate(45deg) translate(-1px, -1px); } .toggle-switch input[type="radio"]::after { width: 6px; height: 6px; background: white; border-radius: 50%; } .toggle-switch input:checked::after { opacity: 1; } @keyframes pulse-green { 0% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.7); } 70% { box-shadow: 0 0 0 6px rgba(34, 197, 94, 0); } 100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); } } .status-dot { height: 10px; width: 10px; background-color: #22c55e; border-radius: 50%; display: inline-block; margin-right: 6px; animation: pulse-green 2s infinite; } .toast-container { position: fixed; top: 24px; left: 50%; transform: translateX(-50%); z-index: 10000; display: flex; flex-direction: column; gap: 10px; pointer-events: none; } .toast { background: var(--surface); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); padding: 12px 24px; border-radius: 50px; box-shadow: var(--shadow); color: var(--text); font-weight: 500; font-size: 0.95rem; display: flex; align-items: center; gap: 10px; opacity: 0; transform: translateY(-20px); transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); pointer-events: auto; border: 1px solid var(--border); } .toast.show { opacity: 1; transform: translateY(0); } .toast.success { border-color: rgba(34, 197, 94, 0.5); } .toast.success i { color: #22c55e; } .toast.error { border-color: rgba(239, 68, 68, 0.5); } .toast.error i { color: #ef4444; }`;
}
function getFlagEmoji(c) {
    if (!c || c.length !== 2) return '';
    const cp = c.toUpperCase().split('').map(char => 127397 + char.charCodeAt());
    return String.fromCodePoint(...cp);
}
function getPoemPage() {
    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>404</title><style>${getCommonCSS()}</style></head><body><div style="width: 100%; max-width: 440px;"><div class="card" style="text-align: center;"><div class="logo">🍃</div><h1 style="margin-bottom: 1.5rem;">404 Not Found</h1><div id="time" style="font-family: monospace; color: var(--text-light);">Loading...</div></div></div><script>function updateTime() { document.getElementById('time').innerText = new Date().toLocaleString('zh-CN'); } setInterval(updateTime, 1000); updateTime();</script></body></html>`;
    return ResponseBuilder.html(html, 404);
}
export default {
    async fetch(req, env, ctx) {
        try {
            await optimizeConfigLoading(env, ctx);
            if (p === 'dylj' || p === '') p = uid || 'dylj';
            if (env.FDIP) fdc = env.FDIP.split(',').map(s => s.trim());
            p = env.SUB_PATH || env.subpath || p;
            uid = env.UUID || env.uuid || env.AUTH || uid;
            const config = await optimizeConfigLoading(env, ctx);
            dns = config.dns || env.DNS_RESOLVER || dns;
            const loginPath = config.klp || 'login';
            const upg = req.headers.get('Upgrade');
            const url = new URL(req.url);
            const contentType = req.headers.get('content-type') || '';
            const referer = req.headers.get('Referer') || '';
            
            if (upg && upg.toLowerCase() === 'websocket') {
                return await handleWSRequest(req, uid, url);
            } else if (contentType.startsWith('application/grpc')) {
                return await handleGRPCRequest(req, uid);
            } else if (req.method === 'POST' && !url.pathname.startsWith('/admin') && url.pathname !== `/${loginPath}`) {
                return await handleXHTTPRequest(req, uid);
            }
            
            const pathname = url.pathname;
            if (pathname === '/') {
                const token = getSessionCookie(req.headers.get('Cookie'));
                const sessionResult = await validateAndRefreshSession(env, token);
                if (sessionResult.valid) {
                    const host = req.headers.get('Host');
                    const response = await getMainPageContent(host, `https://${host}`, await gP(env), await gU(env), env);
                    if (sessionResult.refreshed) response.headers.set('Set-Cookie', setSessionCookie(sessionResult.newToken));
                    return response;
                } else {
                    const pw = await gP(env); const u = await gU(env);
                    if (!pw || !u) return getInitPage(req.headers.get('Host'), `https://${req.headers.get('Host')}`, true);
                    if (env.ASSETS) { try { const assetRes = await env.ASSETS.fetch(req); if (assetRes.status !== 404) return assetRes; } catch(e) {} }
                    return getPoemPage();
                }
            }
            
            if (pathname === `/${loginPath}`) return await handleLogin(req, env);
            switch (pathname) {
                case `/${p}`: return await sub(req);
                case '/info': return await requireAuth(req, env, () => ResponseBuilder.json(req.cf));
                case '/test-dns': return await requireAuth(req, env, async () => ResponseBuilder.json({success:true}));
                case '/admin/save': return await handleAdminSave(req, env);
                case '/admin': return await requireAuth(req, env, getAdminPage);
                case '/init': return await handleInit(req, env);
                case '/zxyx': return await requireAuth(req, env, zxyx);
                case '/logout': return await handleLogout(req, env);
                case '/api/usage': return await requireAuth(req, env, async()=> ResponseBuilder.json(await getCloudflareUsageAPI(env)));
            }
            if (pathname === `/${uid}`) return await sub(req);
            if (env.ASSETS) { try { const assetRes = await env.ASSETS.fetch(req); if (assetRes.status !== 404) return assetRes; } catch(e) {} }
            return getPoemPage();
        } catch (err) {
            return ErrorHandler.internalError();
        }
    }
};
function getLoginPage(url, baseUrl, showError = false, showPasswordChanged = false) {
    let msgHtml = '';
    if (showPasswordChanged) msgHtml = `<div class="success-msg">密码已修改，请重新登录</div>`;
    else if (showError) msgHtml = `<div class="error-msg">密码错误，请重试</div>`;
    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>登录</title><style>${getCommonCSS()}</style></head><body><div style="width: 100%; max-width: 440px;"><div class="card" style="text-align: center;"><div class="logo">🔒</div><h1>欢迎回来</h1><p>请输入密码以访问控制台</p>${msgHtml}<form method="post" action="/${cc?.klp || 'login'}"><div class="form-group"><label>访问密码</label><input type="password" name="password" required autofocus placeholder="请输入登录密码"></div><button type="submit" class="btn">立即登录 ➜</button></form><div class="footer">© 2025 Workers Service</div></div></div></body></html>`;
    return ResponseBuilder.html(html);
}
function getInitPage(url, baseUrl, isFirstTime = true) {
    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>系统初始化</title><style>${getCommonCSS()}</style><script>function genUUID() { const u = crypto.randomUUID(); document.getElementById('uuid').value = u; } function validateForm(e) { const u = document.getElementById('uuid').value; if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(u)) { alert('UUID 格式不正确'); return false; } return true; }</script></head><body><div style="width: 100%; max-width: 500px;"><div class="card"><div style="text-align: center;"><div class="logo">🚀</div><h1>系统初始化</h1><p>首次运行，请配置基本安全信息</p></div><form action="/init" method="post" onsubmit="return validateForm()"><div class="form-group"><label>管理员密码</label><input type="password" name="password" required minlength="4" placeholder="设置后台登录密码"></div><div class="form-group"><label>确认密码</label><input type="password" name="confirm_password" required minlength="4" placeholder="再次输入密码"></div><div class="form-group"><label>UUID (用户ID)</label><div style="display: flex; gap: 0.5rem;"><input type="text" id="uuid" name="uuid" required placeholder="xxxxxxxx-xxxx-4xxx..."><button type="button" class="btn-secondary" onclick="genUUID()" style="width: auto; white-space: nowrap;">生成</button></div></div><div class="form-group"><label>登录路径</label><input type="text" name="login_path" value="login" required placeholder="例如: admin"></div><button type="submit" class="btn">完成设置 ➜</button></form></div></div></body></html>`;
    return ResponseBuilder.html(html);
}
async function handleInit(req, env) {
    const host = req.headers.get('Host');
    const base = `https://${host}`;
    if (req.method !== 'POST') return getInitPage(host, base, true);
    const form = await req.formData();
    const password = form.get('password');
    const confirmPassword = form.get('confirm_password');
    const uuid = form.get('uuid');
    const loginPath = form.get('login_path') || 'login';
    if (password !== confirmPassword) return ResponseBuilder.html('密码不匹配', 400);
    if (!UUIDUtils.isValidUUID(uuid)) return ResponseBuilder.html('UUID无效', 400);
    await sP(env, password);
    await sU(env, uuid);
    await saveConfigToKV(env, yx, fdc, uuid, null, null, null, loginPath);
    uid = uuid;
    const newToken = await signToken(env, Date.now() + SESSION_DURATION);
    return ResponseBuilder.redirect(`${base}/${loginPath}`, 302, { 'Set-Cookie': setSessionCookie(newToken) });
}
async function getMainPageContent(host, base, pw, uuid, env) {
    const proxyStatus = cc?.proxyConfig?.enabled ? `<span style="color:#22c55e;">● 已启用 (${cc.proxyConfig.type.toUpperCase()})</span>` : `<span style="color:#94a3b8;">● 未启用</span>`;
    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>控制台</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"><style>${getCommonCSS()} body { justify-content: flex-start; padding: 2rem 1rem; } .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; width: 100%; max-width: 1000px; margin-top: 1.5rem; } @media (max-width: 768px) { .dashboard-grid { grid-template-columns: 1fr; } } .card { padding: 1.5rem; } .stat-item { display: flex; justify-content: space-between; padding: 0.75rem 0; border-bottom: 1px solid rgba(255,255,255,0.1); } .stat-item:last-child { border-bottom: none; } .stat-label { color: var(--text-light); display: flex; align-items: center; gap: 0.5rem; } .stat-val { font-weight: 500; word-break: break-all; text-align: right; } .action-grid { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-top: 1rem; } .action-grid .btn, .action-grid .btn-secondary { flex: 1 1 auto; min-width: 120px; } .copy-btn { cursor: pointer; color: var(--primary); margin-left: 0.5rem; } .nav-header { width: 100%; max-width: 1000px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; } .nav-brand { font-size: 1.5rem; font-weight: 700; background: linear-gradient(to right, #6366f1, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; } .nav-actions { display: flex; gap: 1rem; } .glass-btn { background: var(--surface); backdrop-filter: var(--glass); padding: 0.5rem 1rem; border-radius: 2rem; text-decoration: none; color: var(--text); font-size: 0.875rem; border: 1px solid var(--border); transition: all 0.2s; display: flex; align-items: center; gap: 0.5rem; white-space: nowrap; } .glass-btn:hover { background: rgba(255,255,255,0.2); }</style></head><body><div class="nav-header"><div class="nav-brand">Workers Service</div><div class="nav-actions"><a href="/admin" class="glass-btn"><i class="fas fa-cog"></i> 设置</a><a href="/logout" class="glass-btn"><i class="fas fa-sign-out-alt"></i> 退出</a></div></div><div class="dashboard-grid"><div class="card"><h3 style="margin-top:0"><i class="fas fa-server" style="color:var(--primary)"></i> 系统状态</h3><div class="stat-item"><span class="stat-label">运行状态</span><span class="stat-val" style="display:flex; align-items:center;"><span class="status-dot"></span>正常运行</span></div><div class="stat-item"><span class="stat-label">协议</span><span class="stat-val" style="display: flex; align-items: center; gap: 8px; justify-content: flex-end;"><span style="color:${ev?'#22c55e':'#94a3b8'}">VL ${ev?'●':'○'}</span><span style="opacity: 0.2;">|</span><span style="color:${et?'#22c55e':'#94a3b8'}">TJ ${et?'●':'○'}</span></span></div><div class="stat-item"><span class="stat-label">传输网络</span><span class="stat-val" style="display: flex; align-items: center; gap: 8px; justify-content: flex-end;"><span style="color:${cc?.transConfig?.grpc?'#22c55e':'#94a3b8'}">gRPC</span><span style="opacity: 0.2;">|</span><span style="color:${cc?.transConfig?.xhttp?'#22c55e':'#94a3b8'}">XHTTP</span><span style="opacity: 0.2;">|</span><span style="color:${cc?.transConfig?.ech?'#22c55e':'#94a3b8'}">ECH</span></span></div><div class="stat-item"><span class="stat-label">代理转发</span><span class="stat-val">${proxyStatus}</span></div><div class="stat-item"><span class="stat-label">API用量</span><span class="stat-val" id="usage">加载中...</span></div></div><div class="card"><h3 style="margin-top:0"><i class="fas fa-link" style="color:#ec4899"></i> 订阅管理</h3><div class="action-grid"><button class="btn btn-secondary" onclick="copy('${base}/${uuid}')"><i class="fas fa-bolt"></i> Base64</button><button class="btn btn-secondary" onclick="copySub('clash')"><i class="fas fa-cat"></i> Clash</button><button class="btn btn-secondary" onclick="copySub('singbox')"><i class="fas fa-box"></i> SingBox</button><button class="btn btn-secondary" onclick="copy('${base}/${uuid}?format=surge')"><i class="fas fa-paper-plane"></i> Surge</button></div></div><div class="card" style="grid-column: 1 / -1;"><h3 style="margin-top:0"><i class="fas fa-tools" style="color:#f59e0b"></i> 快捷工具</h3><div class="action-grid"><a href="/admin#ip" class="btn btn-secondary"><i class="fas fa-list"></i> IP 库管理</a><a href="/zxyx" class="btn"><i class="fas fa-tachometer-alt"></i> 在线优选 IP</a></div></div></div><script>function showToast(msg, type = 'success') { let container = document.querySelector('.toast-container'); if (!container) { container = document.createElement('div'); container.className = 'toast-container'; document.body.appendChild(container); } const toast = document.createElement('div'); toast.className = 'toast ' + type; const icon = type === 'success' ? '<i class="fas fa-check-circle"></i>' : '<i class="fas fa-exclamation-circle"></i>'; toast.innerHTML = icon + '<span>' + msg + '</span>'; container.appendChild(toast); requestAnimationFrame(() => toast.classList.add('show')); setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 300); }, 3000); } function copy(text) { navigator.clipboard.writeText(text).then(() => showToast('已复制到剪贴板', 'success')).catch(() => showToast('复制失败，请手动复制', 'error')); } function copySub(type) { const rawSub = '${base}/${uuid}'; let url = rawSub + (rawSub.includes('?') ? '&' : '?') + 'target=' + type; copy(url); } fetch('/api/usage').then(r=>r.json()).then(d=>{ const el = document.getElementById('usage'); if(d.success) { const total = d.total; const limit = 100000; const percent = (total / limit) * 100; let color = '#22c55e'; if (percent >= 80) color = '#ef4444'; else if (percent >= 60) color = '#f59e0b'; el.innerHTML = \`<span style="color:\${color}; font-weight:bold;">\${total} 请求</span>\`; } else { el.innerText = '未配置'; } });</script></body></html>`;
    return ResponseBuilder.html(html);
}
async function handleAdminSave(req, env) {
    try {
        const token = getSessionCookie(req.headers.get('Cookie'));
        const sessionResult = await validateAndRefreshSession(env, token);
        if (!sessionResult.valid) return ErrorHandler.unauthorized();
        const form = await req.formData();
        const cfipList = form.get('cfip') || '';
        const fdipList = form.get('fdip') || '';
        const u = form.get('uuid');
        const formDyhd = form.get('dyhd');
        const formDypz = form.get('dypz');
        const surgeT = form.get('surgeTemplate');
        const formDns = form.get('custom_dns') || '';
        const newPassword = form.get('new_password');
        const protocolEv = form.get('protocol_ev') === 'on';
        const protocolEt = form.get('protocol_et') === 'on';
        const protocolTp = form.get('protocol_tp');
        const grpc = form.get('trans_grpc') === 'on';
        const xhttp = form.get('trans_xhttp') === 'on';
        const ech = form.get('trans_ech') === 'on';
        const ech_sni = form.get('trans_ech_sni') || '';
        let cfAccountId = form.get('cf_account_id');
        const cfApiToken = form.get('cf_api_token');
        const proxyEnabled = form.get('proxy_enabled') === 'on';
        const proxyType = form.get('proxy_type');
        const proxyAccount = form.get('proxy_account');
        const proxyMode = form.get('proxy_mode');
        const loginPath = form.get('login_path') || 'login';
        if (u && !UUIDUtils.isValidUUID(u)) return ResponseBuilder.text('UUID无效', 400);
        const cfipArr = uniqueIPList(cfipList.split('\n').map(x => x.trim()).filter(Boolean));
        const fdipArr = uniqueIPList(fdipList.split('\n').map(x => x.trim()).filter(Boolean));
        if (newPassword) await sP(env, newPassword);
        const protocolCfg = { ev: protocolEv, et: protocolEt, tp: protocolTp };
        const cfCfg = { accountId: cfAccountId, apiToken: cfApiToken };
        const proxyCfg = { enabled: proxyEnabled, type: proxyType, account: proxyAccount, global: proxyMode === 'global', whitelist:[] };
        const transCfg = { grpc, xhttp, ech, ech_sni };
        await saveConfigToKV(env, cfipArr, fdipArr, u, protocolCfg, cfCfg, proxyCfg, loginPath, formDyhd, formDypz, surgeT, formDns, transCfg);
        yx = cfipArr; fdc = fdipArr; dyhd = formDyhd; dypz = formDypz; stp = surgeT; dns = formDns || dns;
        if (u) uid = u;
        ev = protocolEv; et = protocolEt; tp = protocolTp;
        protocolConfig = { ev, et, tp };
        const host = req.headers.get('Host');
        if (req.headers.get('Accept') === 'application/json') return ResponseBuilder.json({ success: true });
        return ResponseBuilder.redirect(`https://${host}/admin?msg=saved`);
    } catch (e) { return ResponseBuilder.text(e.message, 500); }
}
async function getAdminPage(req, env) {
    const token = getSessionCookie(req.headers.get('Cookie'));
    const sessionResult = await validateAndRefreshSession(env, token);
    if (!sessionResult.valid) return ErrorHandler.unauthorized();
    if (!cc) await optimizeConfigLoading(env);
    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>系统配置</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"><style>${getCommonCSS()} body { justify-content: flex-start; padding: 2rem 1rem; } .admin-container { max-width: 1000px; width: 100%; margin: 0 auto; } .card { padding: 1.5rem; margin-bottom: 1.5rem; } h3 { margin-top: 0; margin-bottom: 1.25rem; font-size: 1.25rem; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 0.75rem; } .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; } @media (max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } } label { font-size: 0.9rem; font-weight: 600; color: var(--text); margin-bottom: 0.5rem; display: block; } .form-group { margin-bottom: 1.25rem; position: relative; } textarea { font-family: 'Menlo', 'Monaco', 'Courier New', monospace; font-size: 0.85rem; line-height: 1.4; height: 140px; background: rgba(255,255,255,0.03); border-color: var(--border); } textarea:focus { background: rgba(255,255,255,0.08); } .help-text { font-size: 0.8rem; color: var(--text-light); margin-top: 0.5rem; line-height: 1.4; display: flex; align-items: flex-start; gap: 0.4rem; background: rgba(255,255,255,0.03); padding: 0.5rem; border-radius: 0.5rem; } .help-text i { margin-top: 0.15rem; color: var(--primary); opacity: 0.8; } .toggle-switch { margin-bottom: 0; }</style><script>function genUUID() { const u = crypto.randomUUID(); document.getElementById('uuid').value = u; } function showToast(msg, type = 'success') { let container = document.querySelector('.toast-container'); if (!container) { container = document.createElement('div'); container.className = 'toast-container'; document.body.appendChild(container); } const toast = document.createElement('div'); toast.className = 'toast ' + type; const icon = type === 'success' ? '<i class="fas fa-check-circle"></i>' : '<i class="fas fa-exclamation-circle"></i>'; toast.innerHTML = icon + '<span>' + msg + '</span>'; container.appendChild(toast); requestAnimationFrame(() => toast.classList.add('show')); setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 300); }, 3000); } async function saveConfig(e) { e.preventDefault(); const form = e.target; const btn = form.querySelector('button[type="submit"]'); const originalText = btn.innerHTML; btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 保存中...'; try { const response = await fetch('/admin/save', { method: 'POST', body: new FormData(form), headers: { 'Accept': 'application/json' } }); if (response.ok) { showToast('配置已保存并立即生效', 'success'); } else { showToast('保存失败', 'error'); } } catch (err) { showToast('网络错误: ' + err, 'error'); } finally { btn.disabled = false; btn.innerHTML = originalText; } }</script></head><body><div class="admin-container"><div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 1.5rem;"><h1 style="margin:0"><i class="fas fa-cogs"></i> 系统配置</h1><a href="/" class="btn-secondary btn" style="width:auto; padding: 0.6rem 1.2rem; gap: 0.5rem;"><i class="fas fa-arrow-left"></i> 返回主页</a></div><form onsubmit="saveConfig(event)"><div class="card" id="ip"><h3><i class="fas fa-globe" style="color:var(--primary)"></i> IP 资源管理</h3><div class="grid-2"><div class="form-group"><label>优选 IP / 域名 (Web伪装 & 订阅)</label><textarea name="cfip" placeholder="例如: 1.1.1.1:443#美国">${yx.join('\n')}</textarea></div><div class="form-group"><label>反代 IP / 域名 / TXT记录 (支持 .william )</label><textarea name="fdip" placeholder="例如: ip.sb">${fdc.join('\n')}</textarea></div></div></div><div class="card"><h3><i class="fas fa-shield-alt" style="color:#ec4899"></i> 协议与网络传输</h3><div class="grid-2"><div class="form-group"><label>启用协议</label><div style="display:flex; gap:1.5rem; margin-top:0.5rem; background:rgba(255,255,255,0.03); padding:1rem; border-radius:0.5rem; align-items:center;"><label class="toggle-switch" style="margin:0"><input type="checkbox" name="protocol_ev" ${ev ? 'checked' : ''}> Vless</label><label class="toggle-switch" style="margin:0"><input type="checkbox" name="protocol_et" ${et ? 'checked' : ''}> Trojan</label></div></div><div class="form-group"><label>传输模式增强</label><div style="display:flex; gap:1.5rem; margin-top:0.5rem; background:rgba(255,255,255,0.03); padding:1rem; border-radius:0.5rem; align-items:center;"><label class="toggle-switch" style="margin:0"><input type="checkbox" name="trans_grpc" ${cc?.transConfig?.grpc ? 'checked' : ''}> gRPC</label><label class="toggle-switch" style="margin:0"><input type="checkbox" name="trans_xhttp" ${cc?.transConfig?.xhttp ? 'checked' : ''}> XHTTP</label><label class="toggle-switch" style="margin:0"><input type="checkbox" name="trans_ech" ${cc?.transConfig?.ech ? 'checked' : ''}> ECH</label></div></div></div><div class="grid-2"><div class="form-group"><label>Trojan 密码</label><input type="text" name="protocol_tp" value="${tp}" placeholder="留空默认UUID"></div><div class="form-group"><label>ECH SNI (留空自动获取)</label><input type="text" name="trans_ech_sni" value="${cc?.transConfig?.ech_sni||''}"></div></div><div class="form-group"><label>UUID (用户ID)</label><div style="display: flex; gap: 0.75rem;"><input type="text" id="uuid" name="uuid" value="${uid}" required style="font-family:monospace;"><button type="button" class="btn btn-secondary" onclick="genUUID()" style="width: auto; padding: 0 1.5rem;">生成</button></div></div><div class="form-group"><label>修改后台密码</label><input type="password" name="new_password" placeholder="留空保持不变"></div></div><div class="card"><div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1.25rem;"><h3 style="margin:0"><i class="fas fa-network-wired" style="color:#f59e0b"></i> 代理转发 (SOCKS5/HTTP)</h3></div><div class="form-group"><label class="toggle-switch" style="display:flex; align-items:center; margin-bottom: 1rem;"><input type="checkbox" name="proxy_enabled" ${cc?.proxyConfig?.enabled ? 'checked' : ''}> 启用代理转发</label></div><div class="grid-2"><div class="form-group"><label>节点地址</label><input type="text" name="proxy_account" value="${cc?.proxyConfig?.account || ''}" placeholder="user:pass@host:port"></div><div class="form-group"><label>协议类型</label><select name="proxy_type"><option value="socks5" ${cc?.proxyConfig?.type === 'socks5' ? 'selected' : ''}>SOCKS5</option><option value="http" ${cc?.proxyConfig?.type === 'http' ? 'selected' : ''}>HTTP</option><option value="https" ${cc?.proxyConfig?.type === 'https' ? 'selected' : ''}>HTTPS</option></select></div></div><div class="form-group"><label>转发模式</label><div style="display:flex; gap:2rem; margin-top:0.5rem; background:rgba(255,255,255,0.03); padding:1rem; border-radius:0.5rem;"><label class="toggle-switch"><input type="radio" name="proxy_mode" value="global" ${cc?.proxyConfig?.global ? 'checked' : ''}> 全局代理</label><label class="toggle-switch"><input type="radio" name="proxy_mode" value="failover" ${!cc?.proxyConfig?.global ? 'checked' : ''}> 故障分流</label></div></div></div><div class="card"><h3><i class="fas fa-bolt" style="color:#8b5cf6"></i> 订阅与高级配置</h3><div class="grid-2"><div class="form-group"><label>订阅后端</label><input type="text" name="dyhd" value="${cc?.dyhd || dyhd}"></div><div class="form-group"><label>远程配置</label><input type="text" name="dypz" value="${cc?.dypz || dypz}"></div></div><div class="grid-2"><div class="form-group"><label>后台入口路径</label><div style="position:relative;"><span style="position:absolute; left:1rem; top:0.75rem; color:var(--text-light); opacity:0.5;">/</span><input type="text" name="login_path" value="${cc?.klp || 'login'}" style="padding-left: 2rem;"></div></div><div class="form-group"><label>DNS DoH 地址</label><input type="text" name="custom_dns" value="${cc?.dns || dns}"></div></div></div><div class="card" style="margin-bottom: 5rem;"><h3><i class="fas fa-chart-line" style="color:#10b981"></i> Cloudflare API (统计)</h3><div class="grid-2"><div class="form-group"><label>Account ID</label><input type="text" name="cf_account_id" value="${cc?.cfConfig?.accountId || ''}"></div><div class="form-group"><label>API Token</label><input type="password" name="cf_api_token" value="${cc?.cfConfig?.apiToken || ''}"></div></div></div><div style="position: fixed; bottom: 2rem; left: 0; right: 0; display: flex; justify-content: center; pointer-events: none; z-index: 100;"><button type="submit" class="btn" style="pointer-events: auto; box-shadow: 0 10px 30px rgba(79, 70, 229, 0.4); width: auto; padding: 1rem 3rem; border-radius: 2rem;"><i class="fas fa-save"></i> 保存配置</button></div></form></div></body></html>`;
    return ResponseBuilder.html(html);
}
async function zxyx(request, env) {
    const country = request.cf?.country || 'CN';
    const isChina = country === 'CN';
    const countryDisplayText = isChina ? `${country}` : `${country} (可能需关闭代理)`;
    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>在线优选工具</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"><style>${getCommonCSS()} body { justify-content: flex-start; padding: 2rem 1rem 8rem 1rem; } .container { max-width: 1000px; width: 100%; margin: 0 auto; } .card { padding: 1.5rem; margin-bottom: 1.5rem; } h3 { margin-top: 0; margin-bottom: 1.25rem; font-size: 1.25rem; font-weight: 700; display: flex; align-items: center; gap: 0.75rem; } .nav-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; } .nav-brand { font-size: 1.5rem; font-weight: 700; background: linear-gradient(to right, #6366f1, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; } .ip-list { background: rgba(0,0,0,0.03); padding: 1rem; border-radius: 0.5rem; border: 1px solid var(--border); max-height: 400px; overflow-y: auto; font-family: monospace; font-size: 0.9rem; } .ip-item { margin: 4px 0; padding: 4px 8px; border-radius: 4px; display: flex; justify-content: space-between; } .ip-item:hover { background: rgba(255,255,255,0.05); } .good-latency { color: #22c55e; } .bad-latency { color: #ef4444; } .btn-group { display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 1rem; } .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; }</style><script>function showToast(msg) { alert(msg); }</script></head><body><div class="container"><div class="nav-header"><div class="nav-brand">在线优选 IP</div><div style="display:flex; gap:0.5rem;"><a href="/admin" class="btn btn-secondary" style="width:auto; padding: 0.5rem 1rem;"><i class="fas fa-cog"></i> 配置</a><a href="/" class="btn btn-secondary" style="width:auto; padding: 0.5rem 1rem;"><i class="fas fa-arrow-left"></i> 首页</a></div></div><div class="card"><h3><i class="fas fa-chart-bar" style="color:var(--primary)"></i> 位置提示</h3><p>${countryDisplayText}</p><p>由于资源限制，完整的在线优选测速功能请在本地运行专门工具。网页端仅作展示预留。</p></div></div></body></html>`;
    return ResponseBuilder.html(html);
}