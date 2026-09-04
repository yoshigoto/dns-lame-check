import express from 'express';
import net from 'net';
import dgram from 'dgram';
import path from 'path';
import dnsPacket from 'dns-packet';	// https://github.com/mafintosh/dns-packet
import promisesDns from 'dns/promises';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());
app.use(express.static('public'));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

function isIPv6(ip) {
    return ip.includes(':');
}

function normalizeDnsName(name) {
    return String(name || '').trim().toLowerCase().replace(/\.$/, '');
}

function normalizeUserDomain(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';

    const candidate = raw.replace(/^https?:\/\//i, '').replace(/\/$/, '');
    const normalized = normalizeDnsName(candidate);

    if (!normalized) return '';
    if (normalized.length > 253) return '';
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(normalized)) {
        return '';
    }

    return normalized;
}

function isSubdomainOrEqual(childCandidate, parentCandidate) {
    const c = normalizeDnsName(childCandidate);
    const p = normalizeDnsName(parentCandidate);
    if (!c || !p) return false;
    if (c === p) return true;
    return c.endsWith('.' + p);
}

function hasParentChildRelationship(domainA, domainB) {
    return isSubdomainOrEqual(domainA, domainB) || isSubdomainOrEqual(domainB, domainA);
}

function isInBailiwickGlue(record, nsNames, delegatedZone) {
    return (record.type === 'A' || record.type === 'AAAA') &&
        nsNames.includes(normalizeDnsName(record.name)) &&
        isSubdomainOrEqual(record.name, delegatedZone);
}

function summarizeRfc9471Referral(nsRecords, additionals, retryFrom = '') {
    const delegatedZone = normalizeDnsName(nsRecords[0]?.name);
    const nsNames = nsRecords.map(record => normalizeDnsName(record.data));
    const inDomainNs = nsNames.filter(nsName => isSubdomainOrEqual(nsName, delegatedZone));
    const inDomainGlueNames = [...new Set(additionals
        .filter(record => isInBailiwickGlue(record, nsNames, delegatedZone))
        .map(record => normalizeDnsName(record.name)))];
    const missingInDomainGlueNames = inDomainNs.filter(nsName => !inDomainGlueNames.includes(nsName));
    const nonInDomainAddressNames = [...new Set(additionals
        .filter(record => (record.type === 'A' || record.type === 'AAAA') && nsNames.includes(normalizeDnsName(record.name)) && !isSubdomainOrEqual(record.name, delegatedZone))
        .map(record => normalizeDnsName(record.name)))];
    const transportNote = retryFrom === 'udp-truncated'
        ? 'UDP 応答は TC=1 のため TCP で再取得しました。'
        : 'UDP 応答は TC=0 でした。';
    const inDomainNote = inDomainNs.length === 0
        ? 'in-domain NS はありません。'
        : missingInDomainGlueNames.length === 0
            ? `in-domain glue: [${inDomainGlueNames.join(', ')}]`
            : `ADDITIONAL SECTION に存在しない in-domain NS: [${missingInDomainGlueNames.join(', ')}] → 親ゾーンで利用可能な glue が存在するかは応答だけでは判定できません。`;
    const nonInDomainNote = nonInDomainAddressNames.length > 0
        ? `ゾーン外 NS の追加アドレス: ${nonInDomainAddressNames.join(', ')} → sibling glue を含む可能性がありますが、このツールでは glue として採用しません。`
        : '';

    return [transportNote, inDomainNote, nonInDomainNote].filter(Boolean).join('\r');
}

const DNS_CACHE_TTL = {
    success: 30000,
    transient: 2000,
    timeout: Infinity
};

function getCacheEntry(dnsResponseCache, cacheKey) {
    const entry = dnsResponseCache.get(cacheKey);
    if (!entry) {
        return null;
    }

    if (entry.expiresAt <= Date.now()) {
        dnsResponseCache.delete(cacheKey);
        return null;
    }

    return entry.value;
}

function setCacheEntry(dnsResponseCache, cacheKey, value, ttlMs = DNS_CACHE_TTL.success) {
    dnsResponseCache.set(cacheKey, {
        value,
        expiresAt: Date.now() + ttlMs
    });
}

function queryDirectlyTCP(domain, serverIp, dnsResponseCache, qType = 'NS') {
    return new Promise((resolve) => {
        const cacheKey = `${serverIp}|${qType}|${domain}`;
        const cachedResult = getCacheEntry(dnsResponseCache, cacheKey);
        // 以前に同じサーバー・タイプ・ドメインに対して問い合わせ済みなら、即時復元
        if (cachedResult) {
            return resolve({ ...cachedResult, isCached: true });
        }

        let settled = false;
        let socket = null;
        let timer = null;

        const finish = (result) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            if (socket) socket.destroy();
            resolve(result);
        };

        try {
            const tcpBuf = dnsPacket.streamEncode({
                type: 'query',
                id: Math.floor(Math.random() * 65534),
                questions: [{ type: qType, name: domain }],
                additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 1232 }]
            });

            socket = net.createConnection({ host: serverIp, port: 53 }, () => {
                socket.write(tcpBuf);
            });

            timer = setTimeout(() => {
                const timeoutResult = { error: 'TIMEOUT', transport: 'tcp' };
                setCacheEntry(dnsResponseCache, cacheKey, timeoutResult, DNS_CACHE_TTL.timeout);
                finish(timeoutResult);
            }, 5000);

            socket.on('error', (err) => {
                const socketError = { error: 'SOCKET_ERROR', detail: err.message, transport: 'tcp' };
                setCacheEntry(dnsResponseCache, cacheKey, socketError, DNS_CACHE_TTL.transient);
                finish(socketError);
            });

            let receivedData = Buffer.alloc(0);
            socket.on('data', (chunk) => {
                receivedData = Buffer.concat([receivedData, chunk]);

                while (receivedData.length >= 2) {
                    // 先頭 2バイトから DNSメッセージの長さを取得
                    const msgLength = receivedData.readUInt16BE(0);
                    if (receivedData.length < msgLength + 2) break;

                    try {
                        const decoded = dnsPacket.streamDecode(receivedData);
                        if (!decoded) break;

                        receivedData = receivedData.subarray(2 + msgLength);
                        const tcpSuccess = { ...decoded, transport: 'tcp' };
                        setCacheEntry(dnsResponseCache, cacheKey, tcpSuccess, DNS_CACHE_TTL.success);
                        return finish(tcpSuccess);
                    } catch (e) {
                        const decodeError = { error: 'DECODE_ERROR', detail: e.message, transport: 'tcp' };
                        setCacheEntry(dnsResponseCache, cacheKey, decodeError, DNS_CACHE_TTL.transient);
                        return finish(decodeError);
                    }
                }
            });
        } catch (e) {
            const sendError = { error: 'SEND_ERROR', detail: e.message, transport: 'tcp' };
            setCacheEntry(dnsResponseCache, cacheKey, sendError, DNS_CACHE_TTL.transient);
            finish(sendError);
        }
    });
}

function queryDirectlyUDP(domain, serverIp, dnsResponseCache, qType = 'NS', useEdns = true) {
    return new Promise((resolve) => {
        const cacheKey = `${serverIp}|${qType}|${domain}`;
        const cachedResult = getCacheEntry(dnsResponseCache, cacheKey);
        // 以前に同じサーバー・タイプ・ドメインに対して問い合わせ済みなら、即時復元
        if (cachedResult) {
            return resolve({ ...cachedResult, isCached: true });
        }

        const socketType = isIPv6(serverIp) ? 'udp6' : 'udp4';
        const client = dgram.createSocket(socketType);
        let settled = false;
        let timer = null;

        const finish = (result) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            try { client.close(); } catch (e) {}
            resolve(result);
        };

        try {
            const buf = dnsPacket.encode({
                type: 'query',
                id: Math.floor(Math.random() * 65534),
                questions: [{ type: qType, name: domain }],
                additionals: useEdns ? [{ type: 'OPT', name: '.', udpPayloadSize: 1232 }] : []
            });

            client.send(buf, 0, buf.length, 53, serverIp, (err) => {
                if (err) {
                    const sendError = { error: 'SEND_ERROR', detail: err.message, transport: 'udp' };
                    setCacheEntry(dnsResponseCache, cacheKey, sendError, DNS_CACHE_TTL.transient);
                    return finish(sendError);
                }
            });
        } catch (e) {
            const sendError = { error: 'SEND_ERROR', detail: e.message, transport: 'udp' };
            setCacheEntry(dnsResponseCache, cacheKey, sendError, DNS_CACHE_TTL.transient);
            return finish(sendError);
        }

        timer = setTimeout(() => {
            const timeoutResult = { error: 'TIMEOUT', transport: 'udp' };
            setCacheEntry(dnsResponseCache, cacheKey, timeoutResult, DNS_CACHE_TTL.timeout);
            return finish(timeoutResult);
        }, 5000);

        client.on('error', (err) => {
            const socketError = { error: 'SOCKET_ERROR', detail: err.message, transport: 'udp' };
            setCacheEntry(dnsResponseCache, cacheKey, socketError, DNS_CACHE_TTL.transient);
            return finish(socketError);
        });

        client.on('message', (msg) => {
            try {
                const decoded = dnsPacket.decode(msg);
                if (decoded.rcode === 'FORMERR' && useEdns) {
                    if (timer) clearTimeout(timer);
                    try { client.close(); } catch (e) {}
                    return queryDirectlyUDP(domain, serverIp, dnsResponseCache, qType, false)
                        .then(result => finish({ ...result, retryWithoutEdns: true }));
                }
                const answers = decoded.answers || [];
                const authorities = decoded.authorities || [];

                const TC_FLAG = dnsPacket.TRUNCATED_RESPONSE;
                const isTruncated = (decoded.flags & TC_FLAG) !== 0;

                if (isTruncated) {
                    const fallback = () => queryDirectlyTCP(domain, serverIp, dnsResponseCache, qType)
                        .then((tcpResult) => {
                            return finish({
                                ...tcpResult,
                                transport: tcpResult?.transport || 'tcp',
                                retryFrom: 'udp-truncated',
                                isFallback: true
                            });
                        })
                        .catch((err) => {
                            return finish({
                                error: 'TCP_FALLBACK_ERROR',
                                detail: err?.message || 'TCP fallback failed',
                                transport: 'tcp',
                                retryFrom: 'udp-truncated',
                                isFallback: true
                            });
                        });

                    if (timer) clearTimeout(timer);
                    try { client.close(); } catch (e) {}
                    return fallback();
                }

                const hasNsRecord = [...answers, ...authorities].some(r => r.type === 'NS' && hasParentChildRelationship(domain, r.name));
                if (hasNsRecord) {
                    setCacheEntry(dnsResponseCache, cacheKey, decoded, DNS_CACHE_TTL.success);
                }

                return finish({ ...decoded, transport: 'udp' });
            } catch (e) {
                const decodeError = { error: 'DECODE_ERROR', detail: e.message, transport: 'udp' };
                setCacheEntry(dnsResponseCache, cacheKey, decodeError, DNS_CACHE_TTL.transient);
                return finish(decodeError);
            }
        });
    });
}

async function resolveServerIPs(nsName) {
    const ips = [];
    try { const v4 = await promisesDns.resolve4(nsName); ips.push(...v4); } catch (e) {}
    try { const v6 = await promisesDns.resolve6(nsName); ips.push(...v6); } catch (e) {}
    return ips.length > 0 ? ips : null;
}

async function getZoneApex(domain, dnsResponseCache) {
    let currentNs = 'a.root-servers.net';
    let currentServerIPs = await resolveServerIPs(currentNs);
    let parentNs = '';
    let parentServerIPs = [];
    let zoneApex = '';
    let cdName = false;
    let explorationLogs = [];
    let lastDelegatedZone = '';

    const pushExplorationLog = (status, detail, server = currentNs, parent = parentNs || null, extra = {}) => {
        explorationLogs.push({
            server,
            parent,
            status,
            detail,
            nsMatch: null,
            glueMatch: null,
            ...extra
        });
    };

    for (let i = 0; i < 10 && currentServerIPs?.length; i++) {
        const currentParent = parentNs || null;
        let delegation = null;

        for (const serverIp of currentServerIPs) {
            const res = await queryDirectlyUDP(domain, serverIp, dnsResponseCache, 'SOA');
            if (res.error) {
                pushExplorationLog('NETWORK_ERROR', `ゾーン頂点探索中のエラー (${serverIp}): ${res.error}${res.detail ? ' - ' + res.detail : ''}`, currentNs, currentParent);
                continue;
            }

            const isAuthoritative = (res.flags & (dnsPacket.AUTHORITATIVE_ANSWER || 1024)) !== 0;
            const answers = res.answers || [];
            const authorities = res.authorities || [];

            if (isAuthoritative) {
                const cnameRecord = answers.find(r => r.type === 'CNAME');
                const dnameRecord = answers.find(r => r.type === 'DNAME');
                if (cnameRecord || dnameRecord) {
                    const detail = cnameRecord
                        ? `入力名は CNAME (${normalizeDnsName(cnameRecord.name)} -> ${normalizeDnsName(cnameRecord.data)}) です。CNAME の委任先は追跡せず、ゾーン頂点としての委任検査を終了します。 (${serverIp})`
                        : `回答に DNAME が含まれており、ゾーン頂点を確定できませんでした。 (${serverIp})`;
                    pushExplorationLog(cnameRecord ? 'CNAME_FOUND' : 'DNAME_FOUND', detail, currentNs, currentParent);
                    cdName = true;
                    break;
                }
            }

            const soaRecord = [...answers, ...authorities].find(r => r.type === 'SOA' && isSubdomainOrEqual(domain, r.name));

            if (soaRecord) {
                const soaName = normalizeDnsName(soaRecord.name);
                if (lastDelegatedZone && !isSubdomainOrEqual(soaName, lastDelegatedZone)) {
                    zoneApex = lastDelegatedZone;
                    pushExplorationLog(
                        'LAME_DELEGATION_SOA_MISMATCH',
                        `親サーバー (${currentParent || currentNs}) は ${lastDelegatedZone} ゾーンの権威サーバーとして ${currentNs} を示しましたが、${currentNs} は ${soaName} ゾーンの SOA レコードを返しました。親子で情報が一致していません。 (${serverIp})`,
                        currentNs,
                        currentParent
                    );
                    break;
                }

                zoneApex = soaName;
                pushExplorationLog(res.rcode === 'NXDOMAIN' ? 'NXDOMAIN_SOA_FOUND' : 'SOA_FOUND', `ゾーン頂点を確定: ${zoneApex} (${serverIp})`, currentNs, currentParent);
                break;
            }

            const validNsRecords = authorities.filter(r => r.type === 'NS' && isSubdomainOrEqual(domain, r.name));
            if (validNsRecords.length > 0) {
                const nextZone = normalizeDnsName(validNsRecords[0].name);
                if (nextZone !== lastDelegatedZone) {
                    delegation = { nsRecords: validNsRecords, additionals: res.additionals || [], serverIp, nextZone };
                    break;
                }
            }

            pushExplorationLog('UNEXPECTED_RESPONSE', `ゾーン頂点を特定できない応答です (${serverIp}, rcode: ${res.rcode}, AA: ${isAuthoritative})。`, currentNs, currentParent);
        }

        if (zoneApex || cdName) break;
        if (!delegation) break;

        const nextNsNames = delegation.nsRecords.map(record => normalizeDnsName(record.data));
        const glueIPs = delegation.additionals
            .filter(record => isInBailiwickGlue(record, nextNsNames, delegation.nextZone))
            .map(record => record.data);
        const resolvedIPs = await Promise.all(nextNsNames.map(resolveServerIPs));
        const nextServerIPs = [...new Set([...glueIPs, ...resolvedIPs.flat().filter(Boolean)])];

        pushExplorationLog('FOLLOW_DELEGATION', `${currentNs} が ${nextNsNames.join(', ')} を示しました。 (${delegation.serverIp})`, currentNs, currentParent, {
            nextServer: nextNsNames,
            glueIPs,
            rfc9471: summarizeRfc9471Referral(delegation.nsRecords, delegation.additionals)
        });
        parentNs = currentNs;
        parentServerIPs = currentServerIPs;
        currentNs = nextNsNames.join(', ');
        currentServerIPs = nextServerIPs;
        lastDelegatedZone = delegation.nextZone;
    }
    return {
        currentNs: currentNs,
        parentNs: parentNs,
        parentServerIPs: parentServerIPs,
        zoneApex: zoneApex,
        cdName: cdName,
        explorationLogs: explorationLogs,
        errorLogs: explorationLogs
    };
}

async function traceDomain(domain, servers, dnsResponseCache, parentIP = null, currentDepth = 1, expectedNSList = [], parentGlueMap = {}) {
    let results = [];
    if (currentDepth > 10) {
        results.push({
            server: servers[0] || '',
            parent: parentIP,
            status: 'LAME_DELEGATION_MAX_DEPTH',
            detail: `委任チェーンが上限 (${10}) に達したため、以降の追跡を打ち切りました。`,
            nsMatch: null,
            glueMatch: null
        });
        return results;
    }

    for (const serverIp of servers) {
        let logEntry = {
            server: serverIp,
            parent: parentIP,
            status: 'Querying',
            detail: '',
            nsMatch: null,
            glueMatch: null
        };

        const res = await queryDirectlyUDP(domain, serverIp, dnsResponseCache, 'NS');

        if (res.error === 'TIMEOUT') {
            logEntry.status = 'LAME_DELEGATION_TIMEOUT';
            if (res.isCached) {
                logEntry.detail = `サーバーから応答がありません。(キャッシュ再利用)`;
            } else {
                logEntry.detail = `サーバーから応答がありません。`;
            }
            results.push(logEntry);
            continue; 
        }

        if (res.error === 'SEND_ERROR' || res.error === 'SOCKET_ERROR' || res.error === 'DECODE_ERROR') {
            logEntry.status = 'NETWORK_ERROR';
            logEntry.detail = `エラー: ${res.detail}`;
            results.push(logEntry);
            continue;
        }

        const AUTHORITATIVE_ANSWER = dnsPacket.AUTHORITATIVE_ANSWER || 1024;
        const isAuthoritative = (res.flags & AUTHORITATIVE_ANSWER) !== 0;
        const answers = res.answers || [];
        const authorities = res.authorities || [];
        const additionals = res.additionals || [];

        const cacheNote = res.isCached ? ' (キャッシュ再利用)' : '';

        if (isAuthoritative && answers.length === 0) {
            logEntry.status = 'LAME_DELEGATION_NO_ZONE';
            logEntry.detail = `AUTHORITYとして指定されていますが、ゾーンを保持していません。${cacheNote}`;
            results.push(logEntry);
            continue;
        }

        if (isAuthoritative && answers.length > 0) {
            logEntry.status = 'SUCCESS';

            const childNSList = answers
                .filter(r => r.type === 'NS' && hasParentChildRelationship(domain, r.name))
                .map(r => normalizeDnsName(r.data));
            const parentNSListNormalized = expectedNSList.map(ns => normalizeDnsName(ns));

            if (childNSList.length > 0 && parentNSListNormalized.length > 0) {
                const isMatch = childNSList.length === parentNSListNormalized.length &&
                                childNSList.every(ns => parentNSListNormalized.includes(ns));

                if (isMatch) {
                    logEntry.nsMatch = {
                        success: true,
                        msg: `✅ NS情報一致！${cacheNote}\r委任情報: [${parentNSListNormalized.sort().join(', ')}]`
                    };
                } else {
                    logEntry.nsMatch = {
                        success: false, 
                        msg: `⚠️ NS情報不一致！\r親が保持する委任情報: [${parentNSListNormalized.sort().join(', ')}]\r子が保持する NS情報: [${childNSList.sort().join(', ')}]${cacheNote}`
                    };
                    logEntry.status = 'LAME_DELEGATION_NOT_MATCH';
                }
            } else if (childNSList.length === 0 && parentNSListNormalized.length > 0) {
                logEntry.nsMatch = {
                    success: false,
                    msg: `⚠️ NS情報不一致！\r親が保持する委任情報: [${parentNSListNormalized.sort().join(', ')}]\r子が保持する NS情報: (NSレコードが存在しません)${cacheNote}`
                };
                logEntry.status = 'LAME_DELEGATION_NOT_MATCH';
            }

            const currentNSName = Object.keys(parentGlueMap).find(name => parentGlueMap[name].includes(serverIp));

            if (currentNSName) {
                const childIPs = await resolveServerIPs(currentNSName);
                const parentGlueIPs = parentGlueMap[currentNSName] || [];

                if (childIPs) {
                    if (parentGlueIPs.length > 0) {
                        const sortedChild = [...childIPs].sort();
                        const sortedParent = [...parentGlueIPs].sort();
                        const isGlueMatch = sortedChild.length === sortedParent.length &&
                                            sortedChild.every((ip, i) => ip === sortedParent[i]);

                        if (isGlueMatch) {
                            logEntry.glueMatch = {
                                success: true,
                                msg: `✅ IPアドレス一致！【${currentNSName}】\r子の IPアドレス: [${sortedChild.sort().join(', ')}]`
                            };
                        } else {
                            logEntry.glueMatch = {
                                success: false,
                                msg: `⚠️ IPアドレス不一致！【${currentNSName}】\r親が保持する子情報: [${sortedParent.sort().join(', ')}]\r子の IPアドレス: [${sortedChild.sort().join(', ')}]`
                            };
                            logEntry.status = 'LAME_DELEGATION_NOT_MATCH';
                        }
                    }
                } else {
                    logEntry.glueMatch = { 
                        success: false, 
                        msg: `⚠️ IPアドレス不一致！【${currentNSName}】IPアドレスを得られませんでした。`
                    };
                    logEntry.status = 'LAME_DELEGATION_NO_IP_ADDRESS';
                }
            }

            if (logEntry.status !== 'SUCCESS') {
                logEntry.detail = `委任元 (親) と委任先 (子) とで情報が一致していません。${cacheNote}`;
            } else {
                logEntry.detail = `正しく委任できています。${cacheNote}`;
            }
            results.push(logEntry);
            continue;
        }

        const nsRecords = authorities.filter(r => r.type === 'NS' && hasParentChildRelationship(domain, r.name));
        if (nsRecords.length > 0) {
            logEntry.status = 'DELEGATED';
            logEntry.detail = `AUTHORITY SECTION に ${nsRecords.length} 個の NSレコード。IPアドレスを以下に列挙。${cacheNote}`;
            results.push(logEntry);

            const currentNSNames = nsRecords.map(r => normalizeDnsName(r.data));
            const delegatedZone = normalizeDnsName(nsRecords[0].name);
            logEntry.rfc9471 = summarizeRfc9471Referral(nsRecords, additionals, res.retryFrom);

            let nextGlueMap = {};
            let nextServerIPs = [];

            for (const ns of nsRecords) {
                const nsKey = normalizeDnsName(ns.data);
                nextGlueMap[nsKey] = [];

                const matchedGlues = additionals.filter(record => isInBailiwickGlue(record, [nsKey], delegatedZone));
                if (matchedGlues.length > 0) {
                    // 本来の意味での Glueをリストに登録
                    matchedGlues.forEach(g => {
                        nextServerIPs.push(g.data);
                        nextGlueMap[nsKey].push(g.data);
                    });
                } else {
                    // 本来の意味での Glueが無かった場合に、親が持つ子情報から IPアドレスを取得してリストに登録
                    const resolvedIPs = await resolveServerIPs(ns.data);
                    if (resolvedIPs) {
                        resolvedIPs.forEach(ip => {
                            nextServerIPs.push(ip);
                        });
                    }
                }
            }

            nextServerIPs = [...new Set(nextServerIPs)];

            if (nextServerIPs.length > 0) {
                const childResults = await traceDomain(domain, nextServerIPs, dnsResponseCache, serverIp, currentDepth + 1, currentNSNames, nextGlueMap);
                results = results.concat(childResults);
            } else {
                results.push({
                    server: serverIp, parent: parentIP, status: 'ERROR',
                    detail: `次の委任先 NSレコードの IPアドレスを特定できませんでした。`
                });
            }
        } else {
            logEntry.status = 'LAME_DELEGATION_NO_AUTHORITY_NS';
            logEntry.detail = `権威サーバーが AUTHORITY セクションに NS レコードを持っていません。委任情報が欠落している可能性があります。${cacheNote}`;
            results.push(logEntry);
        }
    }
    return results;
}

app.post('/api/trace', async (req, res) => {
    const domain = normalizeUserDomain(req.body?.domain);
    if (!domain) {
        return res.status(400).json({ error: 'ドメイン名を入力してください' });
    }

    const dnsResponseCache = new Map();

    try {
        const zoneApexInfo = await getZoneApex(domain, dnsResponseCache);
        const explorationLog = zoneApexInfo.explorationLogs || zoneApexInfo.errorLogs || [];

        let traceLog = [];
        if (zoneApexInfo.zoneApex !== '') {
            const serverList = zoneApexInfo.parentServerIPs.length > 0
                ? zoneApexInfo.parentServerIPs
                : await resolveServerIPs('a.root-servers.net');
            traceLog = await traceDomain(zoneApexInfo.zoneApex, serverList, dnsResponseCache, null, 1, [], {});
        }

        res.json({
            success: true,
            zoneApexLog: [...explorationLog],
            traceLog: [...traceLog]
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

const PORT = 3001;
const server = app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
server.timeout = 120000; 
