import express from 'express';
import dgram from 'dgram';
import dnsPacket from 'dns-packet';	// https://github.com/mafintosh/dns-packet
import promisesDns from 'dns/promises';

const app = express();
app.use(express.json());
app.use(express.static('public'));

function isIPv6(ip) {
    return ip.includes(':');
}

function queryDirectly(domain, serverIp, dnsResponseCache, qType = 'NS') {
    return new Promise((resolve) => {
        // もし以前にこのサーバーへの問い合わせ実績があれば、通信せずキャッシュから即座に復元
        if (dnsResponseCache.has(serverIp)) {
            const cachedResult = dnsResponseCache.get(serverIp);
            return resolve({ ...cachedResult, isCached: true });
        }

        const socketType = isIPv6(serverIp) ? 'udp6' : 'udp4';
        const client = dgram.createSocket(socketType);
        
        const AUTHORITATIVE_ANSWER = dnsPacket.AUTHORITATIVE_ANSWER || 1024; 

        try {
            const buf = dnsPacket.encode({
                type: 'query',
                id: Math.floor(Math.random() * 65534),
                questions: [{ type: qType, name: domain }],
                additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 1232 }]
            });

            client.send(buf, 0, buf.length, 53, serverIp, (err) => {
                if (err) { 
                    client.close(); 
                    resolve({ error: 'SEND_ERROR', detail: err.message }); 
                }
            });
        } catch (e) {
            client.close();
            resolve({ error: 'SEND_ERROR', detail: e.message });
        }

        const timer = setTimeout(() => {
            client.close();
            const timeoutResult = { error: 'TIMEOUT' };
            dnsResponseCache.set(serverIp, timeoutResult);
            resolve(timeoutResult);
        }, 5000);

        client.on('message', (msg) => {
            clearTimeout(timer);
            client.close();
            try {
                const decoded = dnsPacket.decode(msg);
                // ANSWER SECTION に NS があったらキャッシュに登録
                const answers = decoded.answers || [];
                let nsRecord = answers.find(r => r.type === 'NS');
                if (nsRecord) {
                    dnsResponseCache.set(serverIp, decoded);
                }
                // AUTHORITY SECTION に NS があったらキャッシュに登録
                const authorities = decoded.authorities || [];
                nsRecord = authorities.find(r => r.type === 'NS');
                if (nsRecord) {
                    dnsResponseCache.set(serverIp, decoded);
                }
                // DNSメッセージを返す
                resolve(decoded);
            } catch (e) {
                resolve({ error: 'DECODE_ERROR', detail: e.message });
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
    let parentNs = '';
    let zoneApex = '';
    let rcode = '';
    let cdName = false;

    for (let i = 0; i < 10; i++) {
        const res = await queryDirectly(domain, currentNs, dnsResponseCache, 'SOA');

        if (res.error === 'TIMEOUT' || res.error === 'SEND_ERROR' || res.error === 'DECODE_ERROR') {
            continue;
        }
        rcode = res.rcode;

        const AUTHORITATIVE_ANSWER = dnsPacket.AUTHORITATIVE_ANSWER || 1024;
        const isAuthoritative = (res.flags & AUTHORITATIVE_ANSWER) !== 0;
        const answers = res.answers || [];
        const authorities = res.authorities || [];
        const additionals = res.additionals || [];
        if (isAuthoritative) {
            if (res.rcode === 'NOERROR') {
                if (answers.length > 0) {
                    const cnameRecord = answers.find(r => r.type === 'CNAME');
                    if (cnameRecord) {
                        cdName = true;
                        break;
                    }
                    const dnameRecord = answers.find(r => r.type === 'DNAME');
                    if (dnameRecord) {
                        cdName = true;
                        break;
                    }
                    const soaRecord = answers.find(r => r.type === 'SOA');
                    if (soaRecord) {
                        zoneApex = soaRecord.name;
                        break;
                    }
                } else if (authorities.length > 0) {
                    const soaRecord = authorities.find(r => r.type === 'SOA');
                    if (soaRecord) {
                        zoneApex = soaRecord.name;
                        break;
                    }
                }
            }
            if (res.rcode === 'NXDOMAIN') {
                if (authorities.length > 0) {
                    const soaRecord = authorities.find(r => r.type === 'SOA');
                    if (soaRecord) {
                        zoneApex = soaRecord.name;
                        break;
                    }
                }
            }
        }
        if (!isAuthoritative && authorities.length > 0) {
            const nsRecord = authorities.find(r => r.type === 'NS');
            if (nsRecord) {
                parentNs = currentNs;
                currentNs = nsRecord.data;
            }
        }
    }
    return { currentNs: currentNs, parentNs: parentNs, zoneApex: zoneApex, rcode: rcode, cdName: cdName };
}

async function traceDomain(domain, servers, dnsResponseCache, parentIP = null, currentDepth = 1, expectedNSList = [], parentGlueMap = {}) {
    let results = [];
    if (currentDepth > 10) return results;

    for (const serverIp of servers) {
        let logEntry = {
            server: serverIp,
            parent: parentIP,
            status: 'Querying',
            detail: '',
            nsMatch: null,
            glueMatch: null
        };

        const res = await queryDirectly(domain, serverIp, dnsResponseCache, 'NS');

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

        if (res.error === 'SEND_ERROR' || res.error === 'DECODE_ERROR') {
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

            const childNSList = answers.filter(r => r.type === 'NS').map(r => r.data.toLowerCase().replace(/\.$/, ''));
            const parentNSListNormalized = expectedNSList.map(ns => ns.toLowerCase().replace(/\.$/, ''));

            if (childNSList.length > 0 && parentNSListNormalized.length > 0) {
                const isMatch = childNSList.length === parentNSListNormalized.length &&
                                childNSList.every(ns => parentNSListNormalized.includes(ns));

                if (isMatch) {
                    logEntry.nsMatch = {
                        success: true,
                        msg: `✅ NS情報一致！${cacheNote}\r　委任情報: [${parentNSListNormalized.sort().join(', ')}]`
                    };
                } else {
                    logEntry.nsMatch = {
                        success: false, 
                        msg: `⚠️ NS情報不一致！\r　親が保持する委任情報: [${parentNSListNormalized.sort().join(', ')}]\r　子が保持する NS情報: [${childNSList.sort().join(', ')}]${cacheNote}`
                    };
                    logEntry.status = 'LAME_DELEGATION_NOT_MATCH';
                }
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
                                msg: `✅ IPアドレス一致！【${currentNSName}】\r　子の IPアドレス: [${sortedChild.sort().join(', ')}]`
                            };
                        } else {
                            logEntry.glueMatch = {
                                success: false,
                                msg: `⚠️ IPアドレス不一致！【${currentNSName}】\r　親が保持する子情報: [${sortedParent.sort().join(', ')}]\r　子の IPアドレス: [${sortedChild.sort().join(', ')}]`
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

        const nsRecords = authorities.filter(r => r.type === 'NS');
        if (nsRecords.length > 0) {
            logEntry.status = 'DELEGATED';
            logEntry.detail = `AUTHORITY SECTION に ${nsRecords.length} 個の NSレコード。IPアドレスを以下に列挙。${cacheNote}`;
            results.push(logEntry);

            const currentNSNames = nsRecords.map(r => r.data);

            let nextGlueMap = {};
            let nextServerIPs = [];

            for (const ns of nsRecords) {
                const nsKey = ns.data.toLowerCase().replace(/\.$/, '');
                nextGlueMap[nsKey] = [];

                const matchedGlues = additionals.filter(r => r.name === ns.data && (r.type === 'A' || r.type === 'AAAA'));
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
                            nextGlueMap[nsKey].push(ip);
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
            logEntry.status = 'ERROR';
            logEntry.detail = `委任先情報 (NSレコード) が見つかりませんでした。`;
            results.push(logEntry);
        }
    }
    return results;
}

app.post('/api/trace', async (req, res) => {
    const { domain } = req.body;
    if (!domain) {
        return res.status(400).json({ error: 'ドメイン名を入力してください' });
    }

    const dnsResponseCache = new Map();
    let logEntry = {
        server: '',
        parent: '',
        status: '',
        detail: '',
        nsMatch: null,
        glueMatch: null
    };

    try {
        const zoneApexInfo = await getZoneApex(domain, dnsResponseCache);
        if (zoneApexInfo.zoneApex === '') {
            logEntry.server = zoneApexInfo.parentNs;
            logEntry.parent = zoneApexInfo.parentNs;
            logEntry.status = 'ERROR';
            if (zoneApexInfo.cdName) {
                logEntry.detail = 'このドメイン名は CNAME/DNAME のためゾーン頂点を特定できませんでした。';
            } else {
                logEntry.detail = `${zoneApexInfo.currentNs} から先の探索ができませんでした。(rcode: ${zoneApexInfo.rcode})`;
            }
            const fullLog = new Array(logEntry);
            res.json({ success: true, log: fullLog });
        } else if (zoneApexInfo.parentNs !== '') {
            logEntry.server = zoneApexInfo.parentNs;
            logEntry.parent = zoneApexInfo.parentNs;
            logEntry.status = 'INFO';
            logEntry.detail = `ゾーン頂点は ${zoneApexInfo.zoneApex} です。`;
            const fullLog = new Array(logEntry);
            const serverList = new Array(zoneApexInfo.parentNs);
            const traceLog = await traceDomain(zoneApexInfo.zoneApex, serverList, dnsResponseCache, null, 1, [], {});
            fullLog.push(...traceLog);
            res.json({ success: true, log: fullLog });
        } else {
            const serverList = new Array('a.root-servers.net');
            const fullLog = await traceDomain(zoneApexInfo.zoneApex, serverList, dnsResponseCache, null, 1, [], {});
            res.json({ success: true, log: fullLog });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

const PORT = 3001;
const server = app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
server.timeout = 120000; 
