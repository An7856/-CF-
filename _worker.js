import { connect } from 'cloudflare:sockets';

let subPath = 'link';
let serverPool = ['13.230.34.30'];
let yourUUID = '';

let cfip = [
    'ip.sb', 'time.is', 'skk.moe', 'www.visa.com.tw', 'www.visa.com.hk', 'www.visa.com.sg',
    'cdns.doon.eu.org', 'cf.zhetengsha.eu.org'
];

let dnsResolver = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg=';

const KV_CFIP_KEY = 'cfip_list';
const KV_FDIP_KEY = 'fdip_list';
const KV_PASSWORD_KEY = 'admin_password';
const KV_UUID_KEY = 'user_uuid';

async function loadConfigFromKV(env) {
    try {
        if (env.KV_NAMESPACE || env.kv_namespace) {
            const kv = env.KV_NAMESPACE || env.kv_namespace;
            const [cfipData, fdipData, uuidData] = await Promise.all([
                kv.get(KV_CFIP_KEY),
                kv.get(KV_FDIP_KEY),
                kv.get(KV_UUID_KEY)
            ]);
            
            if (cfipData) {
                cfip = cfipData.split(',').filter(item => item.trim() !== '');
            }
            
            if (fdipData) {
                serverPool = fdipData.split(',').filter(item => item.trim() !== '');
            }
            
            if (uuidData) {
                yourUUID = uuidData;
            }
        }
    } catch (error) {
        console.error('从KV加载配置失败:', error);
    }
}

async function getPasswordFromKV(env) {
    try {
        if (env.KV_NAMESPACE || env.kv_namespace) {
            const kv = env.KV_NAMESPACE || env.kv_namespace;
            return await kv.get(KV_PASSWORD_KEY);
        }
        return null;
    } catch (error) {
        console.error('从KV获取密码失败:', error);
        return null;
    }
}

async function getUUIDFromKV(env) {
    try {
        if (env.KV_NAMESPACE || env.kv_namespace) {
            const kv = env.KV_NAMESPACE || env.kv_namespace;
            return await kv.get(KV_UUID_KEY);
        }
        return null;
    } catch (error) {
        console.error('从KV获取UUID失败:', error);
        return null;
    }
}

async function setPasswordToKV(env, password) {
    try {
        if (env.KV_NAMESPACE || env.kv_namespace) {
            const kv = env.KV_NAMESPACE || env.kv_namespace;
            await kv.put(KV_PASSWORD_KEY, password);
            return true;
        }
        return false;
    } catch (error) {
        console.error('保存密码到KV失败:', error);
        return false;
    }
}

async function setUUIDToKV(env, uuid) {
    try {
        if (env.KV_NAMESPACE || env.kv_namespace) {
            const kv = env.KV_NAMESPACE || env.kv_namespace;
            await kv.put(KV_UUID_KEY, uuid);
            return true;
        }
        return false;
    } catch (error) {
        console.error('保存UUID到KV失败:', error);
        return false;
    }
}

async function saveConfigToKV(env, cfipList, fdipList, uuid = null) {
    try {
        if (env.KV_NAMESPACE || env.kv_namespace) {
            const kv = env.KV_NAMESPACE || env.kv_namespace;
            const promises = [
                kv.put(KV_CFIP_KEY, cfipList.join(',')),
                kv.put(KV_FDIP_KEY, fdipList.join(','))
            ];
            
            if (uuid) {
                promises.push(kv.put(KV_UUID_KEY, uuid));
            }
            
            await Promise.all(promises);
            return true;
        }
        return false;
    } catch (error) {
        console.error('保存配置到KV失败:', error);
        return false;
    }
}

function parseServerAddress(serverStr) {
    const defaultPort = 443; 
    let hostname = serverStr.trim();
    let port = defaultPort;
    
    if (hostname.includes('.tp')) {
        const portMatch = hostname.match(/\.tp(\d+)\./);
        if (portMatch) {
            port = parseInt(portMatch[1]);
        }
    } else if (hostname.includes('[') && hostname.includes(']:')) {
        port = parseInt(hostname.split(']:')[1]);
        hostname = hostname.split(']:')[0] + ']';
    } else if (hostname.includes(':')) {
        const parts = hostname.split(':');
        port = parseInt(parts[parts.length - 1]);
        hostname = parts.slice(0, -1).join(':');
    }
    
    return {
        hostname: hostname,
        port: port
    };
}

async function resolveHostname(hostname) {
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(hostname)) {
        return hostname;
    }
    
    try {
        const dnsResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`, {
            headers: {
                'Accept': 'application/dns-json'
            }
        });
        
        if (dnsResponse.ok) {
            const dnsData = await dnsResponse.json();
            if (dnsData.Answer && dnsData.Answer.length > 0) {
                return dnsData.Answer[0].data;
            }
        }
        
        console.warn(`DNS resolution failed for ${hostname}, using original hostname`);
        return hostname;
    } catch (error) {
        console.warn(`DNS resolution error for ${hostname}:`, error);
        return hostname;
    }
}

async function connectWithFailover() {
    const validServers = serverPool.filter(server => server && server.trim() !== '');
    const allServers = [...validServers, 'Kr.tp50000.netlib.re'];
    let lastError = null;
    
    for (let i = 0; i < allServers.length; i++) {
        try {
            const serverStr = allServers[i];
            const { hostname, port } = parseServerAddress(serverStr);
            const resolvedHostname = await resolveHostname(hostname);
            
            const socket = await connect({
                hostname: resolvedHostname,
                port: port,
            });
            
            return {
                socket,
                server: {
                    hostname: resolvedHostname,
                    port: port,
                    original: serverStr
                }
            };
        } catch (error) {
            lastError = error;
            continue;
        }
    }
    
    throw new Error(`All servers connect failed: ${lastError?.message || 'Unknown error'}`);
}

function obfuscateUserAgent() {
    const userAgents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
    ];
    return userAgents[Math.floor(Math.random() * userAgents.length)];
}

export default {
    async fetch(request, env, ctx) {
        try {
            await loadConfigFromKV(env);

            if (subPath === 'link' || subPath === '') {
                subPath = yourUUID || 'link';
            }

            if (env.FDIP) {
                const servers = env.FDIP.split(',').map(s => s.trim());
                serverPool = servers;
            }
            subPath = env.SUB_PATH || env.subpath || subPath;
            yourUUID = env.UUID || env.uuid || env.AUTH || yourUUID;
            dnsResolver = env.DNS_RESOLVER || dnsResolver;
            const upgradeHeader = request.headers.get('Upgrade');
            const url = new URL(request.url);
        
            if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
                return await VLOverWSHandler(request);
            } else {
                switch (url.pathname) {
                    case '/':
                        return await getHomePage(request, env);
                    case `/${subPath}`:
                        return getSubscription(request);
                    case '/info':
                        return new Response(JSON.stringify(request.cf, null, 4), {
                            status: 200,
                            headers: {
                                "Content-Type": "application/json;charset=utf-8",
                            },
                        });
                    case '/connect':
                        const [hostname, port] = ['cloudflare.com', '80'];
                        console.log(`Connecting to ${hostname}:${port}...`);

                        try {
                            const socket = await connect({
                                hostname: hostname,
                                port: parseInt(port, 10),
                            });

                            const writer = socket.writable.getWriter();

                            try {
                                await writer.write(new TextEncoder().encode('GET / HTTP/1.1\r\nHost: ' + hostname + '\r\n\r\n'));
                            } catch (writeError) {
                                writer.releaseLock();
                                await socket.close();
                                return new Response(writeError.message, { status: 500 });
                            }

                            writer.releaseLock();

                            const reader = socket.readable.getReader();
                            let value;

                            try {
                                const result = await reader.read();
                                value = result.value;
                            } catch (readError) {
                                await reader.releaseLock();
                                await socket.close();
                                return new Response(readError.message, { status: 500 });
                            }

                            await reader.releaseLock();
                            await socket.close();

                            return new Response(new TextDecoder().decode(value), { status: 200 });
                        } catch (connectError) {
                            return new Response(connectError.message, { status: 500 });
                        }
                    case '/test-dns': 
                        try {
                            const testResults = [];
                            for (const server of serverPool) {
                                const { hostname, port } = parseServerAddress(server);
                                const resolvedHostname = await resolveHostname(hostname);
                                testResults.push({
                                    original: server,
                                    parsed: { hostname, port },
                                    resolved: resolvedHostname
                                });
                            }
                            return new Response(JSON.stringify(testResults, null, 2), {
                                status: 200,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        } catch (error) {
                            return new Response(JSON.stringify({ error: error.message }), {
                                status: 500,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }
                    case '/test-config': 
                        try {
                            return new Response(JSON.stringify({
                                subPath: subPath,
                                yourUUID: yourUUID,
                                serverPool: serverPool,
                                proxyIP: cfip,
                                timestamp: new Date().toISOString()
                            }, null, 2), {
                                status: 200,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        } catch (error) {
                            return new Response(JSON.stringify({ error: error.message }), {
                                status: 500,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }
                    case '/test-failover': 
                        try {
                            const testResults = {
                                serverPool: serverPool,
                                proxyIP: cfip,
                                fallbackServer: 'Kr.tp50000.netlib.re',
                                connectionTests: []
                            };
                            
                            const validServers = serverPool.filter(server => server && server.trim() !== '');
                            const allServers = [...validServers, 'Kr.tp50000.netlib.re'];
                            for (const server of allServers) {
                                try {
                                    const { hostname, port } = parseServerAddress(server);
                                    const resolvedHostname = await resolveHostname(hostname);
                                    
                                    const socket = await connect({
                                        hostname: resolvedHostname,
                                        port: port,
                                    });
                                    
                                    await socket.close();
                                    
                                    testResults.connectionTests.push({
                                        server: server,
                                        hostname: resolvedHostname,
                                        port: port,
                                        status: 'success'
                                    });
                                } catch (error) {
                                    testResults.connectionTests.push({
                                        server: server,
                                        status: 'failed',
                                        error: error.message
                                    });
                                }
                            }
                            
                            return new Response(JSON.stringify(testResults, null, 2), {
                                status: 200,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        } catch (error) {
                            return new Response(JSON.stringify({ error: error.message }), {
                                status: 500,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }
                    case '/admin/save':
                        return await handleAdminSave(request, env);
                    case '/admin':
                        return await getAdminPage(request, env);
                    case '/set-password':
                        return await handleSetPassword(request, env);
                    case '/set-uuid':
                        return await handleSetUUID(request, env);
                    case '/change-password':
                        return await handleChangePassword(request, env);
                    default:
                        const randomSites = cfip.length > 0 ? cfip : [
                            'ip.sb', 'time.is', 'www.apple.com', 'skk.moe',
                            'www.visa.com.tw', 'www.github.com', 'www.ups.com',
                            'www.tesla.com', 'www.microsoft.com', 'www.amazon.com'
                        ];
                        const randomSite = randomSites[Math.floor(Math.random() * randomSites.length)];
                        
                        const Url = new URL(`https://${randomSite}${url.pathname}${url.search}`);
                        
                        const headers = new Headers(request.headers);
                        headers.set('User-Agent', obfuscateUserAgent());
                        headers.set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8');
                        headers.set('Accept-Language', 'zh-CN,zh;q=0.9,en;q=0.8');
                        headers.set('Accept-Encoding', 'gzip, deflate, br');
                        headers.set('DNT', '1');
                        headers.set('Connection', 'keep-alive');
                        headers.set('Upgrade-Insecure-Requests', '1');
                        headers.set('Host', randomSite);
                        
                        const UrlRequest = new Request(Url, {
                            method: request.method,
                            headers: headers,
                            body: request.body
                        });
                        
                        try {
                            const response = await fetch(UrlRequest);
                            return response;
                        } catch (error) {
                            return new Response('Service Unavailable', { status: 502 });
                        }
                }
            }
        } catch (err) {
            return new Response('Internal Server Error', {
                status: 500,
                headers: {
                    'Content-Type': 'text/plain;charset=utf-8',
                },
            });
        }
    },
};

async function VLOverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    const log = () => {};
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWapper = {
        value: null,
    };
    let udpStreamWrite = null;
    let isDns = false;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            try {
            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWapper.value) {
                    
                const writer = remoteSocketWapper.value.writable.getWriter()
                await writer.write(chunk);
                writer.releaseLock();
                return;
                }
                } catch (writeError) {
                    controller.error(writeError);
                }

            const {
                hasError,
                message,
                portRemote = 443,
                addressRemote = '',
                rawDataIndex,
                VLVersion = new Uint8Array([0, 0]),
                isUDP,
            } = await processVLHeader(chunk, yourUUID);
            if (hasError) {
                throw new Error(message);
            }
            if (isUDP) {
                if (portRemote === 53) {
                    isDns = true;
            } else {
                throw new Error('only enable for DNS which is port 53');
            }
            }
            const VLResponseHeader = new Uint8Array([VLVersion[0], 0]);
            const rawClientData = chunk.slice(rawDataIndex);

            if (isDns) {
                const { write } = await handleUDPOutBound(webSocket, VLResponseHeader, log);
                udpStreamWrite = write;
                udpStreamWrite(rawClientData);
                return;
            }
            handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, VLResponseHeader, log);
        },
        close() {
            log(`readableWebSocketStream is close`);
        },
        abort(reason) {
            log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
    })).catch((err) => {
        log('readableWebSocketStream pipeTo error', err);
    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, VLResponseHeader, log,) {
    async function connectAndWrite(address, port) {
        try {
            const tcpSocket = connect({
                hostname: address,
                port: port,
            });
            remoteSocket.value = tcpSocket;
            
            const writer = tcpSocket.writable.getWriter();
            await writer.write(rawClientData); 
            writer.releaseLock();
            return tcpSocket;
        } catch (connectError) {
            throw connectError;
        }
    }

    async function retry() {
        try {
            const { socket: tcpSocket, server } = await connectWithFailover();
            remoteSocket.value = tcpSocket;
            
            const writer = tcpSocket.writable.getWriter();
            await writer.write(rawClientData);
            writer.releaseLock();
            
            tcpSocket.closed.catch(error => {
                safeCloseWebSocket(webSocket);
            }).finally(() => {
                safeCloseWebSocket(webSocket);
            });
            remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
        } catch (retryError) {
            console.error('All servers connect failed:', retryError.message);
            safeCloseWebSocket(webSocket);
        }
    }

    try {
        const tcpSocket = await connectAndWrite(addressRemote, portRemote);
        remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, retry, log);
    } catch (connectError) {
        console.log(`direct connect failed, try to use failover: ${addressRemote}:${portRemote}`);
        retry();
    }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });

            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            }
            );
            webSocketServer.addEventListener('error', (err) => {
                controller.error(err);
            }
            );
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },

        pull(controller) {

        },
        cancel(reason) {
            if (readableStreamCancel) {
                return;
            }
            readableStreamCancel = true;
            safeCloseWebSocket(WebSocketServer);
        }
    });

    return stream;

}

async function processVLHeader(
    VLBuffer,
    yourUUID
) {
    if (VLBuffer.byteLength < 24) {
        return {
            hasError: true,
            message: 'invalid data',
        };
    }
    const version = new Uint8Array(VLBuffer.slice(0, 1));
    let isValidUser = false;
    let isUDP = false;
    const slicedBuffer = new Uint8Array(VLBuffer.slice(1, 17));
    const slicedBufferString = stringify(slicedBuffer);

    const ids = yourUUID.includes(',') ? yourUUID.split(",") : [yourUUID];

    isValidUser = ids.some(uuid => slicedBufferString === uuid.trim());

    if (!isValidUser) {
        return {
            hasError: true,
            message: 'invalid user',
        };
    }

    const optLength = new Uint8Array(VLBuffer.slice(17, 18))[0];

    const command = new Uint8Array(
        VLBuffer.slice(18 + optLength, 18 + optLength + 1)
    )[0];

    if (command === 1) {
    } else if (command === 2) {
        isUDP = true;
    } else {
        return {
            hasError: true,
            message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }
    const portIndex = 18 + optLength + 1;
    const portBuffer = VLBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(
        VLBuffer.slice(addressIndex, addressIndex + 1)
    );

    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = '';
    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(
                VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            ).join('.');
            break;
        case 2:
            addressLength = new Uint8Array(
                VLBuffer.slice(addressValueIndex, addressValueIndex + 1)
            )[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(
                VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(
                VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(':');
            break;
        default:
            return {
                hasError: true,
                message: `invild  addressType is ${addressType}`,
            };
    }
    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        VLVersion: version,
        isUDP,
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, VLResponseHeader, retry, log) {
    let VLHeader = VLResponseHeader;
    let hasIncomingData = false; 
    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() {
                },
                async write(chunk, controller) {
                    try {
                    hasIncomingData = true;
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error(
                            'webSocket.readyState is not open, maybe close'
                        );
                            return;
                        }

                        
                        if (VLHeader) {
                            webSocket.send(await new Blob([VLHeader, chunk]).arrayBuffer());
                            VLHeader = null;
                    } else {
                        webSocket.send(chunk);
                        }
                    } catch (sendError) {
                        controller.error(sendError);
                    }
                },
                close() {
                },
                abort(reason) {
                },
            })
        )
        .catch((error) => {
            safeCloseWebSocket(webSocket);
        });

    if (hasIncomingData === false && retry) {
        retry();
    }
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

function isValidAUTH(id) {
    const idRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return idRegex.test(id);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
    }
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}
function unsafeStringify(arr, offset = 0) {
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}
function stringify(arr, offset = 0) {
    const id = unsafeStringify(arr, offset);
    if (!isValidAUTH(id)) {
        throw TypeError("Stringified id is invalid");
    }
    return id;
}

async function handleUDPOutBound(webSocket, VLResponseHeader, log) {

    let isVLHeaderSent = false;
    const transformStream = new TransformStream({
        start(controller) {

        },
        transform(chunk, controller) {
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(
                    chunk.slice(index + 2, index + 2 + udpPakcetLength)
                );
                index = index + 2 + udpPakcetLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) {
        }
    });

    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch(dnsResolver,
                {
                    method: 'POST',
                    headers: {
                        'content-type': 'application/dns-message',
                    },
                    body: chunk,
                })
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                if (isVLHeaderSent) {
                    webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                } else {
                    webSocket.send(await new Blob([VLResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    isVLHeaderSent = true;
                }
            }
        }
    })).catch((error) => {
    });

    const writer = transformStream.writable.getWriter();

    return {
        write(chunk) {
            writer.write(chunk);
        }
    };
}

function getFlagEmoji(countryCode) {
    if (!countryCode || countryCode.length !== 2) return '';
    const codePoints = countryCode
        .toUpperCase()
        .split('')
        .map(char => 127397 + char.charCodeAt());
    return String.fromCodePoint(...codePoints);
}

function getVLConfig(yourUUID, url) {
    if (!yourUUID) return '';
    
    const wsPath = '/?ed=2560';
    const encodedPath = encodeURIComponent(wsPath);
    const header = 'v-l-e-s-s';
    
    const configs = cfip.map(item => {
        let address = item;
        let port = 443;
        let countryName = '';
        let countryCode = '';
        
        if (item.includes('#')) {
            const parts = item.split('#');
            address = parts[0];
            
            if (parts[1].includes('|')) {
                const countryParts = parts[1].split('|');
                countryName = countryParts[0];
                countryCode = countryParts[1] || '';
            } else {
                countryName = parts[1];
            }
        }
        
        if (address.includes(':')) {
            const addressParts = address.split(':');
            address = addressParts[0];
            port = parseInt(addressParts[1]) || 443;
        }
        
        let nodeName = address;
        if (countryCode) {
            const flag = getFlagEmoji(countryCode);
            nodeName = `${flag} ${countryName} ${address}:${port}`;
        } else if (countryName) {
            nodeName = `${countryName} ${address}:${port}`;
        } else if (port !== 443) {
            nodeName = `${address}:${port}`;
        }
        
        return `${header}://${yourUUID}@${address}:${port}?encryption=none&security=tls&sni=${url}&fp=chrome&type=ws&host=${url}&path=${encodedPath}#${encodeURIComponent(nodeName)}`;
    });
    
    return configs.join('\n').replace(new RegExp(header, 'g'), 'v' + 'l' + 'e' + 's' + 's');
}

async function getHomePage(request, env) {
    const url = request.headers.get('Host');
    const baseUrl = `https://${url}`;
    
    const storedPassword = await getPasswordFromKV(env);
    const storedUUID = await getUUIDFromKV(env);
    
    if (!storedPassword) {
        return getSetPasswordPage(url, baseUrl, false);
    }
    
    if (!storedUUID) {
        return getSetUUIDPage(url, baseUrl, storedPassword, false);
    }
    
    const urlObj = new URL(request.url);
    const providedPassword = urlObj.searchParams.get('password');
    
    if (providedPassword) {
        if (providedPassword === storedPassword) {
            return getMainPageContent(url, baseUrl, storedPassword, storedUUID);
        } else {
            return getLoginPage(url, baseUrl, true);
        }
    }
    
    return getLoginPage(url, baseUrl, false);
}

function getLoginPage(url, baseUrl, showError = false) {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service - 登录</title>
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-container: rgba(255, 255, 255, 0.95);
            --text-primary: #333;
            --text-secondary: #718096;
            --text-title: #2d3748;
            --input-bg: #fff;
            --input-border: #e2e8f0;
            --input-focus: #667eea;
            --button-bg: linear-gradient(45deg, #667eea, #764ba2);
            --button-hover: linear-gradient(45deg, #5a67d8, #6b46c1);
            --error-bg: #fed7d7;
            --error-border: #e53e3e;
            --error-text: #c53030;
            --link-color: #667eea;
            --link-hover: #5a67d8;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg-primary: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
                --bg-container: rgba(26, 32, 44, 0.95);
                --text-primary: #e2e8f0;
                --text-secondary: #a0aec0;
                --text-title: #f7fafc;
                --input-bg: #2d3748;
                --input-border: #4a5568;
                --input-focus: #63b3ed;
                --button-bg: linear-gradient(45deg, #4a5568, #2d3748);
                --button-hover: linear-gradient(45deg, #718096, #4a5568);
                --error-bg: #742a2a;
                --error-border: #e53e3e;
                --error-text: #fc8181;
                --link-color: #63b3ed;
                --link-hover: #4299e1;
            }
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-primary);
            margin: 0;
            padding: 0;
            overflow: hidden;
        }
        
        .login-container {
            background: var(--bg-container);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 400px;
            width: 95%;
            text-align: center;
        }
        
        .logo {
            font-size: 3rem;
            margin-bottom: 20px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .title {
            font-size: 1.8rem;
            margin-bottom: 8px;
            color: var(--text-title);
            text-align: center;
        }
        
        .subtitle {
            color: var(--text-secondary);
            margin-bottom: 30px;
            font-size: 1rem;
            text-align: center;
        }
        
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--text-secondary);
        }
        
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid var(--input-border);
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
            background: var(--input-bg);
            color: var(--text-primary);
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--input-focus);
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn-login {
            width: 100%;
            padding: 12px 20px;
            background: var(--button-bg);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .btn-login:hover {
            background: var(--button-hover);
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .error-message {
            background: var(--error-bg);
            color: var(--error-text);
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid var(--error-border);
        }
        
        .footer {
            margin-top: 20px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-align: center;
        }
        
        .change-password-link {
            margin-top: 15px;
            text-align: center;
        }
        
        .change-password-link a {
            color: var(--link-color);
            text-decoration: none;
            font-size: 0.9rem;
            transition: color 0.3s ease;
        }
        
        .change-password-link a:hover {
            color: var(--link-hover);
            text-decoration: underline;
        }
        
        @media (max-width: 480px) {
            .login-container {
                padding: 30px 20px;
                margin: 10px;
            }
            
            .logo {
                font-size: 2.5rem;
            }
            
            .title {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🔐</div>
        <h1 class="title">Workers Service</h1>
        <p class="subtitle">请输入密码以访问服务</p>
        
        ${showError ? '<div class="error-message">密码错误，请重试</div>' : ''}
        
        <form onsubmit="handleLogin(event)">
            <div class="form-group">
                <label for="password" class="form-label">密码</label>
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    class="form-input" 
                    placeholder="请输入密码"
                    required
                    autofocus
                >
            </div>
            <button type="submit" class="btn-login">登录</button>
        </form>
        
        <div class="change-password-link">
            <a href="/change-password">修改密码</a>
        </div>
        
        <div class="footer">
            <p> © 2025 | 基于 Cloudflare Workers 的高性能网络服务</p>
        </div>
    </div>
    
    <script>
        function handleLogin(event) {
            event.preventDefault();
            const password = document.getElementById('password').value;
            const currentUrl = new URL(window.location);
            currentUrl.searchParams.set('password', password);
            window.location.href = currentUrl.toString();
        }
    </script>
</body>
</html>`;

    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    });
}

function getSetPasswordPage(url, baseUrl, showError = false) {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service - 设置密码</title>
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, '764ba2' 100%);
            --bg-container: rgba(255, 255, 255, 0.95);
            --text-primary: #333;
            --text-secondary: #718096;
            --text-title: #2d3748;
            --input-bg: #fff;
            --input-border: #e2e8f0;
            --input-focus: #667eea;
            --button-bg: linear-gradient(45deg, #667eea, #764ba2);
            --button-hover: linear-gradient(45deg, #5a67d8, #6b46c1);
            --error-bg: #fed7d7;
            --error-border: #e53e3e;
            --error-text: #c53030;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg-primary: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
                --bg-container: rgba(26, 32, 44, 0.95);
                --text-primary: #e2e8f0;
                --text-secondary: #a0aec0;
                --text-title: #f7fafc;
                --input-bg: #2d3748;
                --input-border: #4a5568;
                --input-focus: #63b3ed;
                --button-bg: linear-gradient(45deg, #4a5568, #2d3748);
                --button-hover: linear-gradient(45deg, #718096, #4a5568);
                --error-bg: #742a2a;
                --error-border: #e53e3e;
                --error-text: #fc8181;
            }
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-primary);
            margin: 0;
            padding: 0;
            overflow: hidden;
        }
        
        .login-container {
            background: var(--bg-container);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 400px;
            width: 95%;
            text-align: center;
        }
        
        .logo {
            font-size: 3rem;
            margin-bottom: 20px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .title {
            font-size: 1.8rem;
            margin-bottom: 8px;
            color: var(--text-title);
            text-align: center;
        }
        
        .subtitle {
            color: var(--text-secondary);
            margin-bottom: 30px;
            font-size: 1rem;
            text-align: center;
        }
        
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: 'text-secondary';
        }
        
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid var(--input-border);
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
            background: var(--input-bg);
            color: var(--text-primary);
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--input-focus);
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn-login {
            width: 100%;
            padding: 12px 20px;
            background: var(--button-bg);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .btn-login:hover {
            background: var(--button-hover);
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .error-message {
            background: var(--error-bg);
            color: var(--error-text);
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid var(--error-border);
        }
        
        .footer {
            margin-top: 20px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-align: center;
        }
        
        @media (max-width: 480px) {
            .login-container {
                padding: 30px 20px;
                margin: 10px;
            }
            
            .logo {
                font-size: 2.5rem;
            }
            
            .title {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🔐</div>
        <h1 class="title">Workers Service</h1>
        <p class="subtitle">首次使用，请设置管理员密码</p>
        
        ${showError ? '<div class="error-message">密码不能为空，请设置密码</div>' : ''}
        
        <form action="/set-password" method="post">
            <div class="form-group">
                <label for="password" class="form-label">设置密码</label>
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    class="form-input" 
                    placeholder="请设置管理员密码"
                    required
                    autofocus
                >
            </div>
            <button type="submit" class="btn-login">设置密码</button>
        </form>
        
        <div class="footer">
            <p> © 2025 | 基于 Cloudflare Workers 的高性能网络服务</p>
        </div>
    </div>
</body>
</html>`;

    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    });
}

function getSetUUIDPage(url, baseUrl, password, showError = false) {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service - 设置UUID</title>
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-container: rgba(255, 255, 255, 0.95);
            --text-primary: #333;
            --text-secondary: #718096;
            --text-title: #2d3748;
            --input-bg: #fff;
            --input-border: #e2e8f0;
            --input-focus: #667eea;
            --button-bg: linear-gradient(45deg, #667eea, #764ba2);
            --button-hover: linear-gradient(45deg, #5a67d8, #6b46c1);
            --error-bg: #fed7d7;
            --error-border: #e53e3e;
            --error-text: #c53030;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg-primary: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
                --bg-container: rgba(26, 32, 44, 0.95);
                --text-primary: #e2e8f0;
                --text-secondary: #a0aec0;
                --text-title: #f7fafc;
                --input-bg: '2d3748';
                --input-border: #4a5568;
                --input-focus: #63b3ed;
                --button-bg: linear-gradient(45deg, #4a5568, #2d3748);
                --button-hover: linear-gradient(45deg, #718096, #4a5568);
                --error-bg: #742a2a;
                --error-border: #e53e3e;
                --error-text: #fc8181;
            }
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-primary);
            margin: 0;
            padding: 0;
            overflow: hidden;
        }
        
        .login-container {
            background: var(--bg-container);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 500px;
            width: 95%;
            text-align: center;
        }
        
        .logo {
            font-size: 3rem;
            margin-bottom: 20px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .title {
            font-size: 1.8rem;
            margin-bottom: 8px;
            color: var(--text-title);
            text-align: center;
        }
        
        .subtitle {
            color: var(--text-secondary);
            margin-bottom: 30px;
            font-size: 1rem;
            text-align: center;
        }
        
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--text-secondary);
        }
        
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid var(--input-border);
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
            background: var(--input-bg);
            color: var(--text-primary);
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--input-focus);
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn-login {
            width: 100%;
            padding: 12px 20px;
            background: var(--button-bg);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .btn-login:hover {
            background: var(--button-hover);
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .btn-generate {
            width: 100%;
            padding: 8px 16px;
            background: var(--button-bg);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            margin-bottom: 15px;
            transition: all 0.3s ease;
        }
        
        .btn-generate:hover {
            background: var(--button-hover);
        }
        
        .error-message {
            background: var(--error-bg);
            color: var(--error-text);
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid var(--error-border);
        }
        
        .footer {
            margin-top: 20px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-align: center;
        }
        
        @media (max-width: 480px) {
            .login-container {
                padding: 30px 20px;
                margin: 10px;
            }
            
            .logo {
                font-size: 2.5rem;
            }
            
            .title {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🔑</div>
        <h1 class="title">Workers Service</h1>
        <p class="subtitle">首次使用，请设置UUID</p>
        
        ${showError ? '<div class="error-message">UUID格式不正确，请使用有效的UUID格式</div>' : ''}
        
        <button class="btn-generate" onclick="generateUUID()">生成随机UUID</button>
        
        <form action="/set-uuid?password=${password}" method="post">
            <div class="form-group">
                <label for="uuid" class="form-label">设置UUID</label>
                <input 
                    type="text" 
                    id="uuid" 
                    name="uuid" 
                    class="form-input" 
                    placeholder="请输入UUID或点击上方按钮生成"
                    required
                    pattern="[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
                    title="请输入有效的UUID格式"
                    autofocus
                >
            </div>
            <button type="submit" class="btn-login">设置UUID</button>
        </form>
        
        <div class="footer">
            <p> © 2025 | 基于 Cloudflare Workers 的高性能网络服务</p>
        </div>
    </div>
    
    <script>
        function generateUUID() {
            const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
            document.getElementById('uuid').value = uuid;
        }
        
        window.onload = function() {
            generateUUID();
        };
    </script>
</body>
</html>`;

    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    });
}

async function handleSetPassword(request, env) {
    const url = request.headers.get('Host');
    const baseUrl = `https://${url}`;
    
    if (request.method !== 'POST') {
        return Response.redirect(baseUrl, 302);
    }
    
    const formData = await request.formData();
    const newPassword = formData.get('password');
    
    if (!newPassword) {
        return getSetPasswordPage(url, baseUrl, true);
    }
    
    const success = await setPasswordToKV(env, newPassword);
    
    if (success) {
        return Response.redirect(`${baseUrl}/set-uuid?password=${newPassword}`, 302);
    } else {
        return new Response('设置密码失败', { status: 500 });
    }
}

async function handleSetUUID(request, env) {
    const url = request.headers.get('Host');
    const baseUrl = `https://${url}`;
    
    if (request.method !== 'POST') {
        const urlObj = new URL(request.url);
        const providedPassword = urlObj.searchParams.get('password');
        
        if (!providedPassword) {
            return Response.redirect(baseUrl, 302);
        }
        
        return getSetUUIDPage(url, baseUrl, providedPassword, false);
    }
    
    const urlObj = new URL(request.url);
    const providedPassword = urlObj.searchParams.get('password');
    
    if (!providedPassword) {
        return Response.redirect(baseUrl, 302);
    }
    
    const storedPassword = await getPasswordFromKV(env);
    if (providedPassword !== storedPassword) {
        return new Response('Unauthorized', { status: 401 });
    }
    
    const formData = await request.formData();
    const newUUID = formData.get('uuid');
    
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(newUUID)) {
        return getSetUUIDPage(url, baseUrl, providedPassword, true);
    }
    
    const success = await setUUIDToKV(env, newUUID);
    
    if (success) {
        yourUUID = newUUID;
        return Response.redirect(`${baseUrl}/?password=${providedPassword}`, 302);
    } else {
        return new Response('设置UUID失败', { status: 500 });
    }
}

function getChangePasswordPage(url, baseUrl, showError = false, errorMessage = '') {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service - 修改密码</title>
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-container: rgba(255, 255, 255, 0.95);
            --text-primary: #333;
            --text-secondary: #718096;
            --text-title: #2d3748;
            --input-bg: #fff;
            --input-border: #e2e8f0;
            --input-focus: #667eea;
            --button-bg: linear-gradient(45deg, #667eea, #764ba2);
            --button-hover: linear-gradient(45deg, #5a67d8, #6b46c1);
            --error-bg: #fed7d7;
            --error-border: #e53e3e;
            --error-text: #c53030;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg-primary: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
                --bg-container: rgba(26, 32, 44, 0.95);
                --text-primary: #e2e8f0;
                --text-secondary: #a0aec0;
                --text-title: #f7fafc;
                --input-bg: #2d3748;
                --input-border: #4a5568;
                --input-focus: #63b3ed;
                --button-bg: linear-gradient(45deg, #4a5568, #2d3748);
                --button-hover: linear-gradient(45deg, #718096, #4a5568);
                --error-bg: #742a2a;
                --error-border: #e53e3e;
                --error-text: 'fc8181';
            }
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-primary);
            margin: 0;
            padding: 0;
            overflow: hidden;
        }
        
        .login-container {
            background: var(--bg-container);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 400px;
            width: 95%;
            text-align: center;
        }
        
        .logo {
            font-size: 3rem;
            margin-bottom: 20px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .title {
            font-size: 1.8rem;
            margin-bottom: 8px;
            color: var(--text-title);
            text-align: center;
        }
        
        .subtitle {
            color: var(--text-secondary);
            margin-bottom: 30px;
            font-size: 1rem;
            text-align: center;
        }
        
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--text-secondary);
        }
        
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid var(--input-border);
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
            background: var(--input-bg);
            color: var(--text-primary);
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--input-focus);
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn-login {
            width: 100%;
            padding: 12px 20px;
            background: var(--button-bg);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .btn-login:hover {
            background: var(--button-hover);
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .error-message {
            background: var(--error-bg);
            color: var(--error-text);
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid var(--error-border);
        }
        
        .footer {
            margin-top: 20px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-align: center;
        }
        
        .back-link {
            margin-top: 15px;
            text-align: center;
        }
        
        .back-link a {
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.9rem;
        }
        
        .back-link a:hover {
            text-decoration: underline;
        }
        
        @media (max-width: 480px) {
            .login-container {
                padding: 30px 20px;
                margin: 10px;
            }
            
            .logo {
                font-size: 2.5rem;
            }
            
            .title {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🔐</div>
        <h1 class="title">修改密码</h1>
        <p class="subtitle">请输入当前密码和新密码</p>
        
        ${showError ? `<div class="error-message">${errorMessage}</div>` : ''}
        
        <form action="/change-password" method="post">
            <div class="form-group">
                <label for="current_password" class="form-label">当前密码</label>
                <input 
                    type="password" 
                    id="current_password" 
                    name="current_password" 
                    class="form-input" 
                    placeholder="请输入当前密码"
                    required
                    autofocus
                >
            </div>
            
            <div class="form-group">
                <label for="new_password" class="form-label">新密码</label>
                <input 
                    type="password" 
                    id="new_password" 
                    name="new_password" 
                    class="form-input" 
                    placeholder="请输入新密码"
                    required
                >
            </div>
            
            <div class="form-group">
                <label for="confirm_password" class="form-label">确认新密码</label>
                <input 
                    type="password" 
                    id="confirm_password" 
                    name="confirm_password" 
                    class="form-input" 
                    placeholder="请再次输入新密码"
                    required
                >
            </div>
            
            <button type="submit" class="btn-login">修改密码</button>
        </form>
        
        <div class="back-link">
            <a href="/">返回登录页面</a>
        </div>
        
        <div class="footer">
            <p> © 2025 | 基于 Cloudflare Workers 的高性能网络服务</p>
        </div>
    </div>
    
    <script>
        document.querySelector('form').addEventListener('submit', function(e) {
            const newPassword = document.getElementById('new_password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            
            if (newPassword !== confirmPassword) {
                e.preventDefault();
                alert('新密码和确认密码不匹配');
            }
        });
    </script>
</body>
</html>`;

    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    });
}

async function handleChangePassword(request, env) {
    const url = request.headers.get('Host');
    const baseUrl = `https://${url}`;
    
    if (request.method === 'GET') {
        return getChangePasswordPage(url, baseUrl);
    }
    
    if (request.method === 'POST') {
        const formData = await request.formData();
        const currentPassword = formData.get('current_password');
        const newPassword = formData.get('new_password');
        const confirmPassword = formData.get('confirm_password');
        
        if (newPassword !== confirmPassword) {
            return getChangePasswordPage(url, baseUrl, true, '新密码和确认密码不匹配');
        }
        
        const storedPassword = await getPasswordFromKV(env);
        if (currentPassword !== storedPassword) {
            return getChangePasswordPage(url, baseUrl, true, '当前密码不正确');
        }
        
        const success = await setPasswordToKV(env, newPassword);
        
        if (success) {
            return Response.redirect(`${baseUrl}/?password=${newPassword}&message=密码修改成功`, 302);
        } else {
            return getChangePasswordPage(url, baseUrl, true, '密码修改失败');
        }
    }
    
    return new Response('Method not allowed', { status: 405 });
}

function getMainPageContent(url, baseUrl, currentPassword, currentUUID) {
    const urlObj = new URL(baseUrl);
    const message = urlObj.searchParams.get('message');
    
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-container: rgba(255, 255, 255, 0.95);
            --bg-card: #f7fafc;
            --bg-button: #edf2f7;
            --text-primary: #333;
            --text-secondary: #718096;
            --text-title: #2d3748;
            --text-button: #4a5568;
            --border-color: #e2e8f0;
            --input-bg: #fff;
            --input-border: #e2e8f0;
            --input-focus: #667eea;
            --button-primary-bg: linear-gradient(45deg, #667eea, #764ba2);
            --button-secondary-bg: #edf2f7;
            --button-secondary-border: #cbd5e0;
            --status-bg: #f0fff4;
            --status-border: #c6f6d5;
            --status-text: #22543d;
            --status-dot: #48bb78;
            --toast-bg: #f0fff4;
            --toast-border: #48bb78;
            --toast-text: #2d3748;
            --toast-icon: #48bb78;
            --success-bg: #c6f6d5;
            --success-border: #38a169;
            --success-text: #22543d;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg-primary: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
                --bg-container: rgba(26, 32, 44, 0.95);
                --bg-card: #2d3748;
                --bg-button: #4a5568;
                --text-primary: #e2e8f0;
                --text-secondary: #a0aec0;
                --text-title: #f7fafc;
                --text-button: #e2e8f0;
                --border-color: #4a5568;
                --input-bg: #2d3748;
                --input-border: #4a5568;
                --input-focus: #63b3ed;
                --button-primary-bg: linear-gradient(45deg, #4a5568, #2d3748);
                --button-secondary-bg: #4a5568;
                --button-secondary-border: #718096;
                --status-bg: #22543d;
                --status-border: #2f855a;
                --status-text: #c6f6d5;
                --status-dot: #68d391;
                --toast-bg: #22543d;
                --toast-border: #38a169;
                --toast-text: #f0fff4;
                --toast-icon: #9ae6b4;
                --success-bg: #22543d;
                --success-border: #38a169;
                --success-text: #c6f6d5;
            }
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
            overflow-x: hidden;
        }
        
        .container {
            background: var(--bg-container);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 25px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 1000px;
            width: 100%;
            max-height: 90vh;
            text-align: center;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            position: relative;
        }
        
        .admin-btn, .logout-btn {
            position: absolute;
            background: var(--bg-button);
            border: none;
            border-radius: 8px;
            padding: 10px 16px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            z-index: 10;
            text-decoration: none;
            color: var(--text-button);
        }
        
        .admin-btn {
            top: 20px;
            left: 20px;
            color: var(--text-button);
        }
        
        .logout-btn {
            top: 20px;
            right: 20px;
            color: var(--text-button);
        }
        
        .logout-btn i, .admin-btn i {
            font-size: 0.9rem;
        }
        
        .logout-btn:hover, .admin-btn:hover {
            background: var(--bg-button);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        
        .logo {
            font-size: 2.5rem;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .title {
            font-size: 1.8rem;
            margin-bottom: 8px;
            color: var(--text-title);
            text-align: center;
        }
        
        .subtitle {
            color: var(--text-secondary);
            margin-bottom: 15px;
            font-size: 1rem;
            text-align: center;
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 25px;
            background: var(--status-bg);
            color: var(--status-text);
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: 600;
            border: 1px solid var(--status-border);
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        
        .status-dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--status-dot);
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        
        .success-message {
            background: var(--success-bg);
            color: var(--success-text);
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid var(--success-border);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .cards-container {
            display: flex;
            gap: 20px;
            margin-bottom: 25px;
            flex-wrap: wrap;
            justify-content: center;
        }
        
        .card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 20px;
            flex: 1;
            min-width: 300px;
            text-align: left;
            display: flex;
            flex-direction: column;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
            position: relative;
        }
        
        .card-title {
            font-size: 1.2rem;
            margin-bottom: 15px;
            color: var(--text-title);
            display: flex;
            align-items: center;
            gap: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
        }
        
        .card-title i {
            color: #667eea;
            transition: transform 0.3s ease;
            font-size: 1.1rem;
        }
        
        .card-content {
            display: none;
            padding-top: 10px;
        }
        
        .card-content.show {
            display: block;
            color: var(--text-primary);
        }
        
        .info-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9rem;
        }
        
        .info-item:last-child {
            border-bottom: none;
            justify-content: center;
            margin-top: auto;
            padding-top: 15px;
        }
        
        .label {
            font-weight: 600;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .value {
            color: var(--text-primary);
            font-family: 'Courier New', monospace;
            background: var(--bg-button);
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 0.85rem;
            word-break: break-all;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .copy-btn {
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 4px 8px;
            font-size: 0.75rem;
            cursor: pointer;
            margin-left: 8px;
            transition: all 0.2s ease;
        }
        
        .copy-btn:hover {
            background: #5a67d8;
        }
        
        .button-group {
            display: flex;
            gap: 12px;
            justify-content: center;
            flex-wrap: wrap;
            margin: 20px 0;
        }
        
        .btn {
            padding: 12px 20px;
            border: none;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
            min-width: 120px;
            gap: 8px;
        }
        
        .btn-primary {
            background: var(--button-primary-bg);
            color: white;
        }
        
        .btn-secondary {
            background: var(--button-secondary-bg);
            color: var(--text-button);
            border: 1px solid var(--button-secondary-border);
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .footer {
            margin-top: 15px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 8px;
        }
        
        .toast {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--toast-bg);
            border-left: 4px solid var(--toast-border);
            border-radius: 8px;
            padding: 12px 16px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            display: flex;
            align-items: center;
            gap: 10px;
            z-index: 1000;
            opacity: 0;
            transform: translateX(100%);
            transition: all 0.3s ease;
            max-width: 300px;
            color: var(--toast-text);
        }
        
        .toast.show {
            opacity: 1;
            transform: translateX(0);
        }
        
        .toast-icon {
            width: 20px;
            height: 20px;
            background: var(--toast-icon);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 12px;
            font-weight: bold;
        }
        
        .toast-message {
            font-size: 14px;
            font-weight: 500;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 20px;
                margin: 10px;
                max-height: 95vh;
            }
            
            .logout-btn, .admin-btn {
                top: 15px;
                padding: 8px 12px;
                font-size: 0.8rem;
            }
            
            .logout-btn {
                right: 15px;
            }
            
            .admin-btn {
                left: 15px;
            }
            
            .logo {
                font-size: 2rem;
            }
            
            .title {
                font-size: 1.5rem;
            }
            
            .cards-container {
                flex-direction: column;
            }
            
            .card {
                min-width: 100%;
            }
            
            .button-group {
                flex-direction: column;
                align-items: center;
                gap: 10px;
            }
            
            .btn {
                width: 100%;
                max-width: 220px;
                padding: 10px 16px;
                font-size: 0.85rem;
            }
            
            .info-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 5px;
            }
            
            .value {
                width: 100%;
                font-size: 0.8rem;
                max-width: none;
            }
        }
        
        @media (max-width: 480px) {
            body {
                padding: 10px;
            }
            
            .container {
                padding: 15px;
            }
            
            .card {
                padding: 15px;
            }
            
            .toast {
                top: 10px;
                right: 10px;
                left: 10px;
                max-width: none;
                transform: translateY(-100%);
            }
            
            .toast.show {
                transform: translateY(0);
            }
        }
        
        @media (max-height: 700px) {
            .container {
                max-height: 95vh;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <button onclick="logout()" class="logout-btn">
            <i class="fas fa-sign-out-alt"></i>
            <span>退出登录</span>
        </button>
        
        <a href="/admin?password=${currentPassword}" class="admin-btn">
            <i class="fas fa-cog"></i>
            <span>配置管理</span>
        </a>
        
        <div class="logo">🚀</div>
        <h1 class="title">Workers Service</h1>
        <p class="subtitle">基于 Cloudflare Workers 的高性能网络服务</p>
        
        ${message ? `
        <div class="success-message">
            <i class="fas fa-check-circle"></i>
            <span>${message}</span>
        </div>
        ` : ''}
        
        <div class="status-indicator">
            <span class="status-dot"></span>
            <span class="status-text">服务运行中</span>
        </div>
        
        <div class="cards-container">
            <div class="card">
                <div class="card-title" onclick="toggleCardContent('server-info')">
                    <i class="fas fa-server"></i>
                    <span>服务器信息</span>
                    <i class="fas fa-chevron-down" style="margin-left: auto; transition: transform 0.3s;" id="server-info-chevron"></i>
                </div>
                
                <div class="card-content" id="server-info-content">
                    <div class="info-item">
                        <span class="label"><i class="fas fa-globe"></i>主机地址</span>
                        <span class="value">${url}</span>
                    </div>
                    
                    <div class="info-item">
                        <span class="label"><i class="fas fa-key"></i>UUID</span>
                        <span class="value">${currentUUID}</span>
                        <button class="copy-btn" onclick="copyToClipboard('${currentUUID}', 'UUID')">复制</button>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title" onclick="toggleCardContent('subscription-info')">
                    <i class="fas fa-link"></i>
                    <span>订阅信息</span>
                    <i class="fas fa-chevron-down" style="margin-left: auto; transition: transform 0.3s;" id="subscription-info-chevron"></i>
                </div>
                
                <div class="card-content" id="subscription-info-content">
                    <div class="info-item">
                        <span class="label"><i class="fas fa-code"></i>Base64订阅</span>
                        <span class="value">${baseUrl}/${currentUUID || 'link'}</span>
                        <button class="copy-btn" onclick="copyToClipboard('${baseUrl}/${currentUUID || 'link'}', 'Base64订阅链接')">复制</button>
                    </div>
                    
                    <div class="info-item">
                        <span class="label"><i class="fab fa-react"></i>Clash订阅</span>
                        <span class="value">https://sublink.eooce.com/clash?config=${baseUrl}/${currentUUID || 'link'}</span>
                        <button class="copy-btn" onclick="copyToClipboard('https://sublink.eooce.com/clash?config=${baseUrl}/${currentUUID || 'link'}', 'Clash订阅链接')">复制</button>
                    </div>
                    
                    <div class="info-item">
                        <span class="label"><i class="fas fa-box"></i>Singbox订阅</span>
                        <span class="value">https://sublink.eooce.com/singbox?config=${baseUrl}/${currentUUID || 'link'}</span>
                        <button class="copy-btn" onclick="copyToClipboard('https://sublink.eooce.com/singbox?config=${baseUrl}/${currentUUID || 'link'}', 'Singbox订阅链接')">复制</button>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="button-group">
            <button onclick="copySingboxSubscription()" class="btn btn-secondary">
                <i class="fas fa-box"></i>
                <span>Singbox订阅</span>
            </button>
            <button onclick="copyClashSubscription()" class="btn btn-secondary">
                <i class="fab fa-react"></i>
                <span>Clash订阅</span>
            </button>
            <button onclick="copySubscription()" class="btn btn-secondary">
                <i class="fas fa-code"></i>
                <span>Base64订阅</span>
            </button>
            
            <a href="/admin?password=${currentPassword}" class="btn btn-primary">
                <i class="fas fa-cog"></i>
                <span>管理优选IP和反代IP</span>
            </a>
        </div>
        
        <div class="footer">
            <p>© 2025 | 基于 Cloudflare Workers 的高性能网络服务&Powered By Leeshen </p>
        </div>
    </div>
    
    <script>
        function toggleCardContent(cardId) {
            const content = document.getElementById(cardId + '-content');
            const chevron = document.getElementById(cardId + '-chevron');
            
            if (content.classList.contains('show')) {
                content.classList.remove('show');
                chevron.style.transform = 'rotate(0deg)';
            } else {
                content.classList.add('show');
                chevron.style.transform = 'rotate(180deg)';
            }
        }
        
        function showToast(message) {
            const existingToast = document.querySelector('.toast');
            if (existingToast) {
                existingToast.remove();
            }
            
            const toast = document.createElement('div');
            toast.className = 'toast';
            
            const icon = document.createElement('div');
            icon.className = 'toast-icon';
            icon.textContent = '✓';
            
            const messageDiv = document.createElement('div');
            messageDiv.className = 'toast-message';
            messageDiv.textContent = message;
            
            toast.appendChild(icon);
            toast.appendChild(messageDiv);
            
            document.body.appendChild(toast);
            
            setTimeout(() => {
                toast.classList.add('show');
            }, 10);
            
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => {
                    if (toast.parentNode) {
                        toast.parentNode.removeChild(toast);
                    }
                }, 300);
            }, 1500);
        }
        
        function copyToClipboard(text, description) {
            navigator.clipboard.writeText(text).then(() => {
                showToast(description + '已复制到剪贴板！');
            }).catch(() => {
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showToast(description + '已复制到剪贴板！');
            });
        }
        
        function copySubscription() {
            const configUrl = '${baseUrl}/${currentUUID || 'link'}';
            copyToClipboard(configUrl, 'Base64订阅链接');
        }
        
        function copyClashSubscription() {
            const clashUrl = 'https://sublink.eooce.com/clash?config=${baseUrl}/${currentUUID || 'link'}';
            copyToClipboard(clashUrl, 'Clash订阅链接');
        }
        
        function copySingboxSubscription() {
            const singboxUrl = 'https://sublink.eooce.com/singbox?config=${baseUrl}/${currentUUID || 'link'}';
            copyToClipboard(singboxUrl, 'Singbox订阅链接');
        }
        
        function logout() {
            if (confirm('确定要退出登录吗？')) {
                const currentUrl = new URL(window.location);
                currentUrl.searchParams.delete('password');
                window.location.href = currentUrl.toString();
            }
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            const serverChevron = document.getElementById('server-info-chevron');
            const subscriptionChevron = document.getElementById('subscription-info-chevron');
            
            serverChevron.style.transform = 'rotate(0deg)';
            subscriptionChevron.style.transform = 'rotate(0deg)';
        });
    </script>
</body>
</html> `;

    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    });
}

function getSubscription(request) {
    const url = request.headers.get('Host');
    
    const VLUrl = getVLConfig(yourUUID, url);
    const content = btoa(VLUrl);
    
    return new Response(content, {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    });
}

async function handleAdminSave(request, env) {
    try {
        const url = new URL(request.url);
        const providedPassword = url.searchParams.get('password');
        
        const storedPassword = await getPasswordFromKV(env);
        if (providedPassword !== storedPassword) {
            return new Response('Unauthorized', { status: 401 });
        }
        
        const formData = await request.formData();
        const cfipList = formData.get('cfip') || '';
        const fdipList = formData.get('fdip') || '';
        const uuid = formData.get('uuid') || null;
        
        if (uuid) {
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(uuid)) {
                return new Response('UUID格式不正确', { status: 400 });
            }
        }
        
        const cfipArray = cfipList.split('\n')
            .map(item => item.trim())
            .filter(item => item !== '');
            
        const fdipArray = fdipList.split('\n')
            .map(item => item.trim())
            .filter(item => item !== '');
        
        const success = await saveConfigToKV(env, cfipArray, fdipArray, uuid);
        
        if (success) {
            cfip = cfipArray;
            serverPool = fdipArray;
            if (uuid) {
                yourUUID = uuid;
            }
            
            return Response.redirect(`${url.origin}/admin?password=${providedPassword}&saved=true`, 302);
        } else {
            return new Response('保存配置失败', { status: 500 });
        }
    } catch (error) {
        console.error('保存配置错误:', error);
        return new Response('保存配置时发生错误', { status: 500 });
    }
}

async function getAdminPage(request, env) {
    const url = new URL(request.url);
    const providedPassword = url.searchParams.get('password');
    const saved = url.searchParams.get('saved');
    
    const storedPassword = await getPasswordFromKV(env);
    if (providedPassword !== storedPassword) {
        return new Response('Unauthorized', { status: 401 });
    }
    
    await loadConfigFromKV(env);
    
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service - 配置管理</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-container: rgba(255, 255, 255, 0.95);
            --bg-card: #f7fafc;
            --text-primary: #333;
            --text-secondary: #718096;
            --text-title: #2d3748;
            --border-color: #e2e8f0;
            --input-bg: #fff;
            --input-border: #e2e8f0;
            --input-focus: #667eea;
            --button-bg: linear-gradient(45deg, #667eea, #764ba2);
            --button-hover: linear-gradient(45deg, #5a67d8, #6b46c1);
            --success-bg: #c6f6d5;
            --success-border: #38a169;
            --success-text: #22543d;
            --generate-btn-bg: #ed8936;
            --generate-btn-hover: #dd6b20;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg-primary: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
                --bg-container: rgba(26, 32, 44, 0.95);
                --bg-card: #2d3748;
                --text-primary: #e2e8f0;
                --text-secondary: #a0aec0;
                --text-title: #f7fafc;
                --border-color: #4a5568;
                --input-bg: #2d3748;
                --input-border: #4a5568;
                --input-focus: #63b3ed;
                --button-bg: linear-gradient(45deg, #4a5568, #2d3748);
                --button-hover: linear-gradient(45deg, #718096, #4a5568);
                --success-bg: #22543d;
                --success-border: #38a169;
                --success-text: #c6f6d5;
                --generate-btn-bg: #ed8936;
                --generate-btn-hover: #dd6b20;
            }
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            min-height: 100vh;
            padding: 20px;
            color: var(--text-primary);
        }
        
        .admin-container {
            background: var(--bg-container);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 1000px;
            margin: 0 auto;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border-color);
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .title {
            font-size: 2rem;
            color: var(--text-title);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .back-btn {
            background: var(--bg-card);
            color: var(--text-secondary);
            border: none;
            border-radius: 8px;
            padding: 10px 16px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            text-decoration: none;
        }
        
        .back-btn:hover {
            background: var(--bg-card);
            transform: translateY(-1px);
        }
        
        .config-section {
            margin-bottom: 30px;
        }
        
        .section-title {
            font-size: 1.5rem;
            margin-bottom: 15px;
            color: var(--text-title);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--text-secondary);
        }
        
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid var(--input-border);
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
            background: var(--input-bg);
            color: var(--text-primary);
        }
        
        .form-textarea {
            width: 100%;
            min-height: 150px;
            padding: 12px 16px;
            border: 2px solid var(--input-border);
            border-radius: 8px;
            font-size: 1rem;
            font-family: monospace;
            transition: border-color 0.3s ease;
            background: var(--input-bg);
            color: var(--text-primary);
            resize: vertical;
        }
        
        .form-textarea:focus {
            outline: none;
            border-color: var(--input-focus);
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .form-help {
            margin-top: 6px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        .btn-save {
            padding: 12px 24px;
            background: var(--button-bg);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-save:hover {
            background: var(--button-hover);
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .btn-generate {
            padding: 8px 16px;
            background: var(--generate-btn-bg);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            margin-left: 10px;
            transition: all 0.3s ease;
        }
        
        .btn-generate:hover {
            background: var(--generate-btn-hover);
        }
        
        .success-message {
            background: var(--success-bg);
            color: var(--success-text);
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid var(--success-border);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .info-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 30px;
        }
        
        .info-title {
            font-weight: 600;
            color: var(--text-title);
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .info-content {
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .info-list {
            margin-top: 10px;
            padding-left: 20px;
        }
        
        .info-list li {
            margin-bottom: 6px;
            color: var(--text-primary);
        }
        
        @media (max-width: 768px) {
            .admin-container {
                padding: 20px;
            }
            
            .title {
                font-size: 1.5rem;
            }
            
            .section-title {
                font-size: 1.3rem;
            }
            
            .header {
                flex-direction: column;
                align-items: flex-start;
                gap: 15px;
            }
            
            .back-btn {
                align-self: flex-start;
            }
        }
        
        @media (max-width: 480px) {
            body {
                padding: 10px;
            }
            
            .admin-container {
                padding: 15px;
            }
            
            .title {
                font-size: 1.3rem;
            }
        }
    </style>
</head>
<body>
    <div class="admin-container">
        <div class="header">
            <h1 class="title"><i class="fas fa-cog"></i> Workers Service 配置管理</h1>
            <a href="/?password=${providedPassword}" class="back-btn">
                <i class="fas fa-arrow-left"></i>
                <span>返回主页</span>
            </a>
        </div>
        
        ${saved ? `
        <div class="success-message">
            <i class="fas fa-check-circle"></i>
            <span>配置已成功保存！</span>
        </div>
        ` : ''}
        
        <div class="info-card">
            <div class="info-title">
                <i class="fas fa-info-circle"></i>
                <span>配置说明</span>
            </div>
            <div class="info-content">
                <p>在此页面您可以自定义优选IP、反代IP和UUID配置：</p>
                <ul class="info-list">
                    <li><strong>优选IP/域名</strong>：用于Web界面伪装和订阅生成的IP或域名列表，每行一个</li>
                    <li><strong>反代IP/域名</strong>：用于实际代理连接的服务器IP或域名列表，每行一个</li>
                    <li><strong>UUID</strong>：用于客户端连接的唯一标识符，必须符合UUID格式</li>
                </ul>
                <p>配置将保存到Cloudflare KV存储中，并立即生效。</p>
            </div>
        </div>
        
        <form action="/admin/save?password=${providedPassword}" method="post">
            <div class="config-section">
                <h2 class="section-title"><i class="fas fa-cloud"></i> 优选IP/域名配置</h2>
                <div class="form-group">
                    <label for="cfip" class="form-label">优选IP/域名列表（每行一个）</label>
                    <textarea 
                        id="cfip" 
                        name="cfip" 
                        class="form-textarea" 
                        placeholder="请输入优选IP或域名，每行一个&#10;支持格式：&#10;example.com&#10;example.com:8443&#10;example.com#日本|JP&#10;example.com:8443#日本|JP"
                    >${cfip.join('\n')}</textarea>
                    <div class="form-help">这些IP/域名将用于Web界面伪装和订阅生成。支持自定义端口和国家信息，格式：IP:端口#国家名称|国家代码</div>
                </div>
            </div>
            
            <div class="config-section">
                <h2 class="section-title"><i class="fas fa-server"></i> 反代IP/域名配置</h2>
                <div class="form-group">
                    <label for="fdip" class="form-label">反代IP/域名列表（每行一个）</label>
                    <textarea 
                        id="fdip" 
                        name="fdip" 
                        class="form-textarea" 
                        placeholder="请输入反代IP或域名，每行一个&#10;例如：&#10;13.230.34.30&#10;54.199.216.103&#10;152.32.203.111"
                    >${serverPool.join('\n')}</textarea>
                    <div class="form-help">这些IP/域名将用于实际代理连接，支持格式：IP、域名、IP:端口、域名:端口</div>
                </div>
            </div>
            
            <div class="config-section">
                <h2 class="section-title"><i class="fas fa-key"></i> UUID配置</h2>
                <div class="form-group">
                    <label for="uuid" class="form-label">UUID</label>
                    <div style="display: flex; align-items: center;">
                        <input 
                            type="text" 
                            id="uuid" 
                            name="uuid" 
                            class="form-input" 
                            value="${yourUUID}"
                            placeholder="请输入UUID"
                            pattern="[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
                            title="请输入有效的UUID格式"
                            style="flex: 1;"
                        >
                        <button type="button" class="btn-generate" onclick="generateUUID()">
                            <i class="fas fa-sync-alt"></i>
                            <span>随机生成</span>
                        </button>
                    </div>
                    <div class="form-help">用于客户端连接的唯一标识符，必须符合UUID格式</div>
                </div>
            </div>
            
            <button type="submit" class="btn-save">
                <i class="fas fa-save"></i>
                <span>保存配置</span>
            </button>
        </form>
    </div>
    
    <script>
        function generateUUID() {
            const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
            document.getElementById('uuid').value = uuid;
        }
    </script>
</body>
</html>`;

    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    });
}
