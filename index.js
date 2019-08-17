// Usage: node index.js [logfile.log] [filter, e.g. ERROR]

const fs = require('fs');
const lineReader = require('readline');

const event = {
    line: 'line',
    close: 'close'
};
const type = {
    info: 'INFO',
    error: 'ERROR',
    warning: 'WARNING',
    debug: 'DEBUG'
};
const logsource = {
    client: 'client',
    server: 'server'
};
const clientFields = {
    type: true, message: true, error: true, timestamp: true, environment: true, ip: true, app: true
};
const filter = process.argv[3] ? process.argv[3].toUpperCase() : null;
const clientRegExp = /^{"type":\s+"client".+}$/i;
const serverRegExp = /^<(\d{1,3})>(\d+) (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\w+) (\d+) (\S+) (\[.+\]) (.+)$/i;
let lastTimestamp = '';
let stacktraceMessage = '';
let stacktraceFlag = false;

const lr = lineReader.createInterface({
    input: fs.createReadStream(process.argv[2] || 'complex.log'),
    // output: process.stdout,
    // console: false
});

lr.on(event.line, parseLine);
lr.on(event.close, finalize);

////////////////////////////////////////////////////////////////////
function parseLine(line) {
    let result;
    line = line.trim();
    switch (true) {
        case isItClient(line):
            if (stacktraceFlag) {
                finalizeStacktrace();
            }
            result = parseClient(line);
            sendParsedData(result);
            break;
        case isItServer(line):
            if (stacktraceFlag) {
                finalizeStacktrace();
            }
            result = parseServer(line);
            sendParsedData(result);
            break;
        default:
            stacktraceFlag = true;
            stacktraceMessage = (stacktraceMessage ? stacktraceMessage + ' | ' : '') + line;
            break;
    }
}

function isItClient(line) {
    return clientRegExp.test(line);
}

function isItServer(line) {
    return serverRegExp.test(line);
}

function finalizeStacktrace() {
    stacktraceFlag = false;
    let instance = getNewInstance();
    instance.timestamp = lastTimestamp;
    instance.message = stacktraceMessage;
    instance.type = type.error;
    stacktraceMessage = '';
    sendParsedData(instance);
}

function parseClient(line) {
    let clientData, instance = getNewInstance();
    try {
        clientData = JSON.parse(line);
    } catch (e) {
        // console.log('Unable to parse client data', e);
        return instance;
    }
    const isItInfo = clientData.hasOwnProperty('message');
    instance.logsource = logsource.client;
    isItInfo ? instance.type = type.info : instance.type = type.error;
    (clientData.message || clientData.error) && (instance.message = isItInfo ? clientData.message : clientData.error);
    clientData.app && (instance.program = clientData.app);
    clientData.ip && (instance.host = clientData.ip);
    clientData.environment && (instance.env = clientData.environment);
    clientData.timestamp && (instance.timestamp = clientTimestamp(clientData.timestamp));
    instance._data = checkClientForAdvancedFields(clientData);

    return instance;
}

function parseServer(line) {
    let prival, version, timestamp, host, app, pid, mid, structuredData, message, severity;
    const serverData = serverRegExp.exec(line);
    let instance = getNewInstance();
    if (serverData.length) {
        prival = parseInt(serverData[1], 10);
        version = serverData[2];
        timestamp = serverData[3];
        host = serverData[4];
        app = serverData[5];
        pid = serverData[6];
        mid = serverData[7];
        structuredData = serverData[8];
        message = serverData[9];
        severity = prival & 7;
    }
    instance.logsource = logsource.server;
    instance.program = app;
    instance.host = host;
    instance.timestamp = timestamp;
    instance.message = message;
    instance.type = getServerEventType(severity);
    // console.log('>>> structured data:', structuredData);
    return instance;
}

function getServerEventType(severity) {
    switch (true) {
        case (severity >= 0 && severity <= 3):
            return type.error;
        case severity === 4:
            return type.warning;
        case (severity >= 5 && severity <= 6):
            return type.info;
        case severity === 7:
            return type.debug;
        default:
            return null;
    }
}

function checkClientForAdvancedFields(clientData) {
    let advancedFields = null;
    Object.keys(clientData).forEach(field => {
        if (!clientFields[field]) {
            advancedFields = advancedFields || {};
            advancedFields[field] = clientData[field];
        }
    });
    return advancedFields;
}

function clientTimestamp(timestamp) {
    timestamp = new Date(timestamp).toISOString();
    lastTimestamp = timestamp;
    return timestamp;
}

function getNewInstance() {
    return {
        logsource: '',
        program: '',
        host: '',
        env: '',
        type: '',
        timestamp: '',
        message: '',
        _data: null
    };
}

function sendParsedData(data) {
    if (filter) {
        if (data.type === filter) {
            console.log(data);
        }
    } else {
        console.log(data);
    }
}

function finalize() {
    if (stacktraceFlag) {
        finalizeStacktrace();
    }
}
