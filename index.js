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
const filter = process.argv[3];
const clientRegExp = /^{"type":\s+"client".+}$/i;
const serverRegExp = /^<(\d{1,3})>\d (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\w+) (\d+) (\S+) (\[.+\]) (.+)$/i;
let lastTimestamp = '';
let stacktraceMessage = '';
let stacktraceFlag = false;
const parsedData = [];

const lr = lineReader.createInterface({
    input: fs.createReadStream(process.argv[2] || 'complex.log'),
    // output: process.stdout,
    // console: false
});

lr.on(event.line, parseLine);
lr.on(event.close, printoutResult);

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
            result = parseServer();
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

function parseServer() {
    let instance = getNewInstance();
    return instance;
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
    // here we can send parsed data to a stream or just push it into array
    if (filter) {
        if (data.type === filter) {
            parsedData.push(data);
        }
    } else {
        parsedData.push(data);
    }
}

function printoutResult() {
    if (stacktraceFlag) {
        finalizeStacktrace();
    }
    console.log('result:', parsedData);
}
