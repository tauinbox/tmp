const usage = "Usage: node index.js [logfile.log] [filter, e.g. ERROR]";

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
const emptyValue = '-';
const clientFields = {
    type: true, message: true, error: true, timestamp: true, environment: true, ip: true, app: true
};
const serverFields = {
    env: true, type: true
};
const filter = process.argv[3] ? process.argv[3].toUpperCase() : null;
const clientRegExp = /^{"type":\s+"client".*}$/;
const serverRegExp = /^<(\d{1,3})>(\d+) (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\w+) (\d+) (\S+) (\[.*]) (.*)$/;
const structuredDataRegExp = /\[(.*?)]/g;
const sdIdRegExp = /(.+)@[^\s]+/;
const sdParamsRegExp = /(\w+)="((\w|\s)*)"/g;
let lastTimestamp = '';
let stacktraceMessage = '';
let stacktraceFlag = false;

const stream = fs.createReadStream(process.argv[2] || 'complex.log');
stream.on('error', function(err){
    if(err.code === 'ENOENT'){
        console.log('File', `'${process.argv[2]}'`, 'was not found');
        console.log(usage);
    }else{
        console.error(err);
        console.log(usage);
    }
});

const lr = lineReader.createInterface({
    input: stream,
    // output: process.stdout,
    // console: false
});

lr.on(event.line, parseLine);
lr.on(event.close, finalize);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
    let prival, version, timestamp, host, app, pid, mid, structuredData, message, severity, parsed;
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

        instance.logsource = logsource.server;
        instance.program = app;
        instance.host = host;
        instance.timestamp = timestamp;
        instance.message = message;
        instance.type = getServerEventType(severity);
        lastTimestamp = timestamp;
        parsed = parseStructuredData(structuredData);
        if (parsed.mainFields && parsed.mainFields.env) {
            instance.env = parsed.mainFields.env;
        }
        if (parsed.data && Object.keys(parsed.data).length) {
            instance._data = parsed.data;
        }
        if (pid !== emptyValue) {
            instance._data = instance._data || {};
            instance._data.pid = pid;
        }
        if (mid !== emptyValue) {
            instance._data = instance._data || {};
            instance._data.mid = mid;
        }
    }

    return instance;
}

function parseStructuredData(structuredData) {
    let parsedSdData, item, parsed, mainFields;
    const data = [...structuredData.matchAll(structuredDataRegExp)];
    if (data.length < 2) {
        parsedSdData = {};
        item = data[0][1];
        if (item) {
            parsed = getSdParams(item);
            parsedSdData[parsed.sdKey] = parsed[parsed.sdKey];
            if (parsed.mainFields) {
                mainFields = parsed.mainFields;
            }
        }
    } else {
        parsedSdData = {};
        data.forEach(sdElement => {
            item = sdElement[1];
            parsed = getSdParams(item);
            parsedSdData[parsed.sdKey] = parsed[parsed.sdKey];
            if (parsed.mainFields) {
                mainFields = parsed.mainFields;
            }
        });
    }
    return { data: parsedSdData, mainFields: mainFields };
}

function getSdParams(sdElement) {
    let sdId, sdKey, sdData, parsedData;
    const sd = sdIdRegExp.exec(sdElement);
    if (sd) {
        sdId = sd[0];
        sdKey = sd[1];
        sdElement = sdElement.replace(sdId, '').trim();
        sdData = parseSdParams(sdElement);
        if (sdData) {
            parsedData = {
                sdKey: sdKey,
                mainFields: sdData.mainFields,
                [sdKey]: sdData.params
            };
        }
    }
    return parsedData;
}

function parseSdParams(sdParams) {
    let params, mainFields = null;
    const data = [...sdParams.matchAll(sdParamsRegExp)];
    if (data.length) {
        params = {};
        data.forEach(item => {
            if (serverFields[item[1]]) {
                mainFields = mainFields || {};
                mainFields[item[1]] = item[2];
            } else {
                params[item[1]] = item[2];
            }
        });
    }
    return { params: params, mainFields: mainFields };
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
