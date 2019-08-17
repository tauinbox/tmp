const fs = require('fs');
const lineReader = require('readline');

const event = {
    line: 'line',
    close: 'close'
};
const type = {
    info: 'INFO',
    error: 'ERROR'
};
const clientFields = {
    type: true, message: true, error: true, timestamp: true, environment: true, ip: true, app: true
};
const clientRegExp = /^{.+}$/i;
const parsedData = [];

const lr = lineReader.createInterface({
    input: fs.createReadStream(process.argv[2] || 'client.log'),
    // output: process.stdout,
    // console: false
});

lr.on(event.line, parseLine);
lr.on(event.close, printoutResult);

////////////////////////////////////////////////////////////////////
function parseLine(line) {
    // console.log('Line from file:', line);
    line = line.trim();
    if (isItClient(line)) {
        parsedData.push(parseClient(line));
    } else {
        parseServer(line);
    }
}

function isItClient(line) {
    return clientRegExp.test(line);
}

function parseClient(line) {
    let clientData, instance = getNewInstance();
    try {
        clientData = JSON.parse(line);
    } catch (e) {
        console.log('Unable to parse client data', e);
        return instance;
    }
    // console.log('clientData:', clientData);
    const isItInfo = clientData.hasOwnProperty('message');
    instance.logsource = 'client';
    isItInfo ? instance.type = type.info : instance.type = type.error;
    (clientData.message || clientData.error) && (instance.message = isItInfo ? clientData.message : clientData.error);
    clientData.app && (instance.program = clientData.app);
    clientData.ip && (instance.host = clientData.ip);
    clientData.environment && (instance.env = clientData.environment);
    clientData.timestamp && (instance.timestamp = new Date(clientData.timestamp).toISOString());
    instance._data = checkClientForAdvancedFields(clientData);

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

function parseServer() {

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

function printoutResult() {
    console.log('result:', parsedData);
}
