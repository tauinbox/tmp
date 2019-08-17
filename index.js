const fs = require('fs');
const args = process.argv;

const stream = new fs.ReadStream(args[2] || 'client.log');
const event = {
    readable: 'readable',
    open: 'open',
    end: 'end',
    close: 'close',
    error: 'error'
};

stream.on(event.readable, function () {
    const data = stream.read();
    if (data !== null) {
        console.log(data.toString());
    }
});

stream.on(event.end, function () {
    console.log("THE END");
});

stream.on(event.error, function (err) {
    if (err.code === 'ENOENT') {
        console.log("File not found");
    } else {
        console.error(err);
    }
});
