const express = require('express')
const https = require('https');
const http = require('http');
const fs = require('fs');
const bodyParser = require('body-parser')

const magicBits = {
    dood_magic: Buffer.from([0x16, 0x0d, 0xd0]),
    shuffled_magic: Buffer.from([0x16, 0x6a, 0xfe, 0x01]),
    secprofile_magic: Buffer.from([0x16, 0x6a, 0xfe, 0x02]),
    tlm_magic: Buffer.from([0x16, 0x6a, 0xfe, 0x03]),
    kontakt_magic: Buffer.from([0x16, 0x6a, 0xfe]),
    location_magic: Buffer.from([0x16, 0x6a, 0xfe, 0x05]),
}


const options = {
    key: fs.readFileSync('client-key.pem'),
    cert: fs.readFileSync('client-cert.pem')
};
const port = 4443
const insecureport = 4000
const app = express()

var rawBodySaver = function (req, res, buf, encoding) {
    // console.warn("Verifier called");
    if (buf && buf.length) {
        req.rawBody = buf.toString(encoding || 'utf8');
    }
    try {
        let j = JSON.parse(buf)
    } catch (e) {
        console.log(`Failed parsing JSON: `)
        console.log(buf.toString('ascii'))
    }
}

app.use(bodyParser.json({ limit: '50mb',  verify: rawBodySaver }));       // to support JSON-encoded bodies
// app.use(bodyParser.urlencoded({ extended: true })); // to support URL-encoded bodies
// app.use(bodyParser.text({ verify: rawBodySaver }));


console.log(`Starting application. Port HTTP: ${insecureport}, HTTPS: ${port}`)

const MODELS = {
    1: 'Smart Beacon',
    3: 'USB Beacon UB16-2',
    4: 'Card Tag CT16-2',
    5: 'Gateway GW16-2',
    6: 'Beacon Pro BP16-3',
    8: 'Asset Tag S18-3',
    9: 'Smart Beacon SB18-3',
    10: 'Heavy Duty Beacon HD18-3',
    11: 'Card Tag CT18-3',
    12: 'Coin Tag C18-3',
    13: 'Smart Beacon with Humidity Sensor SB18-3H',
    14: 'Tough Beacon TB18-2',
    15: 'Bracelet Tag, BT18-3',
    16: 'Universal Tag, UT19-1',
    17: 'Bracelet Tag, BT19-4',
}

function parseTelemetry(adv) {
    let buffer = adv.data
    let currentIndex = 8
    let telemetryData = {}

    telemetryData['rssi'] = adv.rssi

    while (currentIndex < buffer.length) {
        const length = buffer.readUInt8(currentIndex)
        const fieldID = buffer.readUInt8(currentIndex + 1)
        const data = buffer.slice(currentIndex + 2, (currentIndex + 2) + length - 1)
        currentIndex = currentIndex + (length + 1)

        switch (fieldID) {
            case 0x01:
                telemetryData['timestamp'] = data.readUInt32LE(0)
                telemetryData['batteryLevel'] = data.readUInt8(4)
                break
            case 0x02:
                telemetryData['sensitivity'] = data.readUInt8(0)
                telemetryData['x'] = data.readInt8(1)
                telemetryData['y'] = data.readInt8(2)
                telemetryData['z'] = data.readInt8(3)
                telemetryData['doubleTap'] = data.readUInt16LE(4)
                telemetryData['threshold'] = data.readUInt16LE(6)
                break
            case 0x03:
                telemetryData['bleScans'] = data.readUInt8(0)
                telemetryData['wifiScans'] = data.readUInt8(1)
                telemetryData['bleDevices'] = data.readUInt16LE(2)
                break
            case 0x04:
                telemetryData['timestamp'] = data.readUInt32LE(0)
                telemetryData['uptime_h'] = data.readUInt16LE(4)
                telemetryData['loadAverage'] = data.readUInt8(6)
                telemetryData['errorFlags'] = data.readUInt16LE(7)
                break
            case 0x05:
                telemetryData['lightLevel'] = data.readUInt8(0)
                telemetryData['temperature'] = data.readUInt8(1)
                break
            case 0x06:
                telemetryData['sensitivity'] = data.readUInt8(0)
                telemetryData['x'] = data.readInt8(1)
                telemetryData['y'] = data.readInt8(2)
                telemetryData['z'] = data.readInt8(3)
                break
            case 0x07:
                telemetryData['threshold_s'] = data.readUInt16LE(0)
                break
            case 0x08:
                telemetryData['doubleTap'] = data.readUInt16LE(0)
                break
            case 0x09:
                telemetryData['tap'] = data.readUInt16LE(0)
                break
            case 0x0a:
                telemetryData['lightLevel'] = data.readUInt8(0)
                break
            case 0x0b:
                telemetryData['temperature'] = data.readInt8(0)
                break
            case 0x0c:
                telemetryData['batteryLevel'] = data.readUInt8(0)
                break
            case 0x0d:
                telemetryData['buttonClick'] = data.readUInt16LE(0)
                break
            case 0x0e:
                telemetryData['doubleClick'] = data.readUInt16LE(0)
                break
            case 0x0f:
                telemetryData['timestamp'] = data.readUInt32LE(0)
                break
            case 0x10:
                telemetryData['loggingEnabled'] = Boolean(data.readUInt8(0))
                break
            case 0x11:
                telemetryData['clickId'] = `${data.readUInt8(0).toFixed()}i`
                telemetryData['buttonClick'] = data.readUInt16LE(0)
                break
            case 0x12:
                telemetryData['humidity'] = data.readUInt8(0)
                break
            case 0x13:
                telemetryData['temperature'] = data.readInt16LE(0) / 256
                break
            case 0x14:
                telemetryData['bleChannel'] = data.readUInt8(0)
                break
            case 0x15:
                telemetryData['gpioMask'] = data.readUInt8(0)
                telemetryData['gpioState'] = data.readUInt8(1)
                break
            case 0x16:
                telemetryData['movementId'] = data.readUInt8(0)
                telemetryData['threshold'] = data.readUInt16LE(0)
                break
            default:
                telemetryData[fieldID] = data
                break
        }
    }
    return {
        uniqueId: null,
        data: telemetryData,
        type: 'telemetry',
    }
}

function parseKontaktProfile(adv) {
    let buffer = adv.data.slice(8)
    let uniqueId = buffer.slice(5).toString('ascii')
    return {
        uniqueId,
        data: {
            model: buffer.readUInt8(0),
            batteryLevel: buffer.readUInt8(3),
            txPower: buffer.readInt8(4),
            firmware: buffer.readUInt8(2),
            rssi: adv.rssi,
        },
        type: 'secure_profile',
    }
}

function parseLocation(adv) {
    let buffer = adv.data.slice(8)
    let uniqueId = buffer.slice(4).toString('ascii')
    return {
        uniqueId,
        data: {
            txPower: buffer.readInt8(0),
            channel: buffer.readUInt8(1),
            model: buffer.readUInt8(2),
            flags: buffer.readUInt8(3),
            rssi: adv.rssi,
        },
        type: 'location',
    }
}

function parseDood(adv) {
    let buffer = adv.data
    let currentIndex = 0
    while (currentIndex < buffer.length) {
        const length = buffer.readUInt8(currentIndex)
        const fieldID = buffer.readUInt8(currentIndex + 1)
        const data = buffer.slice(currentIndex + 2, (currentIndex + 2) + length - 1)
        currentIndex = currentIndex + (length + 1)

        if (fieldID === 0x16 && data.readUInt16LE() === 0xd00d) {
            let offset = 2

            let uniqueId = data.slice(offset, offset + 4).toString()
            offset += 4

            let firmware = `${String.fromCharCode(data[offset])}.${String.fromCharCode(data[offset + 1])}`
            offset += 2

            let batteryLevel = data.readUInt8(offset)
            return {
                uniqueId,
                data: { firmware, batteryLevel },
                type: 'd00d',
            }
        }
    }
    return { uniqueId: null, type: null }
}

function parseKontakt(adv) {
    if (adv.data.includes(magicBits.tlm_magic)) {
        return parseTelemetry(adv)
    } else if (adv.data.includes(magicBits.secprofile_magic)) {
        return parseKontaktProfile(adv)
    } else if (adv.data.includes(magicBits.location_magic)) {
        return parseLocation(adv)
    } else if (adv.data.includes(magicBits.dood_magic)) {
        return parseDood(adv)
    } else {
        return { uniqueId: null, data: null, type: null }
    }
}


function echo(req, res) {
    console.log('Method', req.method);
    console.log('Path', req.path);
    console.log('Headers');
    console.dir(req.headers);
    console.log('Body');
    console.dir(req.body);
    console.log('Query');
    console.dir(req.query);
    console.log(`Time: ${Math.round((new Date()).getTime() / 1000)}`);

    let backresponse = { path: req.path, headers: req.headers, body: req.body, query: req.query};
    res.status(200).send(backresponse);
}

function api2normal(s) {
    if (!s) return ''
    return Buffer.from(s, 'base64').toString('hex')
}

const macs = new Set([])

function resp(req, res) {
    // console.log('Headers');
    // console.dir(req.headers);
    // console.log('Body ', req.rawBody && req.rawBody.length || "");
    let time = Date.now() / 1000
    // console.log(`Request at time: ${Math.round((new Date()).getTime() / 1000)}`);
    let len = 0;
    let events = req.body.events
    // console.dir(req.body)
    if (events) {
        len = events.length;
        let interesting = (macs.size) ? events.filter(e => macs.has(e.deviceAddress.toLowerCase())) : events
        for (let ping of interesting) {
            ping.data = api2normal(ping.data)
            ping.srData = api2normal(ping.srData)

            if (ping.data) {
                let adv = { rssi: ping.rssi, data: Buffer.from(ping.data, 'hex') }
                let result = parseKontakt(adv)
                if (result && result.data) {
                    console.log(time, result.uniqueId, result.data)
                }
            }

        }
        if (interesting.length == 0) {
            console.log(`Received ${len} scan events`);
        }
    }
    let backresponse = {
        length: len,
    };
    res.status(201).send(backresponse);
}

app.all('/echo', echo);
app.all('/*', resp);

let httpsServer = https.createServer(options, app);
httpsServer.listen(port);
let httpServer = http.createServer(app);
httpServer.listen(insecureport);
