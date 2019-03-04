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
    console.warn("Verifier called");
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

app.use(bodyParser.json({ verify: rawBodySaver }));       // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({ extended: true })); // to support URL-encoded bodies
app.use(bodyParser.text({ verify: rawBodySaver }));



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
    return telemetryData
}

function parseKontaktProfile(adv) {
    let buffer = adv.data.slice(8)
    let uniqueId = buffer.slice(5).toString('ascii')
    let ret = [uniqueId, {
        model: buffer.readUInt8(0),
        batteryLevel: buffer.readUInt8(3),
        txPower: buffer.readInt8(4),
        firmware: buffer.readUInt8(2),
        rssi: adv.rssi,
    }]
    return ret
}

function parseLocation(adv) {
    let buffer = adv.data.slice(8)
    let uniqueId = buffer.slice().toString('ascii')
    return [uniqueId, {
        txPower: buffer.readInt8(0),
        channel: buffer.readUInt8(1),
        rssi: adv.rssi,
    }]
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
// 'da:fb:81:c4:63:63', 'f3:c9:1b:0f:2f:3a', 'ce:1c:87:3a:da:f0', 'd3:c5:b0:e8:94:2c', 'f4:b8:5e:ac:5a:87', 'f4:b8:5e:ac:4e:68', 'e3:44:47:a3:9d:71', 'eb:5f:62:1c:90:07', '60:c0:bf:0d:6b:1b', 'e2:02:00:1e:e3:40', 'e2:02:00:2d:f4:40', 'e3:44:47:a3:9d:71', 'e8:7a:4c:fc:04:72',
// 'ea:96:9d:79:41:64'
const macs = new Set([ 'e0:7b:2d:b6:ae:f7'])

function resp(req, res) {
    // console.log('Headers');
    // console.dir(req.headers);
    // console.log('Body ', req.rawBody && req.rawBody.length || "");
    console.log(`Time: ${Math.round((new Date()).getTime() / 1000)}`);

    let len = 0;
    let events = req.body.events
    // console.dir(req.body)
    if (events) {
        len = events.length;
        let interesting = events.filter((e) => e.ble && macs.has(e.ble.deviceAddress.toLowerCase()))
        interesting = interesting.filter((e) => e.eventType !== 'LOST')
        for (let ping of interesting) {
            ping.ble.data = api2normal(ping.ble.data)
            ping.ble.srData = api2normal(ping.ble.srData)

            let adv = { rssi: ping.ble.rssi, data: Buffer.from(ping.ble.data, 'hex') }
            if (adv.data.includes(magicBits.tlm_magic)) {
                ping.ble.parsed = parseTelemetry(adv)
                // console.log(ping)
            }
            console.log(ping)

        }

        console.log(`Received ${len} scan events`);
    }
    let backresponse = {
        length: len,
    };
    console.log('');
    res.status(201).send(backresponse);
}

app.all('/echo', echo);
app.all('/*', resp);

let httpsServer = https.createServer(options, app);
httpsServer.listen(port);
let httpServer = http.createServer(app);
httpServer.listen(insecureport);
