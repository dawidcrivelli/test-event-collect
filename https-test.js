const express = require('express')
const https = require('https');
const http = require('http');
const fs = require('fs');
const bodyParser = require('body-parser')
const {parseKontakt} = require('./parse_kontakt')

const options = {
    key: fs.readFileSync('client-key.pem'),
    cert: fs.readFileSync('client-cert.pem')
};
const port = 4443
const insecureport = 4123
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


const macs = new Set([])
console.log(`Starting application. Port HTTP: ${insecureport}, HTTPS: ${port}`)
console.log(`Allowing only macs:`, macs)


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

    let backresponse = {}; //{ path: req.path, headers: req.headers, body: req.body, query: req.query};
    res.status(200).send(backresponse);
}

function api2normal(s) {
    if (!s) return ''
    return Buffer.from(s, 'base64').toString('hex')
}


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
            let mac = (ping.deviceAddress || '').toLowerCase()

            if (ping.data) {
                let adv = { rssi: ping.rssi, data: Buffer.from(ping.data, 'hex') }
                let result = parseKontakt(adv)
                if (result && Object.keys(result.data).length > 0) {
                    console.log(time, mac, result.rssi, result.uniqueId , result.data)
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

app.all('/event/collect', resp);
app.all('/*', echo);

let httpsServer = https.createServer(options, app);
httpsServer.listen(port);
let httpServer = http.createServer(app);
httpServer.listen(insecureport);
