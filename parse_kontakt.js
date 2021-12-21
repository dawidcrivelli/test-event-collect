const magicBits = {
    dood_magic: Buffer.from([0x16, 0x0d, 0xd0]),
    shuffled_magic: Buffer.from([0x16, 0x6a, 0xfe, 0x01]),
    secprofile_magic: Buffer.from([0x16, 0x6a, 0xfe, 0x02]),
    tlm_magic: Buffer.from([0x16, 0x6a, 0xfe, 0x03]),
    kontakt_magic: Buffer.from([0x16, 0x6a, 0xfe]),
    location_magic: Buffer.from([0x16, 0x6a, 0xfe, 0x05]),
    location2_magic: Buffer.from([0x16, 0x6a, 0xfe, 0x07]),
    ibeacon_magic: Buffer.from([0xff, 0x4c, 0x00, 0x02, 0x15]),
}

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
    19: 'TT Beacon',
    26: 'Lanyard Tag',
    27: 'Nano Tag',
    28: 'Puck Tag',
    29: 'Portal Light Gateway',
    30: 'Smart Badge',
    31: 'Portal Beam',
    32: 'Nano Series',
    33: 'Asset Tag2',
    34: 'Anchor Beacon2',
    35: 'Bluenrg',
    128: 'Partner device',
}

function macFormat(binary_mac) {
    return Array.from(binary_mac, x => x.toString(16).padStart(2, '0')).join(':')
}

function parseTelemetry(buffer) {
    let currentIndex = 0
    let telemetryData = {type: 'telemetry'}

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
                telemetryData['clickId'] = data.readUInt8(0)
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
            case 0x17:
                telemetryData['pressure'] = data.readFloatLE(0)
                break
            case 0x18:
                telemetryData['pir_s'] = data.readUInt16LE(0)
                break
            case 0x19:
                telemetryData['clickId'] = data.readUInt8(0)
                telemetryData['clickId2'] = data.readUInt8(1)
                telemetryData['buttonClick_s'] = data.readUInt16LE(2)
                break
            case 0x1a:
                telemetryData['aqi'] = data.readUInt8(0)
                break
            case 0x1b:
                telemetryData['room_number'] = data.readUInt16LE(0)
                break
            case 0x1c:
                telemetryData['occupancy'] = data.readUInt8(0)
                telemetryData['occupancy_s'] = data.readUInt16LE(1)
                break
            case 0x1d:
                let mac = macFormat(data.slice(0, 6))
                let rssi = data.readInt8(6)
                let stddev = data.readUInt8(7)
                let count = data.readUInt8(8)
                telemetryData['scan'] = {mac, rssi, stddev, count}
                break
            case 0x1e:
                telemetryData['proximityReport'] = {
                    mac: data.slice(6),
                    distance: data.readUInt16LE(6),
                    accuracy: data.readUInt8(8),
                }
                break
            case 0x1f:
                telemetryData['gas_type'] = data.readUInt8(0)
                telemetryData['gas_ppm'] = data.readInt16LE(1)
                break
            case 0x20:
                telemetryData['lux'] = data.readInt16LE(0)
                break
            case 0xFF:
                const vendorUUID = data.readUInt16LE(0)
                const vendorData = data.slice(2)
                if (vendorUUID == 65130) {
                    Object.assign(telemetryData, parseTelemetry(vendorData))
                } else {
                    telemetryData['vendorUUID'] = vendorUUID
                    telemetryData['vendorSpecific'] = vendorData.toString('hex')
                }
                break
            default:
                telemetryData[fieldID] = data
                break
        }
    }
    return telemetryData
}

function parseKontaktProfile(buffer) {
    return {
        model: buffer.readUInt8(0),
        batteryLevel: buffer.readUInt8(3),
        txPower: buffer.readInt8(4),
        firmware: buffer.readUInt8(2),
        uniqueId: buffer.slice(5).toString('ascii'),
        type: 'secureProfile',
    }
}

function parseLocation(buffer) {
    return {
        txPower: buffer.readInt8(0),
        channel: buffer.readUInt8(1),
        model: buffer.readUInt8(2),
        flags: buffer.readUInt8(3),
        uniqueId: buffer.slice(4).toString('ascii'),
        type: 'location',
    }
}

function parseLocation2(buffer) {
    let ret = {
        battery: buffer.readUInt8(0),
        txPower: buffer.readInt8(1),
        channel: buffer.readUInt8(2),
        model: buffer.readUInt8(3),
        flags: buffer.readUInt8(4),
        timestamp: buffer.readUInt32LE(5) * 1000 + buffer.readUInt8(9) * 4,
        room_number: buffer.readUInt16LE(10),
        uniqueId: buffer.slice(12).toString('ascii'),
        type: 'location',
    }

    if (ret.room_number == 0xFFFF)
        ret.room_number = undefined

    if (ret.battery == 0xFF)
        ret.battery = undefined

    return ret
}

function parseDood(data) {
    let offset = 0

    let uniqueId = data.slice(offset, offset + 4).toString()
    offset += 4

    let firmware = `${String.fromCharCode(data[offset])}.${String.fromCharCode(data[offset + 1])}`
    offset += 2

    let batteryLevel = data.readUInt8(offset)
    return {
        firmware,
        batteryLevel,
        uniqueId,
        type: 'd00d',
    }
}

function parseIbeacon(buffer) {
    let proximity = buffer.slice(0, 16).toString('hex')
    let offset = 16
    let major = buffer.readUInt16BE(offset)
    offset += 2
    let minor = buffer.readUInt16BE(offset)
    offset += 1
    let rssi1m = buffer.readInt8(offset)
    let proxiFormat = proximity.slice(0, 8) + '-' + proximity.slice(8, 12) + '-' +
        proximity.slice(12, 16) + '-' + proximity.slice(16, 20) + '-' + proximity.slice(20, 32)
    return {
        proximity: proxiFormat,
        major,
        minor,
        txPower: rssi1m,
        type: 'ibeacon',
    }
}

function parseShuffled(adv) {
    // let namespace = adv.data.slice(10, 10 + 10).toString('hex')
    // let instance = adv.data.slice(20).toString('hex')
    // return {
    //     uniqueId: undefined,
    //     data: {
    //         namespace,
    //         instance,
    //         rssi: adv.rssi,
    //     },
    //     type: 'shuffled',
    // }
}

function parseTTNotification(buffer) {
    let type = buffer.readUInt8(0)
    if (buffer.length !== 8) return {}
    let battery = buffer.readInt8(1)
    let events = buffer.readUInt8(2)
    let raw_x = buffer.readInt8(3)
    let raw_y = buffer.readInt8(4)
    let raw_z = buffer.readInt8(5)
    let avg_acc = buffer.readUInt16BE(6)

    let counter = events & 0xF
    let active = +((events & 1 << 4) != 0)
    let crash = +((events & 1 << 5) != 0)

    let sensitivity_bits = (events >> 6) & 0b11
    let sensitivity_map = {
        0b00: 0.016,
        0b01: 0.032,
        0b10: 0.064,
        0b11: 0.128
    }
    let sensitivity = sensitivity_map[sensitivity_bits]
    let x = Math.round(raw_x * sensitivity * 100) / 100
    let y = Math.round(raw_y * sensitivity * 100) / 100
    let z = Math.round(raw_z * sensitivity * 100) / 100
    avg_acc = Math.round(avg_acc / 1000 * 100) / 100

    return {
        uniqueId: '',
        data: {
            battery,
            crash,
            active,
            counter,
            x,
            y,
            z,
            avg_acc,
        },
        type: 'tt_frame'
    }
}



function parseAll(buffer) {
    const match_list = [
        [magicBits.tlm_magic, parseTelemetry],
        [magicBits.secprofile_magic, parseKontaktProfile],
        [magicBits.location_magic, parseLocation],
        [magicBits.location2_magic, parseLocation2],
        [magicBits.dood_magic, parseDood],
        [magicBits.ibeacon_magic, parseIbeacon],
        [magicBits.shuffled_magic, parseShuffled],
    ]

    for (let [bits, parser] of match_list) {
        if (buffer.indexOf(bits) == 0) {
            return parser(buffer.slice(bits.length))
        }
    }
}


function parseData(buffer) {
    let parsed_data = {}

    let currentIndex = 0
    while (currentIndex < buffer.length) {
        const length = buffer.readUInt8(currentIndex)
        const fieldAndData = buffer.slice(currentIndex + 1, (currentIndex + 1) + length)
        const data = buffer.slice(currentIndex + 2, (currentIndex + 2) + length - 1)
        currentIndex = currentIndex + (length + 1)
        // console.log(`Parsing block long ${length} with: ${fieldAndData.toString('hex')}`)
        let parsed = parseAll(fieldAndData, data)
        parsed_data = Object.assign(parsed_data, parsed)
    }

    return parsed_data
}

function parseKontakt(adv) {
    let buffer = adv.data
    data = parseData(buffer)
    let rssi = adv.rssi

    return { uniqueId: data['uniqueId'], data: data, type: data['type'], rssi }
}

module.exports.parseKontakt = parseKontakt
module.exports.parseTTNotification = parseTTNotification
module.exports.magicBits = magicBits

if (require.main === module) {
    let ads = [
    '0201061b166afe03050610fe208d041100ffff041600ffff03139f17021231',
    '0b09415a2d4b6e746b2e696f020af80a160dd044435a39343231',
    '0201061a166afe030bff6afe021a5c041c042700051708fcc24703137d18',
    '02010613166afe030eff6afe0a1df008d1d65142be0001',
    '0201061aff4c000215f7826da64fa24e988024bc5b71e0893efae3e1abb3'
]

    for (let ad of ads) {
        console.log(parseKontakt({ data: Buffer.from(ad, 'hex') }))
    }
}