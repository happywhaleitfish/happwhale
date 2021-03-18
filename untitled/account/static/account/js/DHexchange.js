var global_p = 0n;
var global_g = 0n;

var client_rand = "";
var client_alice = 0n;

localStorage.removeItem("master_key");

function exchange() {
    localStorage.removeItem("master_key");
    sleep(500);
    try {
        var ws = new WebSocket("ws://127.0.0.1:2345");
        var receive = new Array();
        ws.onopen = function (evt) {
            console.log("Connection open...");
            //receive: none
            //send: client hello
            for (let i = 0; i < 28 * 8; i++) {
                client_rand += Math.round(Math.random()).toString();
            }
            var timestamp = (new Date()).valueOf().toString(2);
            if (timestamp.length < 32) {
                for (let j = 0; j < 32 - timestamp.length; j++) {
                    timestamp = Math.round(Math.random()).toString() + timestamp;
                }
            } else if (timestamp > 32) {
                timestamp = timestamp.substr(0, 32);
            }
            console.log(timestamp.length);
            client_rand = timestamp + client_rand;
            ws.send(JSON.stringify({
                "state": "hello",
                "exchange": client_rand
            }));
        };
        ws.onmessage = function (evt) {
            receive.push(eval("(" + evt.data + ")"));
            switch (receive[receive.length - 1]["state"]) {
                case "hello":
                    //receive: server hello
                    //send: key exchange
                    var tempA = BigInt("0b" + receive[receive.length - 1]["exchange"]);
                    var tempB = BigInt("0b" + client_rand);
                    if (tempA > tempB) {
                        global_p = tempA;
                        global_g = tempB;
                    } else {
                        global_p = tempB;
                        global_g = tempA;
                    }
                    console.log(global_p);
                    console.log(global_g);
                    client_alice = (BigInt(Math.random() * (10 ** 20)) * (global_p - 2n)) / (10n ** 20n) + 1n;
                    var client_key_exchange = repeatMod(global_g, client_alice, global_p);
                    ws.send(JSON.stringify({
                        "state": "key_exchange",
                        "exchange": client_key_exchange.toString(2)
                    }));
                    break;
                case "key_exchange":
                    master_key = repeatMod(BigInt("0b" + receive[receive.length - 1]["exchange"]), client_alice, global_p);
                    master_key = master_key.toString(2);
                    master_key = (master_key + master_key).substr(0, 256);
                    master_key = binaryToStr(master_key);
                    localStorage.setItem("master_key", master_key);
                    console.log(localStorage.getItem("master_key"));
                    console.log("haha");
                    break;
            }
        };
        ws.onclose = function (evt) {
            console.log("Connection closed...");
        };
    } catch (e) {
        console.log("Key exchange error!!!");
    }
}

function repeatMod(g, a, p) {
    var temp = 1n;
    while (a) {
        if (a & 1n) {
            temp = (temp * g) % p;
        }
        g = (g * g) % p;
        a = a >> 1n;
    }
    return temp;
}

function binaryToStr(str) {
    var strToArr = str.split('');
    for (let i = 8; i < strToArr.length; i += 8 + 1) {
        strToArr.splice(i, 0, ',');
    }
    str = strToArr.join('');
    var result = [];
    var list = str.split(',');
    for (let i = 0; i < list.length; i++) {
        var item = list[i];
        var asciiCode = parseInt(item, 2);
        var charValue = String.fromCharCode(asciiCode);
        result.push(charValue);
    }
    return result.join('');
}

function sleep(numberMillis) {
    var now = new Date();
    var exitTime = now.getTime() + numberMillis;
    while (true) {
        now = new Date();
        if (now.getTime() > exitTime)
            return;
    }
}
