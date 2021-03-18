var RC4_KEY_LEN_MAX = 256;

var rc4CalcTemplate = {
    Rc4Key: localStorage.getItem("master_key"), // 自己约定的密钥
    Keylen: 0,
    Rc4Sbox: new Array(256),
};

/*初始化函数*/
function rc4_init() {
    rc4CalcTemplate.Keylen = rc4CalcTemplate.Rc4Key.length;
    var j = 0;
    var k = new Array(256);
    var tmp = 0;

    for (let i = 0; i < 256; i++) {
        rc4CalcTemplate.Rc4Sbox[i] = i;
        k[i] = String(rc4CalcTemplate.Rc4Key[i % rc4CalcTemplate.Keylen]).charCodeAt(0);
    }

    for (let i = 0; i < 256; i++) {
        j = (j + rc4CalcTemplate.Rc4Sbox[i] + k[i]) % 256;
        tmp = rc4CalcTemplate.Rc4Sbox[i];
        rc4CalcTemplate.Rc4Sbox[i] = rc4CalcTemplate.Rc4Sbox[j]; //交换s[i]和s[j]
        rc4CalcTemplate.Rc4Sbox[j] = tmp;
    }
}

/*加解密*/
function rc4_crypt(Data, Len) {
    var i = 0,
        j = 0,
        t = 0,
        sLen = 0;
    var k = 0;
    var tmp;
    var s = new Array(RC4_KEY_LEN_MAX);
    var result = new Array(Len);
    for (sLen = 0; sLen < RC4_KEY_LEN_MAX; sLen++) {
        s[sLen] = rc4CalcTemplate.Rc4Sbox[sLen];
    }
    for (k = 0; k < Len; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        tmp = s[i];
        s[i] = s[j]; //交换s[x]和s[y]
        s[j] = tmp;
        t = (s[i] + s[j]) % 256;
        result[k] = Data[k].charCodeAt(0) ^ s[t];
    }
    for (let i = 0; i < result.length; i++) {
        result[i] = result[i].toString(16);
        if (result[i].length === 1) {
            result[i] = '0' + result[i];
        }
    }
    return result.join('');
}

function file_upload() {
    var myfile = document.getElementById("fileUpload").files[0];
    var reader = new FileReader();
    reader.readAsArrayBuffer(myfile);
    reader.onload = function (evt) {
        var str = ab2hex(evt.target.result);
        rc4_init();
        var data = rc4_crypt(str, str.length);
        var mac = sha256_digest(data);
        $.ajax({
            type: 'POST',
            url: "http://127.0.0.1:8000/upload/",
            headers: {"csrftoken": document.cookie.substring(10, document.cookie.length)},
            data: {
                "filename": myfile.name,
                "filesize": ab2str(evt.target.result).length,
                "file": data + mac
            },
            dataType: "json",
            traditional: true,
            success: function (ret) {
                console.log("what...");
            }
        });
    }
}

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
}

// 字符串转为ArrayBuffer对象，参数为字符串
function str2ab(str) {
    var buf = new ArrayBuffer(str.length);
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}


var hex2ab = function (hex) {
    var typedArray = new Uint8Array(hex.match(/[\da-f]{2}/gi).map(function (h) {
        return parseInt(h, 16);
    }))

    var buffer = typedArray.buffer;
    return buffer;
}

// ArrayBuffer转16进度字符串示例
const ab2hex = function (buffer) {
    var hexArr = Array.prototype.map.call(
        new Uint8Array(buffer),
        function (bit) {
            return ('00' + bit.toString(16)).slice(-2)
        }
    );
    return hexArr.join('');
}
