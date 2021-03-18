function file_download(id) {
    $.ajax({
        type: 'POST',
        headers: {"csrftoken": document.cookie.substring(10, document.cookie.length)},
        url: "http://127.0.0.1:8000/download/" + id,
        data: {
            "filerequest": "filerequest"
        },
        success: function (retdata) {
            var r_data = retdata["file"].substring(0, retdata["file"].length - 64);
            var r_mac = retdata["file"].substring(retdata["file"].length - 64, retdata["file"].length);
            if (sha256_digest(r_data) === r_mac) {
                window.alert("please wait!!!");
                r_data = hexToStr(r_data)
                rc4_init();
                data = rc4_crypt(r_data, r_data.length);
                data = hexToStr(data);
                saveShareContent(str2ab(hexToStr(data)), retdata["filename"]);
            } else {
                window.alert("error!!!");
            }
        }
    });
}

function saveShareContent(content, fileName) {
    let downLink = document.createElement('a');
    downLink.download = fileName;
    //字符内容转换为blod地址
    let blob = new Blob([content], {
        "type": "application/octet-stream"
    });
    downLink.href = URL.createObjectURL(blob);
    // 链接插入到页面
    document.body.appendChild(downLink);
    downLink.click();
    // 移除下载链接
    document.body.removeChild(downLink);
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

function hexToStr(str) {
    var strToArr = str.split('');
    for (let i = 2; i < strToArr.length; i += 2 + 1) {
        strToArr.splice(i, 0, ',');
    }
    str = strToArr.join('');
    var result = [];
    var list = str.split(',');
    for (let i = 0; i < list.length; i++) {
        var item = list[i];
        var asciiCode = parseInt(item, 16);
        var charValue = String.fromCharCode(asciiCode);
        result.push(charValue);
    }
    return result.join('');
}
