function str2hex(str) {
    var val = "";
    for (var i = 0; i < str.length; i++) {
        if (val === "")
            val = str.charCodeAt(i).toString(16);
        else
            val += str.charCodeAt(i).toString(16);
    }
    return val;
}

function dataSubmit() {
    var username = str2hex(document.getElementById("uname").value);
    var passwword = str2hex(document.getElementById("pwd").value);
    console.log(username);
    console.log(passwword);
    rc4_init();
    var udata = rc4_crypt(username, username.length);
    var umac = sha256_digest(udata);
    rc4_init();
    var pdata = rc4_crypt(passwword, passwword.length);
    var pmac = sha256_digest(pdata);
    $.ajax({
        type: 'POST',
        url: "http://127.0.0.1:8000/login/",
        headers: {"csrftoken": document.cookie.substring(10, document.cookie.length)},
        data: {
            "username": udata + umac,
            "password": pdata + pmac
        },
        dataType: "json",
        traditional: true,
        success: function (ret) {
            console.log("what...");
        }
    });
}