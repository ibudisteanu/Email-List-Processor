console.log("Hello World");

var shell = require('shelljs');
var fs = require('fs');

function extractTLS(domain, port){

    var port = 25;
    var cert = shell.exec('timeout 5 openssl s_client -connect '+domain+':'+port+' -starttls smtp ', {silent:true}).stdout;
    cert = cert.split("\n");
    //console.log(cert);

    var protocol = '';
    for (var i=0; i<cert.length; i++){

        var str = cert[i];
        if (str.indexOf("Protocol  :") >= 0)
            protocol = str.substr(str.indexOf("Protocol  :")+"Protocol  :".length);

    }

    return {
        result: protocol !== '',
        protocol: protocol,
    }


}

function process(user, pass){

    var domain = user.substr( user.indexOf("@")+1 );

    var dig = shell.exec('timeout 5 dig '+domain+' mx', {silent:true}).stdout;
    dig = dig.split("\n");


    //SAMPLE
    // ;; OPT PSEUDOSECTION:
    //     ; EDNS: version: 0, flags:; udp: 4096
    // ;; QUESTION SECTION:
    //     ;google.com.			IN	MX
    //
    // ;; ANSWER SECTION:
    //     google.com.		414	IN	MX	50 alt4.aspmx.l.google.com.
    //     google.com.		414	IN	MX	40 alt3.aspmx.l.google.com.
    //     google.com.		414	IN	MX	20 alt1.aspmx.l.google.com.
    //     google.com.		414	IN	MX	30 alt2.aspmx.l.google.com.
    //     google.com.		414	IN	MX	10 aspmx.l.google.com.
    //
    // ;; Query time: 2 msec
    // ;; SERVER: 127.0.1.1#53(127.0.1.1)
    // ;; WHEN: Fri Oct 05 18:10:35 EEST 2018
    // ;; MSG SIZE  rcvd: 147
    //

    var answer = {
        result: false,
    };

    var ok =false;
    for (var i=0; i<dig.length; i++){

        if (!dig[i]) continue;

        if (dig[i] === ";; ANSWER SECTION:" ) {
            ok = true;
            continue;
        }
        if (dig[i].indexOf(";; Query time:") >= 0) ok = false;

        if (ok){
            //google.com.		414	IN	MX	50 alt4.aspmx.l.google.com.
            var data = dig[i].split(/[\s,]+/);

            var server = data[5];

            if (!server) continue;

            if (server[server.length-1] === '.') server = server.substr(0, server.length-1);

            var r = extractTLS(server, 25)
            if (r.result){

                return {
                    result: true,
                    domain: domain,
                    mx: server,
                    tls: r.protocol,
                };

            }
        }

    }

    return {
        result: false,
        domain: domain
    }

}

function read(){
    var output = fs.createWriteStream( "output.txt", { flags: 'w' } );

    var emails = fs.readFileSync('input.txt', 'utf8');
    emails = emails.split("\n");

    for (var i = 0; i< emails.length; i++){

        var data = emails[i].split(/[\s,]+/);

        var email = data[0];
        var pass = data[1];

        if (email !== undefined && pass !== undefined){
            var answer = process(email, pass);

            if (answer.result) {
                output.write( answer.domain +" "+ answer.mx +" "+ answer.tls + "\n");
            }

        }

        if (i%1000 === 0)
            console.log("processing ", i, data)

    }

}


read();