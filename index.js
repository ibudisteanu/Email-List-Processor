console.log("Hello World");

var shell = require('shelljs');
var fs = require('fs');
var ping = require('ping');
var nodemailer = require('nodemailer');

async function extractTLS(domain, port){

    var port = 25;
    var cert = await shell.exec('timeout 5 openssl s_client -connect '+domain+':'+port+' -starttls smtp ', {silent:true});
    cert = cert.stdout.split("\n");
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

function validateSMTP(hosts){

    return new Promise((resolve)=>{

        var timeout;

        hosts.forEach(function (host) {
            ping.promise.probe(host)
                .then(function (res) {
                    clearTimeout(timeout);
                    resolve({
                        result: true,
                        host: host,
                    });
                });
        });

        var timeout = setTimeout(()=>{

            resolve({
                        result: false,
                        host: host
                    });

        }, 4000);

    });

}

function commonSMTPAddressses(domain, mxs){
    var smtp = ['smtp.'+domain, 'mail.'+domain, 'mail1.'+domain, 'mailhost.'+domain, 'relay.'+domain, 'postoffice.'+domain, 'post.'+domain]
    return [...smtp, ...mxs];
}

function validateSMTPCommon(domain,mxs){

    return validateSMTP( commonSMTPAddressses(domain, mxs));

}

function validateAccountCommon(domain ,mxs, port, user, pass,useSSL = false){

    var hosts = commonSMTPAddressses(domain ,mxs);

    return new Promise((resolve)=>{

        var timeout;

        hosts.forEach(function (host) {
            validateAccount(host, port, user, pass, useSSL)
                .then(function (res) {

                    if (res.result === false)
                        return;

                    clearTimeout(timeout);
                    resolve({
                        result: true,
                        host: host,
                    });
                });
        });

        var timeout = setTimeout(()=>{

             resolve({
                    result: false,
                    message: "timeout_all_validations",
                });

        }, 5000);

    });


}

async function validateAccount(host, port = 465, user, pass, useSSL = false){

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

        var timeout;

        var verification = transporter.verify(function(error, success) {

            clearTimeout(timeout);
            if (error)
                resolve({result: false, message: error.message})
            else {
                console.log('Server is ready to take our messages');
                resolve({result: true})
            }
        });

        //console.log("verification", verification)

        timeout = setTimeout(()=>{
            resolve({result: false, message: "timeout"});
        }, 5000);

    });

}

async function process(user, pass){

    var domain = user.substr( user.indexOf("@")+1 );

    var dig = await shell.exec('timeout 5 dig '+domain+' mx', {silent:true});
    dig = dig.stdout.split("\n");


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
        mxs: [],
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

            if (!answer.mx){

                var r = await extractTLS(server, 25);
                if (r.result){

                    answer.mx = server;
                    answer.tls = r.protocol;

                }

            }

            answer.mxs.push(server);

        }

    }

    // var smtp = await validateSMTPCommon(domain, answer.mxs);
    //
    // if (smtp.result) {
    //
    //     var validation = await validateAccount(smtp.host, 25, user, pass, false);
    //
    //     if (validation.result){
    //         answer.result = true;
    //         answer.verified = true;
    //         answer.smtp = smtp.host;
    //     } else
    //         answer.message = validation.message;
    //
    // } else answer.emssage = "no smtp server found";

    var validation = await validateAccountCommon( domain, answer.mxs, 25, user, pass, false);

    if (validation.result){
        answer.result = true;
        answer.verified = true;
        answer.smtp = validation.host;
    } else
        answer.message = validation.message;

    return answer;
}


async function read(){

    var output = fs.createWriteStream( "output.txt", { flags: 'w' } );
    var outputErr = fs.createWriteStream( "outputErr.txt", { flags: 'w' } );

    var emails = fs.readFileSync('input.txt', 'utf8');
    emails = emails.split("\n");

    var promises = {};
    var max_promises = 100;
    var promisesLength = 0;

    var index = 0;

    var interval = setInterval(()=>{

        if (index === emails.length){
            clearInterval(interval);
            return;
        }

        for (var i=0; i<max_promises; i++)
            if (!promises[i]){


                var data = emails[index].split(/[\s,]+/);
                index++;

                var email = data[0];
                var pass = data[1];

                if (email !== undefined && pass !== undefined){

                    var promise = process(email, pass);

                    promises[i] = promise;

                    promise.then((answer)=>{

                        if (answer.result) {
                            output.write( answer.smtp +" "+ answer.mx +" "+ answer.tls +" "+ " "+email + " "+pass+ " "+answer.verified+ "\n");
                        } else {
                            outputErr.write( email+" "+ pass+" "+answer.message + "\n" );
                        }

                        promises[i] = undefined;

                    });

                }

                if (i%1000 === 0)
                    console.log("processing ", i, data);

                index++;
                break;

            }

    }, 5);

}


read();