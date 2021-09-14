var forge = require('node-forge');
var express = require('express');
var app = express();
var path = require('path');
const { Crypto } = require("@peculiar/webcrypto");
const crypto = new Crypto();
app.use(express.static(__dirname + '/public'));
app.get('/', function(req, res) {
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));


app.post("/link", (req,res) => {
    let pfxd = req.body.pfxd 
    let pfxs = req.body.pfxs 
    let pfxc = req.body.pfxc 
 
    let databfr = Buffer.from(pfxd, "base64");
    let data = databfr.toString("utf8");
    console.log("data : "+data+'\n')

    let certbfr = Buffer.from(pfxc, "base64");
    let certs = certbfr.toString("utf8");
    console.log("signature : "+pfxs+'\n')
    //console.log("certificate : "+pfxc+'\n')
    console.log("certificate : "+certs+'\n')

    var pem = forge.util.decode64(pfxc);
    var signature = forge.util.decode64(pfxs);
    var cert = forge.pki.certificateFromPem(pem);
    
    
    crypto.subtle.importKey("spki",publicKeyToPkcs8(cert.publicKey),
    {   
    name: "RSASSA-PKCS1-v1_5",
    hash: {name: "SHA-256"}, 
    },
    false,
    ["verify"]
    ).then(function(k)
        {
        crypto.subtle.verify(
            {
            name: "RSASSA-PKCS1-v1_5",
            },
            k, //from generateKey or importKey above
            stringToArrayBuffer(signature), //ArrayBuffer of the signature
            stringToArrayBuffer(pfxd) //ArrayBuffer of the data
            ).then(function(isvalid)
            {
            //returns a boolean on whether the signature is true or not
               if (!isvalid)
                   {
                var msg = 'Invalid digital Signature!<br>';
                msg += 'Signed Document: ';
                msg +=  forge.util.decode64($('#pfxd').val());

                msg += '<br>';
                msg += CertInfo(cert);
        
        
                $('#dr').html(msg);
                   }
            else
                   {
                    res.send("Valid Digital Signature!")
                }
            }).catch(function(err)
                {
                   $('#dr').html('Invalid Digital Signature!');
                });
            }
            
        );
    
});

app.listen(8080);


function publicKeyToPkcs8(pk){
	var subjectPublicKeyInfo = forge.pki.publicKeyToAsn1(pk);
	var der = forge.asn1.toDer(subjectPublicKeyInfo).getBytes();
	return stringToArrayBuffer(der);
}


function stringToArrayBuffer(data){
	var arrBuff = new ArrayBuffer(data.length);
	var writer = new Uint8Array(arrBuff);
	for (var i = 0, len = data.length; i < len; i++) 
		{
		writer[i] = data.charCodeAt(i);
		}
	return arrBuff;
}
