var jose = require('node-jose');
var z = require('zlib');
var flatMap = require('array.prototype.flatmap');

let raw = { "iss": "https://smarthealth.cards/examples/issuer", "nbf": 1620992383.218, "vc": { "@context": ["https://www.w3.org/2018/credentials/v1"], "type": ["VerifiableCredential", "https://smarthealth.cards#health-card", "https://smarthealth.cards#immunization", "https://smarthealth.cards#covid19"], "credentialSubject": { "fhirVersion": "4.0.1", "fhirBundle": { "resourceType": "Bundle", "type": "collection", "entry": [{ "fullUrl": "resource:0", "resource": { "resourceType": "Patient", "name": [{ "family": "Anyperson", "given": ["John", "B."] }], "birthDate": "1951-01-20" } }, { "fullUrl": "resource:1", "resource": { "resourceType": "Immunization", "status": "completed", "vaccineCode": { "coding": [{ "system": "http://hl7.org/fhir/sid/cvx", "code": "207" }] }, "patient": { "reference": "resource:0" }, "occurrenceDateTime": "2021-01-01", "performer": [{ "actor": { "display": "ABC General Hospital" } }], "lotNumber": "0000001" } }, { "fullUrl": "resource:2", "resource": { "resourceType": "Immunization", "status": "completed", "vaccineCode": { "coding": [{ "system": "http://hl7.org/fhir/sid/cvx", "code": "207" }] }, "patient": { "reference": "resource:0" }, "occurrenceDateTime": "2021-01-29", "performer": [{ "actor": { "display": "ABC General Hospital" } }], "lotNumber": "0000007" } }] } } } }
ehc = JSON.stringify(raw);
const compressedPayload = z.deflateRawSync(ehc);

const keystore = jose.JWK.createKeyStore();
let signingKey;
keystore.generate("EC", "P-256").
    then(function (result) {
        // {result} is a jose.JWK.Key
        signingKey = result;

        // Print the entire key store, including the `d` member which contains the private key value
        // Remove true to just present the public key
        keystore.toJSON();

        const fields = { zip: 'DEF' }

        let jws;

        jose.JWS.createSign({ format: 'compact', fields }, signingKey)
            .update(Buffer.from(compressedPayload))
            .final()
            .then(function (result) {
                jws = result;
                console.log(jws);

                //let numericJWS = jws.split('').map((c) => c.charCodeAt(0) - 45).flatMap((c) => [Math.floor(c / 10), c % 10]).join('');
            
                // const qrCodeData = 'shc:/' + numericJWS
            
                // console.log(qrCodeData)

                jose.JWS.createVerify(signingKey)
                    .verify(jws).then(function (result) {
                        //console.log(result);
                    });
            });
    });






