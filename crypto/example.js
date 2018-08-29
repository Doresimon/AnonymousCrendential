"use strict";
const UTIL = require("./util.js");
const Issuer = require("./issuer.js");
const User = require("./user.js");

main();

function main() {
    /* public parameter */
    let AttributeName = ["24", "master", "male", "handsome"];
    let Disclosure = [1, 0, 1, 0];

    let I = new Issuer();
    let U = new User();
    let V = new User();

    /* issuer setup */
    I.Setup();
    I.SetAttr(AttributeName);
    console.log("I.Setup()");
    console.log("I.SetAttr(AttributeName)");

    let ipk = I.Ipk();
    U.SetIpk(ipk);
    U.GenerateSk();
    console.log("U.SetIpk(Issuer.ipk)");
    console.log("U.GenerateSk()");

    /* issuer generate a random nonce number */
    let n = UTIL.getRandBN();
    console.log("Issuer.send(n)");

    /* user */
    U.GenerateCrendentialRequest(n);
    console.log("U.GenerateCrendentialRequest(nonce)");

    let v = I.VerifyCredentialRequest(U.Nym, U.pi, n); // verify pi
    console.log("I.VerifyCredentialRequest(Nym, pi, n)");
    console.log(v);
    if (!v) {
        return false;
    }

    let Credential = I.Sign(U.Nym, U.attrs);
    console.log("Issuer.send(Credential)");

    let uv = U.VerifyBBSplus(U.ipk, Credential.attrs, Credential.sig, U.Nym);
    console.log("U.VerifyBBSplus(Credential)");
    console.log(uv);

    U.SetCredential(Credential);
    console.log("U.SetCredential(Credential)");

    /* 
       * @inputs 
              D: Disclosure of attributes.
              Nonce: a non-sense string for fresh.
       * @output    
       */
    let proof = U.Prove(Disclosure);
    console.log("User.prove(Credential)");

    V.SetIpk(ipk);
    console.log("V.SetIpk(Issuer.ipk)");

    let r = V.Verify(proof, Disclosure, U.attrs);
    console.log("V.Verify(proof, Disclosure, attrs)");
    console.log(r);

    console.log("BINGO~");
}
