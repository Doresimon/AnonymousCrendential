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
    console.log("I.Setup()");
    I.SetAttr(AttributeName);
    console.log("I.SetAttr(AttributeName)");

    let ipk = I.Ipk();
    console.log("I.Publish(I.ipk)");

    U.SetIpk(ipk);
    console.log("U.SetIpk(I.ipk)");
    U.GenerateSk();
    console.log("U.GenerateSk()");

    /* issuer generate a random nonce number */
    let nonce = UTIL.getRandBN();
    console.log("Issuer.send(nonce)");

    /* user */
    U.GenerateCrendentialRequest(nonce);
    console.log("U.GenerateCrendentialRequest(nonce)");

    let v = I.VerifyCredentialRequest(U.Nym, U.pi, nonce); // verify pi
    console.log("I.VerifyCredentialRequest(U.Nym, U.pi, nonce)");
    console.log(v);
    if (!v) {
        return false;
    }

    let Credential = I.Sign(U.Nym, U.attrs);
    console.log("I.send(Credential)");

    let uv = U.VerifyBBSplus(U.ipk, Credential.attrs, Credential.sig, U.Nym);
    console.log("U.VerifyBBSplus(Credential), or call it verify issuer's reality");
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
    console.log("U.prove(Credential)");

    /* U ---> V */
    console.log("U.send(proof)");

    V.SetIpk(ipk);
    console.log("V.SetIpk(I.ipk)");

    let r = V.Verify(proof, Disclosure, U.attrs);
    console.log("V.Verify(U.proof, U.Disclosure, U.attrs)");
    console.log(r);

    console.log("BINGO~");
}
