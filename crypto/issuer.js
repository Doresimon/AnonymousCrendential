"use strict";
const PARAM = require("./param.js");
const UTIL = require("./util.js");

function Issuer() {
    let isk;
    let ipk;
    let AttributeName;

    /* 
        Setup() generates 
            isk: issuer's secret key
            ipk: issuer's public key
                ipk.w
                ipk._g1
                ipk._g2
                ipk.pi
                    C
                    S 
        */
    this.Setup = function () {
        let x = UTIL.getRandBN(); // isk
        let w = PARAM.PAIR.G2mul(PARAM.g2, x); // w

        let r = UTIL.getRandBN(); // random number
        let _g1 = PARAM.PAIR.G1mul(PARAM.g1, r);
        let _g2 = PARAM.PAIR.G1mul(_g1, x);

        // zkp - pi
        r = UTIL.getRandBN();
        let t1 = PARAM.PAIR.G2mul(PARAM.g2, r);
        let t2 = PARAM.PAIR.G1mul(_g1, r);

        let C = UTIL.hashToBN(t1, t2, PARAM.g2, _g1, w, _g2);

        let S = PARAM.BIG.modmul(C, x, PARAM.order);
        S.add(r);
        S.mod(PARAM.order);

        let pi = {
            C: C,
            S: S
        };

        let pk = {
            w: w,
            _g1: _g1,
            _g2: _g2,
            pi: pi
        };

        isk = x;
        ipk = pk;
    };

    /* 
        SetAttr(AttributeName) generates 
            ipk.h0: rand G1
            ipk.h_sk: rand G1
            ipk.h[]: Rand G1 array, match to AttributeName
        */
    this.SetAttr = function (AttributeName) {
        let HAttr = UTIL.genAttrElement(AttributeName);
        let h0 = UTIL.getRandG1();
        let h_sk = UTIL.getRandG1();
        let h = [];

        HAttr.forEach(a => {
            h.push(a);
        });

        ipk.h0 = h0;
        ipk.h_sk = h_sk;
        ipk.h = h;
        ipk.attr = AttributeName;
    };

    /* 
        VerifyCredentialRequest(Nym, pi, n) verifies user's credential request
        */
    this.VerifyCredentialRequest = function (Nym, pi, n) {
        let C = new PARAM.BIG(0);
        C.copy(pi.C);

        // let _t1 = h_sk^S * Nym^(-C)
        // let _t1 = new PARAM.ECP(0)
        let _t1 = PARAM.PAIR.G1mul(ipk.h_sk, pi.S);
        _t1.add(PARAM.PAIR.G1mul(Nym, PARAM.BIG.modneg(C, PARAM.order)));

        let _C = UTIL.hashToBN(_t1, ipk.h_sk, Nym, n);

        return PARAM.BIG.comp(pi.C, _C) == 0;
    };

    /* 
        sign a credential for a user
        */
    this.Sign = function (Nym, attrs) {
        // e, s
        let e = UTIL.getRandBN();
        let s = UTIL.getRandBN();
        let B = new PARAM.ECP(); // B = g1 · HRand^s · Nym · MulAll(HAttrs[i]^(Attrs[i]))
        B.copy(PARAM.g1);
        B.add(PARAM.PAIR.G1mul(ipk.h0, s));
        B.add(Nym);
        for (let i = 0; i < ipk.attr.length; i++) {
            B.add(PARAM.PAIR.G1mul(ipk.h[i], attrs[i]));
        }

        let A = new PARAM.ECP(); // A = B^(1/(e+x))
        let tmp = new PARAM.BIG(); //tmp = (1/(e+x))
        tmp.copy(e);
        tmp.add(isk); // !!!!!!!!!!!
        tmp.invmodp(PARAM.order);

        A = PARAM.PAIR.G1mul(B, tmp);

        let Credential = {
            sig: {
                A: A,
                B: B,
                e: e,
                s: s
            },
            attrs: attrs
        };
        return Credential;
    };

    /* 
        get issuer's public key
        */
    this.Ipk = function () {
        let pk = {};
        pk.w = new PARAM.ECP2();
        pk._g1 = new PARAM.ECP();
        pk._g2 = new PARAM.ECP();
        pk.pi = {};
        pk.pi.C = new PARAM.BIG();
        pk.pi.S = new PARAM.BIG();
        pk.h0 = new PARAM.ECP();
        pk.h_sk = new PARAM.ECP();
        pk.h = [];
        pk.attr = [];

        pk.w.copy(ipk.w);
        pk._g1.copy(ipk._g1);
        pk._g2.copy(ipk._g2);
        pk.pi.C.copy(ipk.pi.C);
        pk.pi.S.copy(ipk.pi.S);
        pk.h0.copy(ipk.h0);
        pk.h_sk.copy(ipk.h_sk);

        if (ipk.h != undefined) {
            for (let i = 0; i < ipk.h.length; i++) {
                pk.h[i] = new PARAM.ECP();
                pk.h[i].copy(ipk.h[i]);
            }
        }
        if (ipk.attr != undefined) {
            for (let i = 0; i < ipk.attr.length; i++) {
                pk.attr[i] = ipk.attr[i];
            }
        }

        return pk;
    };

    this.SerilizeIPK = function () {
        // TODO
    };
}

module.exports = Issuer;
