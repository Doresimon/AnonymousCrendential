"use strict";
const crypto = require("crypto");
const PARAM = require("./param.js");

const Util = {
    getRandBN() {
        const buf = crypto.randomBytes(256);
        PARAM.rng.clean();
        PARAM.rng.seed(256, buf);
        let r = PARAM.BIG.randomnum(PARAM.order, PARAM.rng);
        return r;
    },
    getRandG1() {
        let r = this.getRandBN();
        let g = PARAM.PAIR.G1mul(PARAM.g1, r);
        return g;
    },
    getRandG2() {
        let r = this.getRandBN();
        let g = PARAM.PAIR.G1mul(PARAM.g2, r);
        return g;
    },
    hashToBN(...points) {
        let all = [];
        let tmp = [];
        points.forEach(p => {
            if (Array.isArray(p)) {
                if (typeof p[0] == "number") {
                    all = all.concat(p);
                    tmp = [];
                } else {
                    p.forEach(pp => {
                        pp.toBytes(tmp);
                        all = all.concat(tmp);
                        tmp = [];
                    });
                }
            } else {
                p.toBytes(tmp);
                all = all.concat(tmp);
                tmp = [];
            }
        });
        let H = new PARAM.ctx.HASH256();
        H.process_array(all);
        let R = H.hash();
        let C = PARAM.BIG.fromBytes(R);
        C.mod(PARAM.order);
        return C;
    },
    genAttrBN(attrs) {
        let HAttr = [];
        let r;

        for (let i = 0; i < attrs.length; i++) {
            let t = this.getRandBN();
            HAttr[i] = t;
        }

        return HAttr;
    },
    genAttrElement(attrs) {
        let HAttr = [];

        for (let i = 0; i < attrs.length; i++) {
            let t = this.getRandG1();
            HAttr[i] = t;
        }

        return HAttr;
    }
};

module.exports = Util;
