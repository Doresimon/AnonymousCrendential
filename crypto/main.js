'use strict'

const CTX = require("milagro-crypto-js");
const crypto = require('crypto');

const func = {
    get_g1(ctx) {
        let g1 = new ctx.ECP(0);    // new G1
        let x = new ctx.BIG(0);
        let y = new ctx.BIG(0);
        x.rcopy(ctx.ROM_CURVE.CURVE_Gx);
        y.rcopy(ctx.ROM_CURVE.CURVE_Gy);
        g1.setxy(x,y);
        return g1
    },
    get_g2(ctx) {
        let g2 = new ctx.ECP2(0);
        let x = new ctx.BIG(0);
        let y = new ctx.BIG(0);
        let qx = new ctx.FP2(0);
        let qy = new ctx.FP2(0);
        x.rcopy(ctx.ROM_CURVE.CURVE_Pxa);
        y.rcopy(ctx.ROM_CURVE.CURVE_Pxb);
        qx.bset(x, y);
        x.rcopy(ctx.ROM_CURVE.CURVE_Pya);
        y.rcopy(ctx.ROM_CURVE.CURVE_Pyb);
        qy.bset(x, y);
        g2.setxy(qx, qy);
        return g2
    },
    get_order(ctx){
        let r = new ctx.BIG(0);     // new BN
        r.rcopy(ctx.ROM_CURVE.CURVE_Order);
        return r
    }
}

const curve = 'BN254'
const ctx = new CTX(curve);   // set curve
const PAIR = ctx.PAIR;        // Set pairing interface
const ECP2 = ctx.ECP2;        // Set pairing interface
const rng = new ctx.RAND();   //new random number generator

const g1 = func.get_g1(ctx)       // g1
const g2 = func.get_g2(ctx)       // g2
const order = func.get_order(ctx) // n



function getRandBN(){
    const buf = crypto.randomBytes(256);
    rng.seed(256, buf);
    let r = ctx.BIG.randomnum(order, rng);
    return r
}
function getRandG1(){
    const buf = crypto.randomBytes(256);
    rng.seed(256, buf);
    let r = ctx.BIG.randomnum(order, rng);
    let g = PAIR.G1mul(g1, r)
    return g
}
function getRandG2(){
    const buf = crypto.randomBytes(256);
    rng.seed(256, buf);
    let r = ctx.BIG.randomnum(order, rng);
    let g = PAIR.G1mul(g2, r)
    return g
}
function hashToBN(...points){
    let all = []
    let tmp = []
    points.forEach(p => {
        p.toBytes(tmp)
        all = all.concat(tmp)
        tmp = []
    });
    let H = new ctx.HASH256();
    H.process_array(all);
    let R = H.hash();
    let C = ctx.BIG.fromBytes(R)
    return C
}
function genAttrElement(attrs){
    let HAttr = []
    let r

    for (let i = 0; i < attrs.length; i++) {
        let t = getRandG1()
        HAttr[i] = t
    }

    return HAttr
}

let Issuer = {
    Setup(AttributeName){
        let HAttr = genAttrElement(AttributeName)

        let x = getRandBN()         // isk
        let w = PAIR.G2mul(g2, x)   // w

        let r = getRandBN()         // random number
        let _g1 =  PAIR.G1mul(g1, r)
        let _g2 =  PAIR.G1mul(_g1, x)

         // zkp - pi
        r = getRandBN()
        let t1 = PAIR.G2mul(g2, r)
        let t2 = PAIR.G1mul(_g1, r)

        let C = hashToBN(t1, t2, g2, _g1, w, _g2)

        let S = ctx.BIG.modmul(C, x, order)
        S.add(r)
        S.mod(order)

        let pi = {
            C: C,
            S: S,
        }

        // rand
        let h0 = getRandG1()
        let h_sk = getRandG1()

        let isk = new ctx.BIG()
        isk.copy(x)

        // let ipk = {
        //     w: new ctx.ECP2(),
        //     _g1: new ctx.ECP(),
        //     _g2: new ctx.ECP(),
        //     attr: AttributeName,
        //     h: [],
        //     h0: new ctx.ECP(),
        //     h_sk: new ctx.ECP(),
        //     pi: pi,
        // }
        // let ipk = {
        //     w: w.toString(),
        //     _g1: _g1.toString(),
        //     _g2: _g2.toString(),
        //     attr: AttributeName,
        //     h: [],
        //     h0: h0.toString(),
        //     h_sk: h_sk.toString(),
        //     pi: pi,
        // }
        let ipk = {
            w: w,
            _g1: _g1,
            _g2: _g2,
            attr: AttributeName,
            h: [],
            h0: h0,
            h_sk: h_sk,
            pi: pi,
        }

        HAttr.forEach(a => {
            ipk.h.push(a)
        });

        this.isk = isk
        this.ipk = ipk
    },
    getIpkBytes(){

    },
}

let User = {
    Setup(attrName, ipk, n){
        // attrs
        let gsk = getRandBN()                       // gsk
        let Q = PAIR.G1mul(ipk.h_sk, gsk)        // Q

        let r = getRandBN()                         // r
        let t1 = PAIR.G1mul(ipk.h_sk, r)         // t1

        let C = hashToBN(t1, ipk.h_sk, Q, n)

        let S = ctx.BIG.modmul(C, gsk, order)
        S.add(r)
        S.mod(order)

        let pi = {
            C: C,
            S: S,
        }

        let attrs = genAttrElement(attrName)

        this.gsk = gsk
        this.Q = Q
        this.pi = pi
        this.atts = attrs
    },
    SetIpk(ipk){
        let w = ECP2.fromBytes(ipk.w)
    },
}

// /* setup */
main()

function main(){
    /* public parameter */
    let AttributeName = [
        '24',
        'master',
        'male',
        'handsome',
    ]
    /* issuer setup */
    Issuer.Setup(AttributeName)
    console.log(Issuer)

    /* issuer generate a random nonce number */

    let n = getRandBN()
    console.log(n)

    /* user */

    User.Setup(AttributeName, Issuer.ipk, n)
    console.log(User)
}