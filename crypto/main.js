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
const ECP = ctx.ECP;        // Set pairing interface
const ECP2 = ctx.ECP2;        // Set pairing interface
const BIG = ctx.BIG;        // Set pairing interface
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
    VerifyPi(Nym, pi, n){
        let C = new BIG(0)
        C.copy(pi.C)
        // let _t1 = h_sk^S * Nym^(-C)
        let _t1 = new ctx.ECP()
        _t1 = PAIR.G1mul(this.ipk.h_sk, pi.S)
        _t1.add(PAIR.G1mul(Nym, BIG.modneg(C, order)))

        console.log("[Issuer] _t1: ", _t1.toString())

        let _C = hashToBN(_t1, this.ipk.h_sk, Nym, n)

        console.log("[Issuer] _t1: ", _t1.toString())
        console.log("[Issuer] this.ipk.h_sk: ", this.ipk.h_sk.toString())
        console.log("[Issuer] Nym: ", Nym.toString())
        console.log("[Issuer] n: ", n.toString())
        console.log('[Issuer] _C: ', _C.toString())
        console.log('[Issuer] pi.C: ', pi.C.toString())
        console.log('[Issuer] pi.S: ', pi.S.toString())

        return BIG.comp(pi.C, _C)==0
    },
    Sign(Nym, pi, attrs, n){
        let v = this.VerifyPi(Nym, pi, n)        // verify pi
        console.log('verify result',v)

        return

        // e, s
        let e = getRandBN()
        let s = getRandBN()
        let B = new ctx.ECP() // B = g1 · HRand^s · Nym · MulAll(HAttrs[i]^(Attrs[i]))
        B.copy(g1)
        B.add(PAIR.G1mul(this.ipk.h0, s))
        B.add(Nym)
        for (let i = 0; i < this.ipk.attr.length; i++) {
            B.add(PAIR.G1mul(this.ipk.h[i], attrs[i]))
        }
        let A = new ctx.ECP() // A = B^(1/(e+x))
        let tmp = new ctx.BIG(0)
        tmp.add(e)
        tmp.add(s)
        tmp.invmod(order)
        A = PAIR.G1mul(B, tmp)

        let Credential = {
            A: A,
            B: B,
            e: e,
            s: s,
            Attrs: attrs,
        }

        return Credential
    },
    getIpkBytes(){

    },
}

let User = {
    Setup(attrName, ipk, n){
        // attrs
        let gsk = getRandBN()                       // gsk
        let Nym = PAIR.G1mul(ipk.h_sk, gsk)         // Nym

        let r = getRandBN()                         // r
        let t1 = PAIR.G1mul(ipk.h_sk, r)            // t1

        console.log("[User] t1: ", t1.toString())

        let C = hashToBN(t1, ipk.h_sk, Nym, n)
        console.log("[User] t1: ", t1.toString())
        console.log("[User] ipk.h_sk: ", ipk.h_sk.toString())
        console.log("[User] Nym: ", Nym.toString())
        console.log("[User] n: ", n.toString())
        console.log("[User] C: ", C.toString())

        let tmp = new BIG(0)
        tmp.copy(C)

        let S = ctx.BIG.mul(tmp, gsk)
        S.add(r)
        S.mod(order)

        let pi = {
            C: C,
            S: S,
        }

        console.log("A-pi.C: ", pi.C.toString())

        let attrs = genAttrElement(attrName)

        this.gsk = gsk
        this.Nym = Nym
        this.pi = pi
        this.attrs = attrs
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
    // console.log(Issuer)
    // console.log("publish(ipk)")
    // publish(ipk)

    /* issuer generate a random nonce number */

    let n = getRandBN()
    // console.log(n)
    // console.log("send(n)")
    // send(n)

    /* user */

    User.Setup(AttributeName, Issuer.ipk, n)
    // console.log(User)
    // console.log("send(Nym, pi)")
    // send(Nym, pi)
    console.log("B-User.pi.C: ", User.pi.C.toString())

    Issuer.Sign(User.Nym, User.pi, User.attrs, n)
}