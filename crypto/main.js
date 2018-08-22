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
    rng.clean();
    rng.seed(256, buf);
    let r = ctx.BIG.randomnum(order, rng);
    return r
}
function getRandG1(){
    let r = getRandBN()
    let g = PAIR.G1mul(g1, r)
    return g
}
function getRandG2(){
    let r = getRandBN()
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
    C.mod(order)
    return C
}
function genAttrBN(attrs){
    let HAttr = []
    let r

    for (let i = 0; i < attrs.length; i++) {
        let t = getRandBN()
        HAttr[i] = t
    }

    return HAttr
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

        let h0 = getRandG1()
        let h_sk = getRandG1()

        let isk = new ctx.BIG()
        isk.copy(x)

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

        let _C = hashToBN(_t1, this.ipk.h_sk, Nym, n)

        return BIG.comp(pi.C, _C)==0
    },
    Sign(Nym, pi, attrs, n){
        let v = this.VerifyPi(Nym, pi, n)        // verify pi
        console.log('verify result = ',v)
        if (!v) {   return false }
        
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
        let tmp = new ctx.BIG() //tmp = (1/(e+x))
        tmp.copy(e)
        tmp.add(this.isk) // !!!!!!!!!!!
        tmp.invmodp(order)

        A = PAIR.G1mul(B, tmp)

        let Credential = {
            sig:{
                A: A,
                // B: B, 
                e: e,
                s: s,
            },
            Attrs: attrs,
        }
        return Credential
    },
    getIpkBytes(){},
}

let User = {
    Setup(attrName, ipk, n){
        // attrs
        let gsk = getRandBN()                       // gsk
        let Nym = PAIR.G1mul(ipk.h_sk, gsk)         // Nym

        let r = getRandBN()                         // r
        let t1 = PAIR.G1mul(ipk.h_sk, r)            // t1

        let C = hashToBN(t1, ipk.h_sk, Nym, n)

        let S = ctx.BIG.modmul(C, gsk, order)
        S.add(r)
        S.mod(order)

        let pi = {
            C: C,
            S: S,
        }

        let attrs = genAttrBN(attrName)

        this.gsk = gsk
        this.Nym = Nym
        this.pi = pi
        this.attrs = attrs

        return
    },
    VerifyBBSplus(ipk, m, sig, Nym){
        // pk   <- ipk.w
        // m    <- attrs
        // sig  <- (A,E,s)

        // check if 
        // e(A, g2^E * pk) == e(B, g2) 
        // and if 
        // B == g1 * HRand^s * Nym * (h1^m1 * ... * hL^mL).

        let wg2e = new ECP2()
        wg2e.copy(ipk.w)
        wg2e.add(PAIR.G2mul(g2, sig.e))
        wg2e.affine()                       // ~!!!!use affine() after ECP's mul operation, for pairing.
        let left = PAIR.ate(wg2e, sig.A)
        left = PAIR.fexp(left);

        let B = new ECP()
        B.copy(g1)
        B.add(PAIR.G1mul(ipk.h0, sig.s))
        B.add(Nym)

        for (let i = 0; i < m.length; i++) {
            B.add(PAIR.G1mul(ipk.h[i], m[i]))
        }

        B.affine()
        let right = PAIR.ate(g2, B)
        right = PAIR.fexp(right);

        return left.toString() == right.toString()
    },
}

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
    console.log("Issuer.publish(ipk)")

    /* issuer generate a random nonce number */
    let n = getRandBN()
    console.log("Issuer.send(n)")

    /* user */
    User.Setup(AttributeName, Issuer.ipk, n)
    console.log("User.send(Nym, pi)")
    
    let Credential = Issuer.Sign(User.Nym, User.pi, User.attrs, n)
    console.log("Issuer.send(Credential)")

    let uv = User.VerifyBBSplus(Issuer.ipk, Credential.Attrs, Credential.sig, User.Nym)
    console.log("User.verify(Credential)", uv)
}