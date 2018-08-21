'use strict'

const CTX = require("milagro-crypto-js");
const crypto = require('crypto');

let curve = 'BN254'
let ctx = new CTX(curve);   // set curve
let PAIR = ctx.PAIR;        // Set pairing interface
let ECP2 = ctx.ECP2;        // Set pairing interface
let rng = new ctx.RAND();   //new random number generator

let g1 = get_g1()       // g1
let g2 = get_g2()       // g2
let order = get_order() // n



function get_g1(){
    let g1 = new ctx.ECP(0);    // new G1
    let x = new ctx.BIG(0);
    let y = new ctx.BIG(0);
    x.rcopy(ctx.ROM_CURVE.CURVE_Gx);
    y.rcopy(ctx.ROM_CURVE.CURVE_Gy);
    g1.setxy(x,y);
    return g1
}
function get_g2(){
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
}
function get_order(){
    let r = new ctx.BIG(0);     // new BN
    r.rcopy(ctx.ROM_CURVE.CURVE_Order);
    return r
}
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
            ipk.attr.push(a.toString())
        });

        this.isk = isk
        this.ipk = ipk
    },
    getIpkBytes(){

    },
}

let User = {
    Setup(attrs, ipk){
        // attrs
        let gsk = getRandBN()                       // gsk
        let Q = PAIR.mul(this.ipk.h_sk, gsk)        // Q
    },
    SetIpk(ipk){
        let w = ECP2.fromBytes(ipk.w)

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
    },
}

// /* setup */
main()

function main(){
    /* public parameter */

    // let g1 = get_g1()       // g1
    // let g2 = get_g2()       // g2
    // let order = get_order() // n

    let AttributeName = [
        '24',
        'master',
        'male',
        'handsome',
    ]

    // let HAttr = genAttrElement(AttributeName)

    /* issuer setup */

    Issuer.Setup(AttributeName)

    console.log(Issuer)

    // let x = getRandBN()  // isk
    // let w = PAIR.G2mul(g2, x)

    
    // let r = getRandBN()      // random number
    // let _g1 =  PAIR.G1mul(g1, r)
    // let _g2 =  PAIR.G1mul(_g1, x)

    
    // console.log("g1:: ", g1.toString())
    // console.log("g2:: ", g2.toString())
    // console.log("order:: ", order.toString())


    // // zkp - pi
    // r = getRandBN()
    // let t1 = PAIR.G2mul(g2, r)
    // let t2 = PAIR.G1mul(_g1, r)

    // let C = hashToBN(t1, t2, g2, _g1, w, _g2)

    // let S = ctx.BIG.modmul(C, x, order)
    // S.add(r)
    // S.mod(order)

    // let pi = {
    //     C: C.toString(),
    //     S: S.toString(),
    // }

    // // rand
    // let h0 = getRandG1()
    // let h_sk = getRandG1()

    // let isk = x.toString()
    // let ipk = {
    //     w: w.toString(),
    //     _g1: _g1.toString(),
    //     _g2: _g2.toString(),
    //     AttributeName: AttributeName,
    //     HAttr: [],
    //     HRand: h0.toString(),
    //     HSk: h_sk.toString(),
    // }

    // HAttr.forEach(a => {
    //     ipk.HAttr.push(a.toString())
    // });

    // console.log("pi:: ", pi)
    // console.log("isk:: ", isk)
    // console.log("ipk:: ", ipk)


    // let 

    // let pi = {
    //     C: '',
    //     S: '',
    // }

    // console.log("all:: ", all.toString())
    // console.log("order:: ", order.toString())
    // console.log("C:: ", C.toString())
    // console.log("r:: ", r.toString())
    // console.log("S:: ", S.toString())


//     let p = new Param()

//     console.log(Param)
//     console.log(p)
//     console.log(p.toString())
// }
//     console.log("## 1")
    
//     await mcl.init(mcl.BN254)

//     let param = {
//         g1: new mcl.G1(), 
//         g2: new mcl.G2(),
//         h:  [],
//         HRand:  new mcl.G1(),
//     }    

//     let randFr = new mcl.Fr()

//     console.log("## 2")

//     let r = new mcl.Fr()
//     r.setByCSPRNG()

//     param.g1.setHashOf("g1")
//     param.g2.setHashOf("g2")
//     param.HRand = mcl.mul(param.g1, r)

//     let x = new mcl.Fr()
//     x.setByCSPRNG()

//     let w = mcl.mul(param.g2, x)

//     randFr.setByCSPRNG()
//     let _g1 = mcl.mul(param.g1, randFr)

//     let _g2 = mcl.mul(_g1, x)

//     // console.log(param)

//     // zkpok

//     randFr.setByCSPRNG()

//     let t1 = mcl.mul(param.g2, randFr)
//     let t2 = mcl.mul(_g1, randFr)

//     let J = t1.getStr() + t2.getStr() + param.g2.getStr() + _g1.getStr() + w.getStr() + _g2.getStr()

//     let C = new mcl.Fr()
//     C.setHashOf(J)

//     let S = mcl.add(randFr, mcl.mul(C, x))

//     // console.log("S:: ",S)
//     // console.log("S..:: ",S.getStr(16))


//     let issuer = {
//         w:      w,
//         _g1:    _g1,
//         _g2:    _g2,
//         pi:     {
//             C: C,
//             S: S,
//         },
//         // HAttrs:             HAttrs,
//         // AttributeNames:     AttributeNames,
//         // HRand:  HRand,
//         // Hsk:    Hsk,
//         isk:    x,
//     }

//     // console.log("issuer:: ", issuer)
//     console.log(issuer.pi.C.getStr(16))

//     // verify

//     // let _t1 = g2^S * w^(-c)
//     let _t1 = mcl.add(mcl.mul(param.g2, issuer.pi.S), mcl.mul(issuer.w, mcl.neg(issuer.pi.C)))

//     // let _t2 = _g1^S * _g2^(-c)
//     let _t2 = mcl.add(mcl.mul(issuer._g1, issuer.pi.S), mcl.mul(issuer._g2, mcl.neg(issuer.pi.C)))

//     // let _P = _t1 || _t2 || g2 || _g1 || w || _g2
//     let _P = _t1.getStr() + _t2.getStr() + param.g2.getStr() + issuer._g1.getStr() + issuer.w.getStr() + issuer._g2.getStr()

//     let _C = mcl.hashToFr(_P)

//     // console.log(issuer.C.getStr(16))
//     console.log(_C.getStr(16))

//     // use C to compare with _C, which was calculated just now
//     if (issuer.pi.C.getStr(16) == _C.getStr(16)) {
//         console.log("true")
//         // return true
//     } else {
//         console.log("false")
//         // return false
//     } 




//     // console.log("issuer:: ", issuer)
//     console.log("DONE")
// }

// function IssuerSetup(){

}