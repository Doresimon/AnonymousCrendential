const CTX = require("milagro-crypto-js");

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

const Param = {
    curve:  curve,
    ctx:    ctx,
    g1:     g1,
    g2:     g2,
    rng:    rng,
    order:  order,
    PAIR:   PAIR,
    ECP:    ECP,
    ECP2:   ECP2,
    BIG:    BIG,
}

module.exports = Param