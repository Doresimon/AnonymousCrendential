'use strict'

let CTX = require("milagro-crypto-js");

// /* setup */
main()

function main(){
    // set curve
    let curve = 'BN254'
    let ctx = new CTX(curve);

    // Set pairing interface
    let PAIR = ctx.PAIR;

    let g1 = new ctx.ECP(0);    // new G1
    let g2 = new ctx.ECP2(0);   // new G2
    let gt = new ctx.FP12(0);   // new GT


    let r = new ctx.BIG(0);     // new BN
    let x = new ctx.BIG(0);
    let y = new ctx.BIG(0);
    let qx = new ctx.FP2(0);
    let qy = new ctx.FP2(0);

    let rng = new ctx.RAND();   //new random number generator

    // rng seed
    let RAW = [];
    rng.clean();
    for (i = 0; i < 100; i++) RAW[i] = i;
    rng.seed(100, RAW);

    // Set generator of G1
    x.rcopy(ctx.ROM_CURVE.CURVE_Gx);
    y.rcopy(ctx.ROM_CURVE.CURVE_Gy);
    g1.setxy(x,y);

    // Set generator of G2
    x.rcopy(ctx.ROM_CURVE.CURVE_Pxa);
    y.rcopy(ctx.ROM_CURVE.CURVE_Pxb);
    qx.bset(x, y);
    x.rcopy(ctx.ROM_CURVE.CURVE_Pya);
    y.rcopy(ctx.ROM_CURVE.CURVE_Pyb);
    qy.bset(x, y);
    g2.setxy(qx, qy);

    // Set curve order
    r.rcopy(ctx.ROM_CURVE.CURVE_Order);

    // random number
    s = ctx.BIG.randomnum(r,rng);


    //G1, G2, GT mul
    g1_s = PAIR.G1mul(g1,s);
    g2_s = PAIR.G2mul(g2,s);
    gt_s = PAIR.GTpow(gt,s);

    // pair
    e_g1_g2 = PAIR.ate(g1, g2);
    e_g1_g2 = PAIR.fexp(e_g1_g2);

    console.log(g1.toString())
    console.log(g2.toString())

    //copy 
    g1_s.copy(g1)   // G1
    g1_s.add(g1)    // G1
    g1_s.mul(g1)    // Fp

}