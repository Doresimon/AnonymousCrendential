'use strict'

let CTX = require("milagro-crypto-js");
const crypto = require('crypto');

// /* setup */
// main()
a()

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

function a(){    
  // set curve
  let curve = 'BN254'
  let ctx = new CTX(curve);

  let g1 = new ctx.ECP(0);    // new G1
  let g2 = new ctx.ECP2(0);   // new G2
  // let gt = new ctx.FP12(0);   // new GT

  let order = new ctx.BIG(0);     // new BN
  let x = new ctx.BIG(0);
  let y = new ctx.BIG(0);
  let qx = new ctx.FP2(0);
  let qy = new ctx.FP2(0);
  
  // Set curve order
  order.rcopy(ctx.ROM_CURVE.CURVE_Order);
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

  x = getRandBN()
  y = getRandBN()

  /* ################################## */

  let Gx = ctx.PAIR.G1mul(g1,x);
  let Qy = ctx.PAIR.G2mul(g2,y);

  let Gy = ctx.PAIR.G1mul(g1,y);
  let Qx = ctx.PAIR.G2mul(g2,x);

  let left = ctx.PAIR.ate(Qy, Gx);
  left = ctx.PAIR.fexp(left);
  let right = ctx.PAIR.ate(Qx, Gy);
  right = ctx.PAIR.fexp(right);

  console.log("Test that e(g1^x, g2^y) = e(g1^y, g2^x)")
  console.log(left.toString()==right.toString())

  /* ################################## */

  let z = new ctx.BIG(0)
  z.add(x)
  z.add(y)
  let gx = ctx.PAIR.G1mul(g1,x);
  let gy = ctx.PAIR.G1mul(g1,y);
  left = new ctx.ECP()
  left.copy(gx)
  left.add(gy)

  right = ctx.PAIR.G1mul(g1,z);

  console.log("Test that g1^x * g1^y = g1^(x+y)")
  console.log(left.toString()==right.toString())

  /* ################################## */

  gx = ctx.PAIR.G2mul(g2,x);
  gy = ctx.PAIR.G2mul(g2,y);
  left = new ctx.ECP2()
  left.copy(gx)
  left.add(gy)

  right = ctx.PAIR.G2mul(g2,z);

  console.log("Test that g2^x * g2^y = g2^(x+y)")
  console.log(left.toString()==right.toString())


  /* ################################## */
  y.copy(x)
  y.invmodp(order)

  y = ctx.BIG.mul(y, x)
  y.mod(order)

  console.log("Test that 1/x * x = 1")
  console.log(y.toString()=="1")


  /* ################################## */
  x = getRandBN()
  y = getRandBN()
  y.copy(x)
  y.invmodp(order)

  gx = ctx.PAIR.G1mul(g1,x);
  gy = ctx.PAIR.G1mul(gx,y);
  left = new ctx.ECP()
  left.copy(gy)

  console.log("Test that (g1^x)^(1/x) = g1")
  console.log(left.toString()==g1.toString())


  /* ################################## */
  x = getRandBN()
  y = getRandBN()
  y.copy(x)
  y.invmodp(order)

  gx = ctx.PAIR.G2mul(g2,x);
  gy = ctx.PAIR.G2mul(gx,y);
  left = new ctx.ECP2()
  left.copy(gy)

  console.log("Test that (g2^x)^(1/x) = g2")
  console.log(left.toString()==g2.toString())

  /* ################################## */

  x = getRandBN()
  y = getRandBN()

  let sum = new ctx.BIG()
  sum.copy(x)
  sum.add(y)
  sum.mod(order)
  let invsum = new ctx.BIG()
  invsum.copy(sum)
  invsum.invmodp(order)

  let L1 = ctx.PAIR.G1mul(g1,invsum);
  let L2 = ctx.PAIR.G2mul(g2,sum);

  left = ctx.PAIR.ate(L2, L1);
  left = ctx.PAIR.fexp(left);
  right = ctx.PAIR.ate(g2, g1);
  right = ctx.PAIR.fexp(right);

  console.log("Test that e(g1^(1/(x+y)), g2^(x+y)) = e(g1, g2)")
  console.log(left.toString()==right.toString())


  /* ################################## */

  x = getRandBN()
  y = getRandBN()

  sum = new ctx.BIG()
  sum.copy(x)
  sum.add(y)
  sum.mod(order)
  invsum = new ctx.BIG()
  invsum.copy(sum)
  invsum.invmodp(order)

  L1 = ctx.PAIR.G1mul(g1,invsum);
  let g2x = ctx.PAIR.G2mul(g2,x);
  let g2y = ctx.PAIR.G2mul(g2,y);
  L2 = new ctx.ECP2()
  L2.copy(g2x)
  L2.add(g2y)
  L2.affine() // !!! important

  left = ctx.PAIR.ate(L2, L1);
  left = ctx.PAIR.fexp(left);
  right = ctx.PAIR.ate(g2, g1);
  right = ctx.PAIR.fexp(right);

  console.log("Test that e(g1^(1/(x+y)), g2^x * g2^y = e(g1, g2)")
  console.log(left.toString()==right.toString())

}

function getRandBN(){
  let curve = 'BN254'
  let ctx = new CTX(curve);
  let rng = new ctx.RAND();
  const buf = crypto.randomBytes(256);
  rng.clean();
  rng.seed(256, buf);
  let order = new ctx.BIG(0);     // new BN
  order.rcopy(ctx.ROM_CURVE.CURVE_Order);
  let r = ctx.BIG.randomnum(order, rng);
  return r
}