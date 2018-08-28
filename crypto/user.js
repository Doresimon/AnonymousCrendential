'use strict'
const PARAM = require("./param.js");
const UTIL = require("./util.js");

function User(){
    let gsk

    this.GenerateSk = function(){
        let sk = UTIL.getRandBN()
        gsk = sk
    }

    this.SetIpk = function(ipk){
        let pk = {}
        pk.w    =   new PARAM.ECP2()
        pk._g1  =   new PARAM.ECP()
        pk._g2  =   new PARAM.ECP()
        pk.pi   =   {}
        pk.pi.C =   new PARAM.BIG()
        pk.pi.S =   new PARAM.BIG()
        pk.h0   =   new PARAM.ECP()
        pk.h_sk =   new PARAM.ECP()
        pk.h    =   []
        pk.attr =   []

        pk.w.copy(ipk.w)
        pk._g1.copy(ipk._g1)
        pk._g2.copy(ipk._g2)
        pk.pi.C.copy(ipk.pi.C)
        pk.pi.S.copy(ipk.pi.S)
        pk.h0.copy(ipk.h0)
        pk.h_sk.copy(ipk.h_sk)

        if (ipk.h != undefined) {
            for (let i = 0; i < ipk.h.length; i++) {
                pk.h[i] = new PARAM.ECP()
                pk.h[i].copy(ipk.h[i])
            }
        }

        if (ipk.attr != undefined) {
            for (let i = 0; i < ipk.attr.length; i++) {
                pk.attr[i] = ipk.attr[i]
            }
        }

        this.ipk = pk
    }

    this.GenerateCrendentialRequest = function(n){
        if (this.ipk == undefined) {
            console.log("Please set ipk first.")
            return
        }

        const ipk = this.ipk
        let Nym = PARAM.PAIR.G1mul(ipk.h_sk, gsk)         // Nym

        let r = UTIL.getRandBN()                         // r
        let t1 = PARAM.PAIR.G1mul(ipk.h_sk, r)            // t1

        let C = UTIL.hashToBN(t1, ipk.h_sk, Nym, n)

        let S = PARAM.BIG.modmul(C, gsk, PARAM.order)
        S.add(r)
        S.mod(PARAM.order)

        let pi = {
            C: C,
            S: S,
        }

        let attrs = UTIL.genAttrBN(ipk.attr)

        this.Nym = Nym
        this.pi = pi
        this.attrs = attrs

        return
    }

    this.VerifyBBSplus = function (ipk, m, sig, Nym){
        // pk   <- ipk.w
        // m    <- attrs
        // sig  <- (A,E,s)

        // check if 
        // e(A, g2^E * pk) == e(B, g2) 
        // and if 
        // B == g1 * HRand^s * Nym * (h1^m1 * ... * hL^mL).
        // const ipk = this.ipk

        let wg2e = new PARAM.ECP2()
        wg2e.copy(ipk.w)
        wg2e.add(PARAM.PAIR.G2mul(PARAM.g2, sig.e))
        wg2e.affine()                       // ~!!!!use affine() after ECP's mul operation, for pairing.
        let left = PARAM.PAIR.ate(wg2e, sig.A)
        left = PARAM.PAIR.fexp(left);

        let B = new PARAM.ECP()
        B.copy(PARAM.g1)
        B.add(PARAM.PAIR.G1mul(ipk.h0, sig.s))
        B.add(Nym)

        for (let i = 0; i < m.length; i++) {
            B.add(PARAM.PAIR.G1mul(ipk.h[i], m[i]))
        }

        B.affine()
        let right = PARAM.PAIR.ate(PARAM.g2, B)
        right = PARAM.PAIR.fexp(right);

        return left.toString() == right.toString()
    }
    
    this.SetCredential = function(Cred){
        // check attrs
        for (let i = 0; i < this.attrs.length; i++) {
            if (PARAM.BIG.comp(this.attrs[i],Cred.attrs[i])!=0) {
                console.log("attrs in new credential are not matched with our attrs.")
                return false
            }
        }

        let c = {}
        c.attrs = this.attrs
        c.sig = {}
        c.sig.A =   new PARAM.ECP()
        c.sig.B =   new PARAM.ECP()
        c.sig.e =   new PARAM.BIG()
        c.sig.s =   new PARAM.BIG()

        c.sig.A.copy(Cred.sig.A)
        c.sig.B.copy(Cred.sig.B)
        c.sig.e.copy(Cred.sig.e)
        c.sig.s.copy(Cred.sig.s)

        this.Credential = c

        return true
    }

    this.Prove = function (D){
        const ipk = this.ipk
        const Cred = this.Credential

        let r1 = UTIL.getRandBN()                   // r1

        let A_ = PARAM.PAIR.G1mul(Cred.sig.A, r1)         // A'

        let r3 = new PARAM.BIG(0)                         // r3
        r3.copy(r1)
        r3.invmodp(PARAM.order)

        let _e = new PARAM.BIG(0)                         // -e
        _e.copy(Cred.sig.e)
        _e = PARAM.BIG.modneg(_e, PARAM.order)

        let _A = PARAM.PAIR.G1mul(A_, _e)                 // _A
        _A.add(PARAM.PAIR.G1mul(Cred.sig.B, r1))

        let r2 = UTIL.getRandBN()                        // r2
        let _r2 = new PARAM.BIG(0)                        // -r2
        _r2.copy(r2)
        _r2 = PARAM.BIG.modneg(_r2, PARAM.order)

        let B_ = PARAM.PAIR.G1mul(Cred.sig.B, r1)   // B'
        B_.add(PARAM.PAIR.G1mul(ipk.h0, _r2))

        let s_ = PARAM.BIG.modmul(r2, r3, PARAM.order)          // s'
        s_ = PARAM.BIG.modneg(s_, PARAM.order)
        s_.add(Cred.sig.s)
        s_.mod(PARAM.order)
        
        let r_a = []                                // r_a[]
        for (let i = 0; i < D.length; i++) {
            if (D[i]==0) {
                r_a[i] = UTIL.getRandBN()
            }else{
                r_a[i] = false
            }
        }

        let r_e = UTIL.getRandBN()
        let r_r2 = UTIL.getRandBN()
        let r_r3 = UTIL.getRandBN()
        let r_s_ = UTIL.getRandBN()
        let r_sk = UTIL.getRandBN()

        let E = PARAM.PAIR.G1mul(ipk.h_sk, r_sk)                // E

        let t1 = PARAM.PAIR.G1mul(A_, r_e)                      // t1
        t1.add(PARAM.PAIR.G1mul(ipk.h0, r_r2))

        let t2 = PARAM.PAIR.G1mul(B_, r_r3)                     // t2
        t2.add(PARAM.PAIR.G1mul(ipk.h0, r_s_))
        t2.add(PARAM.PAIR.G1mul(E, new PARAM.BIG(-1)))
        for (let i = 0; i < r_a.length; i++) {
            if(r_a[i]!=false){
                t2.add(PARAM.PAIR.G1mul(ipk.h[i], r_a[i]))
            }
        }

        // c' = H(A', _A, B', nym, t1, t2, g1, HRand, h1, ... , hL, w)
        let c_ = UTIL.hashToBN(A_, _A, B_, this.Nym, t1, t2, PARAM.g1, ipk.h0, ipk.h, ipk.w) 

        let nonce = UTIL.getRandBN()
        // c = H(nonce, c', (D, I))
        let c = UTIL.hashToBN(nonce, c_, D, this.attrs)

        let s_sk = new PARAM.BIG(0)
        s_sk.copy(r_sk)
        s_sk.add(PARAM.BIG.modmul(c, gsk, PARAM.order))
        s_sk.mod(PARAM.order)


        let s_a = []
        for (let i = 0; i < D.length; i++) {
            if (D[i]==0) {
                s_a[i] = new PARAM.BIG(0)
                s_a[i].copy(r_a[i])
                s_a[i].sub(PARAM.BIG.modmul(c, this.attrs[i], PARAM.order))
                s_a[i].mod(PARAM.order)
            }else{
                s_a[i] = false
            }
        }

        let s_e = new PARAM.BIG(0)
        s_e.copy(r_e)
        s_e.sub(PARAM.BIG.modmul(c, Cred.sig.e, PARAM.order))
        s_e.mod(PARAM.order)

        let s_r2 = new PARAM.BIG(0)
        s_r2.copy(r_r2)
        s_r2.add(PARAM.BIG.modmul(c, r2, PARAM.order))
        s_r2.mod(PARAM.order)

        let s_r3 = new PARAM.BIG(0)
        s_r3.copy(r_r3)
        s_r3.add(PARAM.BIG.modmul(c, r3, PARAM.order))
        s_r3.mod(PARAM.order)

        let s_s_ = new PARAM.BIG(0)
        s_s_.copy(r_s_)
        s_s_.sub(PARAM.BIG.modmul(c, s_, PARAM.order))
        s_s_.mod(PARAM.order)

        let pi = {
            c:      c,
            s_sk:   s_sk,
            s_a:    s_a,
            s_e:    s_e,
            s_r2:   s_r2,
            s_r3:   s_r3,
            s_s_:   s_s_,
            nonce:  nonce,
        }

        let proof = {
            A_:     A_,
            _A:     _A,
            B_:     B_,
            nym:    this.Nym,
            pi:     pi,
        }

        return proof
    }

    this.Verify = function (proof, D, attrs){
        const ipk = this.ipk
        
        let one = new PARAM.ECP(1)
        if (proof.A_.equals(one)) {
            console.log("A' == 1 return true, verify failed.")
            return false
        }

        let A_ = new PARAM.ECP()
        A_.copy(proof.A_)
        let w = new PARAM.ECP2()
        w.copy(ipk.w)
        let _A = new PARAM.ECP()
        _A.copy(proof._A)
        let g2_dup = new PARAM.ECP2()
        g2_dup.copy(PARAM.g2)

        A_.affine()
        w.affine()
        _A.affine()
        g2_dup.affine()

        let left = PARAM.PAIR.ate(w, A_)
        let right = PARAM.PAIR.ate(g2_dup, _A)

        left = PARAM.PAIR.fexp(left)
        right = PARAM.PAIR.fexp(right)

        if (!left.equals(right)) {
            console.log("e(A', w) == e(_A, g2) return false, verify failed.")
            return false
        }

        // ok
        _A.copy(proof._A)
        let _t1 = PARAM.PAIR.G1mul(A_, proof.pi.s_e) 
        _t1.add(PARAM.PAIR.G1mul(ipk.h0, proof.pi.s_r2))
        _A.sub(proof.B_)
        _t1.add(PARAM.PAIR.G1mul(_A, PARAM.BIG.modneg(proof.pi.c, PARAM.order)))

        // ok
        // ~t2 : (B')^s_r3 · HRand^s_s' · HSk^(-s_sk) · MulAll(hi^(-s_ai)) · (g1·MulAll(hi^ai))^(-c)
        let _t2 = PARAM.PAIR.G1mul(proof.B_, proof.pi.s_r3)
        _t2.add(PARAM.PAIR.G1mul(ipk.h0, proof.pi.s_s_))
        _t2.add(PARAM.PAIR.G1mul(ipk.h_sk, PARAM.BIG.modneg(proof.pi.s_sk, PARAM.order)))

        let sum = new PARAM.ECP()
        sum.copy(PARAM.g1)
        for (let i = 0; i < D.length; i++) {
            if (D[i]==0) {
                _t2.add(PARAM.PAIR.G1mul(ipk.h[i], proof.pi.s_a[i]))
            }else{
                sum.add(PARAM.PAIR.G1mul(ipk.h[i], attrs[i]))
            }   
                   
        }

        _t2.add(PARAM.PAIR.G1mul(sum, PARAM.BIG.modneg(proof.pi.c, PARAM.order)))

        let c1 = UTIL.hashToBN(proof.A_, proof._A, proof.B_, proof.nym, _t1, _t2, PARAM.g1, ipk.h0, ipk.h, ipk.w)
        let c2 = UTIL.hashToBN(proof.pi.nonce, c1, D, attrs)

        if (PARAM.BIG.comp(c2, proof.pi.c)!=0) {
            console.log("c == H(nonce, H(A', _A, B', nym, ~t1, ~t2, g1, HRand, h1, ... , hL, w), (D, I)) return false, verify failed.")
            return false
        }

        return true
    }
}

module.exports = User