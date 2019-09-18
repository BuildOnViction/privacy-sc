import {ECCMath} from "./ECCMath.sol";

/**
 * @title Secp256k1
 *
 * secp256k1 implementation.
 *
 * The library implements 'Curve' and 'codec/ECCConversion', but since it's a library
 * it does not actually extend the contracts. This is a Solidity thing and will be
 * dealt with later.
 *
 * @author Andreas Olofsson (androlo1980@gmail.com)
 */
library Secp256k1 {

    // TODO separate curve from crypto primitives?
    uint256 constant n = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47;
    // Field size
    uint constant pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Base point (generator) G
    uint constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    uint constant Hx = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0;
    uint constant Hy = 0x31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904;

    // Order of G
    uint constant nn = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // Cofactor
    // uint constant hh = 1;

    // Maximum value of s
    uint constant lowSmax = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // For later
    // uint constant lambda = "0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72";
    // uint constant beta = "0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee";

    /// @dev See Curve.onCurve
    function onCurve(uint[2] memory P) internal view returns (bool) {
        uint p = pp;
        if (0 == P[0] || P[0] == p || 0 == P[1] || P[1] == p)
            return false;
        uint LHS = mulmod(P[1], P[1], p);
        uint RHS = addmod(mulmod(mulmod(P[0], P[0], p), P[0], p), 7, p);
        return LHS == RHS;
    }

    function onCurveXY(uint X, uint Y) internal view returns (bool) {
        uint[2] memory P;
        P[0] = X;
        P[1] = Y;
        return onCurve(P);
    }

    function onCurveCompress(uint8 yBit, uint x) internal view returns(bool) {
        uint[2] memory _decompressed = decompress(yBit, x);
        (uint8 _yBit, uint _x) = compress(_decompressed);
        return (_yBit == yBit && _x == x);
    }

    /// @dev See Curve.isPubKey
    function isPubKey(uint[2] memory P) internal view returns (bool isPK) {
        isPK = onCurve(P);
    }

    /// @dev See Curve.validateSignature
    function validateSignature(uint message, uint[2] rs, uint[2] Q) internal view returns (bool) {
        uint n = nn;
        uint p = pp;
        if(rs[0] == 0 || rs[0] >= n || rs[1] == 0 || rs[1] > lowSmax)
            return false;
        if (!isPubKey(Q))
            return false;

        uint sInv = ECCMath.invmod(rs[1], n);
        uint[3] memory u1G = _mul(mulmod(message, sInv, n), [Gx, Gy]);
        uint[3] memory u2Q = _mul(mulmod(rs[0], sInv, n), Q);
        uint[3] memory P = _add(u1G, u2Q);

        if (P[2] == 0)
            return false;

        uint Px = ECCMath.invmod(P[2], p); // need Px/Pz^2
        Px = mulmod(P[0], mulmod(Px, Px, p), p);
        return Px % n == rs[0];
    }

    function pedersenCommitment(uint256 _mask, uint256 _val) internal view returns (uint8 yBit, uint x) {
        uint[2] memory H;
        uint[2] memory G;
        H[0] = Hx;
        H[1] = Hy;
        G[0] = Gx;
        G[1] = Gy;
        uint[3] memory retH = _mul(_val, H);
        uint[3] memory retG = _mul(_mask, G);
        retH = _add(retH, retG);
        (uint _x, uint _y) = toAffinePoint(retH[0], retH[1], retH[2]);
        (yBit, x) = compressXY(_x, _y);
    }

    function pedersenCommitmentDecompress(uint256 _mask, uint256 _val) internal view returns (uint8 yBit, uint x) {
        uint[2] memory H;
        uint[2] memory G;
        H[0] = Hx;
        H[1] = Hy;
        G[0] = Gx;
        G[1] = Gy;
        uint[3] memory retH = _mul(_val, H);
        uint[3] memory retG = _mul(_mask, G);
        retH = _add(retH, retG);
        (uint _x, uint _y) = toAffinePoint(retH[0], retH[1], retH[2]);
        (yBit, x) = compressXY(_x, _y);
    }

    function mulWithH(uint256 val) internal view returns (uint8 yBit, uint x) {
        uint[2] memory H;
        H[0] = Hx;
        H[1] = Hy;
        uint[3] memory ret = _mul(val, H);
        (uint _x, uint _y) = toAffinePoint(ret[0], ret[1], ret[2]);
        (yBit, x) = compressXY(_x, _y);
    }

    /// @dev See Curve.compress
    function compress(uint[2] memory P) internal view returns (uint8 yBit, uint x) {
        assert(P.length == 2);
        x = P[0];
        yBit = P[1] & 1 == 1 ? 1 : 0;
    }

    function compressXY(uint _x, uint _y) internal view returns (uint8 yBit, uint x) {
        x = _x;
        yBit = _y & 1 == 1 ? 1 : 0;
    }

    /// @dev See Curve.decompress
    function decompress(uint8 yBit, uint x) internal view returns (uint[2] memory P) {
        uint p = pp;
        uint y2 = addmod(mulmod(x, mulmod(x, x, p), p), 7, p);
        uint y_ = ECCMath.expmod(y2, (p + 1) / 4, p);
        uint cmp = yBit ^ y_ & 1;
        P[0] = x;
        P[1] = (cmp == 0) ? y_ : p - y_;
    }

    /// @dev See Curve.decompress
    function decompressXY(uint8 yBit, uint x) internal view returns (uint X, uint Y) {
        uint p = pp;
        uint y2 = addmod(mulmod(x, mulmod(x, x, p), p), 7, p);
        uint y_ = ECCMath.expmod(y2, (p + 1) / 4, p);
        uint cmp = yBit ^ y_ & 1;
        X = x;
        Y = (cmp == 0) ? y_ : p - y_;
    }

    // Transform from affine to projective coordinates
    function toProjectivePoint(uint256 x0, uint256 y0) internal view returns(uint256, uint256, uint256)
    {
        uint256 z1 = addmod(0, 1, n);
        uint256 x1 = mulmod(x0, z1, n);
        uint256 y1 = mulmod(y0, z1, n);
        return (x1,y1,z1);
    }

    // Returns the inverse in the field of modulo n
    function inverse(uint256 num) internal view
    returns(uint256 invNum)
    {
        uint256 t = 0;
        uint256 newT = 1;
        uint256 r = n;
        uint256 newR = num;
        uint256 q;
        while (newR != 0) {
            q = r / newR;

            (t, newT) = (newT, addmod(t, (n - mulmod(q, newT,n)), n));
            (r, newR) = (newR, r - q * newR );
        }

        invNum = t;
    }

    // Transform from projective to affine coordinates
    function toAffinePoint(uint256 x0, uint256 y0, uint256 z0) internal view
    returns(uint256 x1, uint256 y1)
    {
        uint256 z0Inv;
        z0Inv = inverse(z0);
        x1 = mulmod(x0, z0Inv, n);
        y1 = mulmod(y0, z0Inv, n);
    }

    // Point addition, P + Q
    // inData: Px, Py, Pz, Qx, Qy, Qz
    // outData: Rx, Ry, Rz
    function _add(uint[3] memory P, uint[3] memory Q) internal view returns (uint[3] memory R) {
        if(P[2] == 0)
            return Q;
        if(Q[2] == 0)
            return P;
        uint p = pp;
        uint[4] memory zs; // Pz^2, Pz^3, Qz^2, Qz^3
        zs[0] = mulmod(P[2], P[2], p);
        zs[1] = mulmod(P[2], zs[0], p);
        zs[2] = mulmod(Q[2], Q[2], p);
        zs[3] = mulmod(Q[2], zs[2], p);
        uint[4] memory us = [
        mulmod(P[0], zs[2], p),
        mulmod(P[1], zs[3], p),
        mulmod(Q[0], zs[0], p),
        mulmod(Q[1], zs[1], p)
        ]; // Pu, Ps, Qu, Qs
        if (us[0] == us[2]) {
            if (us[1] != us[3])
                return;
            else {
                return _double(P);
            }
        }
        uint h = addmod(us[2], p - us[0], p);
        uint r = addmod(us[3], p - us[1], p);
        uint h2 = mulmod(h, h, p);
        uint h3 = mulmod(h2, h, p);
        uint Rx = addmod(mulmod(r, r, p), p - h3, p);
        Rx = addmod(Rx, p - mulmod(2, mulmod(us[0], h2, p), p), p);
        R[0] = Rx;
        R[1] = mulmod(r, addmod(mulmod(us[0], h2, p), p - Rx, p), p);
        R[1] = addmod(R[1], p - mulmod(us[1], h3, p), p);
        R[2] = mulmod(h, mulmod(P[2], Q[2], p), p);
    }

    // Add two elliptic curve points (affine coordinates)
    function add(uint256 x0, uint256 y0,
        uint256 x1, uint256 y1) internal view
    returns(uint256, uint256)
    {
        uint256 z0;
        uint256[3] memory P = [x0, y0, 1];
        uint256[3] memory Q = [x1, y1, 1];
        uint256[3] memory R = _add(P, Q);
        return toAffinePoint(x0, y0, z0);
    }

    // Point addition, P + Q. P Jacobian, Q affine.
    // inData: Px, Py, Pz, Qx, Qy
    // outData: Rx, Ry, Rz
    function _addMixed(uint[3] memory P, uint[2] memory Q) internal view returns (uint[3] memory R) {
        if(P[2] == 0)
            return [Q[0], Q[1], 1];
        if(Q[1] == 0)
            return P;
        uint p = pp;
        uint[2] memory zs; // Pz^2, Pz^3, Qz^2, Qz^3
        zs[0] = mulmod(P[2], P[2], p);
        zs[1] = mulmod(P[2], zs[0], p);
        uint[4] memory us = [
        P[0],
        P[1],
        mulmod(Q[0], zs[0], p),
        mulmod(Q[1], zs[1], p)
        ]; // Pu, Ps, Qu, Qs
        if (us[0] == us[2]) {
            if (us[1] != us[3]) {
                P[0] = 0;
                P[1] = 0;
                P[2] = 0;
                return;
            }
            else {
                _double(P);
                return;
            }
        }
        uint h = addmod(us[2], p - us[0], p);
        uint r = addmod(us[3], p - us[1], p);
        uint h2 = mulmod(h, h, p);
        uint h3 = mulmod(h2, h, p);
        uint Rx = addmod(mulmod(r, r, p), p - h3, p);
        Rx = addmod(Rx, p - mulmod(2, mulmod(us[0], h2, p), p), p);
        R[0] = Rx;
        R[1] = mulmod(r, addmod(mulmod(us[0], h2, p), p - Rx, p), p);
        R[1] = addmod(R[1], p - mulmod(us[1], h3, p), p);
        R[2] = mulmod(h, P[2], p);
    }

    // Same as addMixed but params are different and mutates P.
    function _addMixedM(uint[3] memory P, uint[2] memory Q) internal view {
        if(P[1] == 0) {
            P[0] = Q[0];
            P[1] = Q[1];
            P[2] = 1;
            return;
        }
        if(Q[1] == 0)
            return;
        uint p = pp;
        uint[2] memory zs; // Pz^2, Pz^3, Qz^2, Qz^3
        zs[0] = mulmod(P[2], P[2], p);
        zs[1] = mulmod(P[2], zs[0], p);
        uint[4] memory us = [
        P[0],
        P[1],
        mulmod(Q[0], zs[0], p),
        mulmod(Q[1], zs[1], p)
        ]; // Pu, Ps, Qu, Qs
        if (us[0] == us[2]) {
            if (us[1] != us[3]) {
                P[0] = 0;
                P[1] = 0;
                P[2] = 0;
                return;
            }
            else {
                _doubleM(P);
                return;
            }
        }
        uint h = addmod(us[2], p - us[0], p);
        uint r = addmod(us[3], p - us[1], p);
        uint h2 = mulmod(h, h, p);
        uint h3 = mulmod(h2, h, p);
        uint Rx = addmod(mulmod(r, r, p), p - h3, p);
        Rx = addmod(Rx, p - mulmod(2, mulmod(us[0], h2, p), p), p);
        P[0] = Rx;
        P[1] = mulmod(r, addmod(mulmod(us[0], h2, p), p - Rx, p), p);
        P[1] = addmod(P[1], p - mulmod(us[1], h3, p), p);
        P[2] = mulmod(h, P[2], p);
    }

    // Point doubling, 2*P
    // Params: Px, Py, Pz
    // Not concerned about the 1 extra mulmod.
    function _double(uint[3] memory P) internal view returns (uint[3] memory Q) {
        uint p = pp;
        if (P[2] == 0)
            return;
        uint Px = P[0];
        uint Py = P[1];
        uint Py2 = mulmod(Py, Py, p);
        uint s = mulmod(4, mulmod(Px, Py2, p), p);
        uint m = mulmod(3, mulmod(Px, Px, p), p);
        var Qx = addmod(mulmod(m, m, p), p - addmod(s, s, p), p);
        Q[0] = Qx;
        Q[1] = addmod(mulmod(m, addmod(s, p - Qx, p), p), p - mulmod(8, mulmod(Py2, Py2, p), p), p);
        Q[2] = mulmod(2, mulmod(Py, P[2], p), p);
    }

    // Same as double but mutates P and is internal only.
    function _doubleM(uint[3] memory P) internal view {
        uint p = pp;
        if (P[2] == 0)
            return;
        uint Px = P[0];
        uint Py = P[1];
        uint Py2 = mulmod(Py, Py, p);
        uint s = mulmod(4, mulmod(Px, Py2, p), p);
        uint m = mulmod(3, mulmod(Px, Px, p), p);
        var PxTemp = addmod(mulmod(m, m, p), p - addmod(s, s, p), p);
        P[0] = PxTemp;
        P[1] = addmod(mulmod(m, addmod(s, p - PxTemp, p), p), p - mulmod(8, mulmod(Py2, Py2, p), p), p);
        P[2] = mulmod(2, mulmod(Py, P[2], p), p);
    }

    // Multiplication dP. P affine, wNAF: w=5
    // Params: d, Px, Py
    // Output: Jacobian Q
    function _mul(uint d, uint[2] memory P) internal view returns (uint[3] memory Q) {
        uint p = pp;
        if (d == 0) // TODO
            return;
        uint dwPtr; // points to array of NAF coefficients.
        uint i;

        // wNAF
        assembly
        {
            let dm := 0
            dwPtr := mload(0x40)
            mstore(0x40, add(dwPtr, 512)) // Should lower this.
            loop:
            jumpi(loop_end, iszero(d))
            jumpi(even, iszero(and(d, 1)))
            dm := mod(d, 32)
            mstore8(add(dwPtr, i), dm) // Don't store as signed - convert when reading.
            d := add(sub(d, dm), mul(gt(dm, 16), 32))
            even:
            d := div(d, 2)
            i := add(i, 1)
            jump(loop)
            loop_end:
        }

        // Pre calculation
        uint[3][8] memory PREC; // P, 3P, 5P, 7P, 9P, 11P, 13P, 15P
        PREC[0] = [P[0], P[1], 1];
        var X = _double(PREC[0]);
        PREC[1] = _addMixed(X, P);
        PREC[2] = _add(X, PREC[1]);
        PREC[3] = _add(X, PREC[2]);
        PREC[4] = _add(X, PREC[3]);
        PREC[5] = _add(X, PREC[4]);
        PREC[6] = _add(X, PREC[5]);
        PREC[7] = _add(X, PREC[6]);

        uint[16] memory INV;
        INV[0] = PREC[1][2];                            // a1
        INV[1] = mulmod(PREC[2][2], INV[0], p);         // a2
        INV[2] = mulmod(PREC[3][2], INV[1], p);         // a3
        INV[3] = mulmod(PREC[4][2], INV[2], p);         // a4
        INV[4] = mulmod(PREC[5][2], INV[3], p);         // a5
        INV[5] = mulmod(PREC[6][2], INV[4], p);         // a6
        INV[6] = mulmod(PREC[7][2], INV[5], p);         // a7

        INV[7] = ECCMath.invmod(INV[6], p);             // a7inv
        INV[8] = INV[7];                                // aNinv (a7inv)

        INV[15] = mulmod(INV[5], INV[8], p);            // z7inv
        for(uint k = 6; k >= 2; k--) {                  // z6inv to z2inv
            INV[8] = mulmod(PREC[k + 1][2], INV[8], p);
            INV[8 + k] = mulmod(INV[k - 2], INV[8], p);
        }
        INV[9] = mulmod(PREC[2][2], INV[8], p);         // z1Inv
        for(k = 0; k < 7; k++) {
            ECCMath.toZ1(PREC[k + 1], INV[k + 9], mulmod(INV[k + 9], INV[k + 9], p), p);
        }

        // Mult loop
        while(i > 0) {
            uint dj;
            uint pIdx;
            i--;
            assembly {
                dj := byte(0, mload(add(dwPtr, i)))
            }
            _doubleM(Q);
            if (dj > 16) {
                pIdx = (31 - dj) / 2; // These are the "negative ones", so invert y.
                _addMixedM(Q, [PREC[pIdx][0], p - PREC[pIdx][1]]);
            }
            else if (dj > 0) {
                pIdx = (dj - 1) / 2;
                _addMixedM(Q, [PREC[pIdx][0], PREC[pIdx][1]]);
            }
        }
    }

}