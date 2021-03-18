<?php
/**
 * 生成ecparam
 */
function generatrEcparam()
{
	//椭圆曲线
	$p = gmp_strval('FFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',16);
	$a = gmp_strval('FFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',16);
	$b = gmp_strval('5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',16);
	$curve = ECCurveFp($p,$a,$b);

	//基点

	
	$gxHex = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'; 
	$gyHex = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0';
	$G = curve.decodePointHex('04'.$gxHex. $gyHex);

	$n = gmp_strval('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',16);

	return [$curve, $G, $n];
}

/**
 * 生成密钥对
 */
function generateKeyPairHex() {
	// 随机数
    $rng = random_bytes(32);
    $d = Math_BigInteger(n.bitLength(), rng);
    $d = mod(n.subtract(BigInteger.ONE));
    $d = add(BigInteger.ONE); 
    $privateKey = leftPad(d.toString(16), 64);

    $P = G.multiply(d); // P = dG，p 为公钥，d 为私钥
    $Px = leftPad(P.getX().toBigInteger().toString(16), 64);
    $Py = leftPad(P.getY().toBigInteger().toString(16), 64);
    $publicKey = '04'.$Px.$Py;

    return [$privateKey, $publicKey];
}

