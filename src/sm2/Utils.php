<?php
use bingher\sm\sm2\ECCurveFp;

/**
 * 椭圆曲线
 *
 * @var ECCurveFp
 */
global $curve;
/**
 * 曲线点
 *
 * @var ECPointFp
 */
global $G;
/**
 * 数值n
 *
 * @var GMP
 */
global $n;

/**
 * 生成ecparam
 *
 * @return array [ECCurveFp,ECPointFp,GMP]
 */
function generateECParam()
{
    global $curve, $G, $n;
    //椭圆曲线参数
    $p = gmp_init('FFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16);
    $a = gmp_init('FFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16);
    $b = gmp_init('5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16);
    //椭圆曲线
    $curve = new ECCurveFp($p, $a, $b);

    //基点
    $gxHex = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7';
    $gyHex = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0';
    $G     = $curve->decodePointHex('04' . $gxHex . $gyHex);

    $n = gmp_init('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16);

    return [$curve, $G, $n];
}

/**
 * 生成密钥对
 *
 * @return array [$privateKey,$publicKey]
 */
function generateKeyPairHex()
{
    global $curve, $G, $n;
    if (is_null($curve)) {
        generateECParam();
    }
    // 随机数
    $rng        = gmp_random_bits(16);
    $d          = gmp_init(strlen(gmp_strval($n)), $rng);
    $d          = gmp_mod($d, gmp_sub($n, gmp_init(1)));
    $d          = gmp_add($d, gmp_init(1));
    $privateKey = leftPad(gmp_strval($d, 16), 64);

    // P = dG，p 为公钥，d 为私钥
    $P         = $G->multiply($d);
    $Px        = leftPad(gmp_strval(gmp_init($P->getX()), 16), 64);
    $Py        = leftPad(gmp_strval(gmp_init($P->getY()), 16), 64);
    $publicKey = '04' . $Px . $Py;

    return [$privateKey, $publicKey];
}

/**
 * 获取公共椭圆曲线
 *
 * @return ECCurveFp
 */
function getGlobalCurve()
{
    global $curve;
    return $curve;
}

/**
 * 解析utf8字符串到16进制
 *
 * @param string $input 字符串
 *
 * @return string
 */
function parseUtf8StringToHex($input)
{
    return bin2hex($input);

    $input = urldecode(urlencode($input));

    $length = strlen($input);

    // 转换到字数组
    $words = [];
    for ($i = 0; $i < $length; $i++) {
        $words[$i >> 2] |= (charCodeAt($input, $i) & 0xff) << (24 - ($i % 4) * 8);
    }

    // 转换到16进制
    $hexChars = [];
    for ($i = 0; $i < $length; $i++) {
        $bite       = ($words[$i >> 2] >> (24 - ($i % 4) * 8)) & 0xff;
        $hexChars[] = gmp_strval(gmp_init($bite >> 4), 16);
        $hexChars[] = gmp_strval(gmp_init($bite & 0x0f), 16);
    }

    return join('', $hexChars);
}

/**
 * 获取字符char code
 *
 * @param string  $str   字符串
 * @param integer $index 索引
 *
 * @return string
 */
function charCodeAt($str, $index)
{
    $char = mb_substr($str, $index, 1, 'UTF-8');
    if (!mb_check_encoding($char, 'UTF-8')) {
        return null;
    }
    $ret = mb_convert_encoding($char, "UCS-4BE");
    $ret = unpack("N", $ret);
    $ret = dechex($ret[1]);
    return $ret;
}

/**
 * 解析arrayBuffer到16进制字符串
 *
 * @param string $input 字符串
 *
 * @return string
 */
function parseArrayBufferToHex($input)
{
    // return Array.prototype.map.call(new Uint8Array(input), x => ('00' + x.toString(16)).slice(-2)).join('')
    return bin2hex($input);
}

/**
 * 补全16进制字符串
 *
 * @param string  $input 输入字符串
 * @param integer $num   补全后总长度
 *
 * @return string
 */
function leftPad($input, $num)
{
    $length = strlen($input);
    if ($length >= $num) {
        return $input;
    }
    $zeroArr   = array_fill(0, $num - $length, '0');
    $leftZeros = join('', $zeroArr);
    return $leftZeros . $input;
}

/**
 * 转成16进制串
 *
 * @param array $arr Array
 *
 * @return string
 */
function arrayToHex($arr)
{
    $words      = [];
    $j          = 0;
    $arrLength  = count($arr);
    $arrLength2 = $arrLength * 2;
    for ($i = 0; $i < $arrLength2; $i += 2) {
        $words[$i >> 3] |= intval($arr[$j], 10) << (24 - ($i % 8) * 4);
        $j++;
    }

    // 转换到16进制
    $hexChars = [];
    for ($i = 0; $i < $arrLength; $i++) {
        $bite       = ($words[$i >> 2] >> (24 - ($i % 4) * 8)) & 0xff;
        $hexChars[] = gmp_strval(gmp_init($bite >> 4), 16);
        $hexChars[] = gmp_strval(gmp_init($bite & 0x0f), 16);
    }

    return join('', $hexChars);
}

/**
 * 转成utf8串
 *
 * @param array $arr Array
 *
 * @return string
 */
function arrayToUtf8($arr)
{
    $words      = [];
    $j          = 0;
    $arrLength  = count($arr);
    $arrLength2 = $arrLength * 2;
    for ($i = 0; $i < $arrLength2; $i += 2) {
        $words[$i >> 3] |= intval($arr[$j], 10) << (24 - ($i % 8) * 4);
        $j++;
    }

    try {
        $latin1Chars = [];
        for ($i = 0; $i < $arrLength; $i++) {
            $bite          = ($words[$i >> 2] >> (24 - ($i % 4) * 8)) & 0xff;
            $latin1Chars[] = strval($bite);
        }
        return urldecode(urlencode(join('', $latin1Chars)));
    } catch (\Throwable $th) {
        throw new \Exception('Malformed UTF-8 data');
    }
}

/**
 * 转成ascii码数组
 *
 * @param string $hexStr 16进制字符串
 *
 * @return array
 */
function hexToArray($hexStr)
{
    $words        = [];
    $hexStrLength = strlen($hexStr);

    if ($hexStrLength % 2 !== 0) {
        $hexStr = leftPad($hexStr, $hexStrLength + 1);
    }

    $hexStrLength = strlen($hexStr);

    for ($i = 0; $i < $hexStrLength; $i += 2) {
        $words[] = intval(substr($hexStr, $i, 2), 16);
    }
    return $words;
}

/**
 * 字符串转ASCII
 *
 * @param string $str 字符串
 *
 * @return string
 */
function str2ascii($str)
{
    $str    = mb_convert_encoding($str, 'UTF-8');
    $result = '';
    $strlen = strlen($str);
    for ($i = 0; $i < $strlen; $i++) {
        $temp_str = dechex(ord($str[$i]));
        $result .= $temp_str[1] . $temp_str[0];
    }
    return strtoupper($result);
}

/**
 * ASCII转字符串
 *
 * @param string $ascii ascii码
 *
 * @return string
 */
function ascii2str($ascii)
{
    $ascArr = str_split(strtolower($ascii), 2);
    $str    = '';
    $ascLen = count($ascArr);
    for ($i = 0; $i < $ascLen; $i++) {
        $str .= chr(hexdec($ascArr[$i][1] . $ascArr[$i][0]));
    }
    return mb_convert_encoding($str, 'UTF-8', 'GB2312');
}
