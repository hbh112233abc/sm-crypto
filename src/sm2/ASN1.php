<?php
namespace bingher\sm\sm2;

function bigIntToMinTwosComplementsHex($bigIntegerValue)
{
    $h = gmp_strval($bigIntegerValue, 16);
    if (substr($h, 0, 1) !== '-') {
        if (strlen($h) % 2 === 1) {
            $h = '0'+$h;
        } else if (!preg_match("/^[0-7]/", $h)) {
            $h = '00'+$h;
        }
    } else {
        $hPos   = substr($h, 1);
        $xorLen = strlen($hPos);
        if ($xorLen % 2 === 1) {
            $xorLen += 1;
        } else if (!preg_match("/^[0-7]/", $h)) {
            $xorLen += 2;
        }
        $hMask = '';
        for ($i = 0; $i < $xorLen; $i++) {
            $hMask += 'f';
        }
        $biMask = gmp_init($hMask, 16);
        $biNeg  = gmp_add(gmp_xor($biMask, $bigIntegerValue), gmp_init(1));
        $h      = str_replace("/^-/", '', gmp_strval($biNeg, 16));
    }
    return $h;
}

/**
 * base class for ASN.1 DER encoder object
 */
class ASN1Object
{

    protected $isModified = true;
    protected $hTLV       = null;
    protected $hT         = '00';
    protected $hL         = '00';
    protected $hV         = '';

    public function __construct()
    {
        $this->isModified = true;
        $this->hTLV       = null;
        $this->hT         = '00';
        $this->hL         = '00';
        $this->hV         = '';
    }

    /**
     * get hexadecimal ASN.1 TLV length(L) bytes from TLV value(V)
     */
    public function getLengthHexFromValue()
    {
        $n  = strlen($this->hV) / 2;
        $hN = gmp_strval(gmp_init($n), 16);
        if (strlen($hN) % 2 === 1) {
            $hN = '0'+$hN;
        }
        if ($n < 128) {
            return $hN;
        }

        $hNlen = strlen($hN) / 2;
        $head  = 128 + $hNlen;
        return dechex($head) + $hN;
    }

    /**
     * get hexadecimal string of ASN.1 TLV bytes
     */
    public function getEncodedHex()
    {
        if ($this->hTLV == null || $this->isModified) {
            $this->hV         = $this->getFreshValueHex();
            $this->hL         = $this->getLengthHexFromValue();
            $this->hTLV       = $this->hT + $this->hL + $this->hV;
            $this->isModified = false;
        }
        return $this->hTLV;
    }

    public function getFreshValueHex()
    {
        return '';
    }
}

/**
 * class for ASN.1 DER Integer
 */
class DERInteger extends ASN1Object
{
    /**
     * 构造函数
     *
     * @param int $options
     */
    public function __construct($options)
    {
        parent::__construct();

        $this->hT = '02';
        if ($options && gmp_init($options)) {
            $this->hTLV       = null;
            $this->isModified = true;
            $this->hV         = bigIntToMinTwosComplementsHex(gmp_init($options));
        }
    }

    /**
     * 获取hV
     *
     * @return string
     */
    public function getFreshValueHex()
    {
        return $this->hV;
    }
}

/**
 * class for ASN.1 DER Sequence
 */
class DERSequence extends ASN1Object
{
    public function __construct($options)
    {
        parent::__construct();

        $this->hT        = '30';
        $this->asn1Array = [];
        if ($options && array($options)) {
            $this->asn1Array = array($options);
        }
    }

    public function getFreshValueHex()
    {
        $h = '';
        for ($i = 0; $i < count($this->asn1Array); $i++) {
            $asn1Obj = $this->asn1Array[$i];
            $h += $asn1Obj->getEncodedHex();
        }
        $this->hV = $h;
        return $this->hV;
    }
}

/**
 * get byte length for ASN.1 L(length) bytes
 */
function getByteLengthOfL($s, $pos)
{
    if (substr($s, $pos + 2, $pos + 3) !== '8') {
        return 1;
    }
    $i = intval(substr($s, $pos + 3, $pos + 4), 10);
    if ($i === 0) {
        return -1; // length octet '80' indefinite length
    }
    if ($i > 0 && $i < 10) {
        return $i + 1; // including '8?' octet;
    }
    return -2; // malformed format
}

/**
 * get hexadecimal string for ASN.1 L(length) bytes
 */
function getHexOfL($s, $pos)
{
    $len = getByteLengthOfL($s, $pos);
    if ($len < 1) {
        return '';
    }
    return substr($s, $pos + 2, $pos + 2 + $len * 2);
}

/**
 * get integer value of ASN.1 length for ASN.1 data
 */
function getIntOfL($s, $pos)
{
    $hLength = getHexOfL($s, $pos);
    if ($hLength === '') {
        return -1;
    }

    if (intval(substr($hLength, 0, 1), 10) < 8) {
        $bi = gmp_init($hLength, 16);
    } else {
        $bi = gmp_init(substr($hLength, 2), 16);
    }
    return gmp_strval($bi);
}

/**
 * get ASN.1 value starting string position for ASN.1 object refered by index 'idx'.
 */
function getStartPosOfV($s, $pos)
{
    $lLen = getByteLengthOfL($s, $pos);
    if ($lLen < 0) {
        return $lLen;
    }
    return $pos + ($lLen + 1) * 2;
}

/**
 * get hexadecimal string of ASN.1 V(value)
 */
function getHexOfV($s, $pos)
{
    $pos1 = getStartPosOfV($s, $pos);
    $len  = getIntOfL($s, $pos);
    return substr($s, $pos1, $pos1 + $len * 2);
}

/**
 * get next sibling starting index for ASN.1 object string
 */
function getPosOfNextSibling($s, $pos)
{
    $pos1 = getStartPosOfV($s, $pos);
    $len  = getIntOfL($s, $pos);
    return $pos1 + $len * 2;
}

/**
 * get array of indexes of child ASN.1 objects
 */
function getPosArrayOfChildren($h, $pos)
{
    $a   = [];
    $p0  = getStartPosOfV($h, $pos);
    $a[] = $p0;

    $len = getIntOfL($h, $pos);
    $p   = $p0;
    $k   = 0;
    while (true) {
        $pNext = getPosOfNextSibling($h, $p);
        if ($pNext == null || ($pNext - $p0 >= ($len * 2))) {
            break;
        }
        if ($k >= 200) {
            break;
        }

        $a[] = $pNext;
        $p   = $pNext;

        $k++;
    }

    return $a;
}

/**
 * ASN.1 DER编码
 */
function encodeDer($r, $s)
{
    $derR   = new DERInteger(['bigint' => $r]);
    $derS   = new DERInteger(['bigint' => $s]);
    $derSeq = new DERSequence(['array' => [$derR, $derS]]);

    return $derSeq->getEncodedHex();
}

/**
 * 解析 ASN.1 DER
 */
function decodeDer($input)
{
    // 1. Items of ASN.1 Sequence Check
    $a = getPosArrayOfChildren($input, 0);

    // 2. Integer check
    $iTLV1 = $a[0];
    $iTLV2 = $a[1];

    // 3. getting value
    $hR = getHexOfV($input, $iTLV1);
    $hS = getHexOfV($input, $iTLV2);

    $r = gmp_init($hR, 16);
    $s = gmp_init($hS, 16);

    return [$r, $s];
}
