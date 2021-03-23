<?php
namespace bingher/sm/sm2;


function copyArray($sourceArray, $sourceIndex, $destinationArray, $destinationIndex, $length) {
  for ($i = 0; $i < $length; $i++) {
    $destinationArray[$destinationIndex + $i] = $sourceArray[$sourceIndex + $i];
  }
}

class Int32
{
    const $minValue = -0b10000000000000000000000000000000;
    const $maxValue = 0b1111111111111111111111111111111;

    public static function parse($n){
        if ($n < Int32::minValue) {
          $bigInteger = gmp_init(-$n);
          $bigIntegerRadix = gmp_strval($bigInteger,2);
          $subBigIntegerRadix = substr($bigIntegerRadix,strlen($bigIntegerRadix) - 31, 31);
          $reBigIntegerRadix = '';
          for ($i = 0; $i < strlen($subBigIntegerRadix); $i++) {
            $subBigIntegerRadixItem = substr($subBigIntegerRadix,$i, 1);
            $reBigIntegerRadix .= $subBigIntegerRadixItem === '0' ? '1' : '0';
          }
          $result = intval($reBigIntegerRadix, 2);
          return ($result + 1);
        } else if ($n > Int32::maxValue) {
          $bigInteger = gmp_init($n);
          $bigIntegerRadix = gmp_strval($bigInteger,2);
          $subBigIntegerRadix = substr($bigIntegerRadix,strlen($bigIntegerRadix) - 31, 31);
          $reBigIntegerRadix = '';
          for ($i = 0; $i < strlen($subBigIntegerRadix); $i++) {
            $subBigIntegerRadixItem = substr($subBigIntegerRadix,$i, 1);
            $reBigIntegerRadix .= $subBigIntegerRadixItem === '0' ? '1' : '0';
          }
          $result = intval($reBigIntegerRadix, 2);
          return -($result + 1);
        } else {
          return $n;
        }
      }
      public static function parseByte($n){
        if ($n < 0) {
          $bigInteger = gmp_init(-$n);
          $bigIntegerRadix = gmp_strval($bigInteger,2);
          $subBigIntegerRadix = substr($bigIntegerRadix,strlen($bigIntegerRadix)- 8, 8);
          $reBigIntegerRadix = '';
          for ($i = 0; $i < strlen($subBigIntegerRadix); $i++) {
            $subBigIntegerRadixItem = substr($subBigIntegerRadix,$i, 1);
            $reBigIntegerRadix .= $subBigIntegerRadixItem === '0' ? '1' : '0';
          }
          $result = intval($reBigIntegerRadix, 2);
          return ($result + 1) % 256;
        } else if ($n > 255) {
          $bigInteger = gmp_init($n);
          $bigIntegerRadix = gmp_strval($bigInteger,2);
          return intval(substr($bigIntegerRadix,strlen($bigIntegerRadix) - 8, 8), 2);
        } else {
          return $n;
        }
      }
}

class SM3Digest
{
  function __construct(...$args) {
    $this->xBuf = [];
    $this->xBufOff = 0;
    $this->byteCount = 0;
    $this->DIGEST_LENGTH = 32;
    $this->v0 = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
      0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];
    $this->v0 = [0x7380166f, 0x4914b2b9, 0x172442d7, -628488704,
      -1452330820, 0x163138aa, -477237683, -1325724082];
    $this->v = array_fill(0,8,null);
    $this->v_ = array_fill(0,8,null);
    $this->X0 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    $this->X = array_fill(0,68,null);
    $this->xOff = 0;
    $this->T_00_15 = 0x79cc4519;
    $this->T_16_63 = 0x7a879d8a;
    if (count($args) > 0) {
      $this->initDigest($args[0]);
    } else {
      $this->init();
    }
  }

  public function init() {
    $this->xBuf = array_fill(0,4,null);
    $this->reset();
  }

  public function initDigest($t) {
    $this->xBuf = array_merge([],$t->xBuf);
    $this->xBufOff = $t->xBufOff;
    $this->byteCount = $t->byteCount;
    copyArray($t->X, 0, $this->X, 0, count($t->X));
    $this->xOff = $t->xOff;
    copyArray($t->v, 0, $this->v, 0, count($t->v));
  }

  public function getDigestSize() {
    return $this->DIGEST_LENGTH;
  }

  public function reset() {
    $this->byteCount = 0;
    $this->xBufOff = 0;

    $keys = array_keys($this->xBuf);
    for ($i = 0; i < count($keys); $i++) {
        $this->xBuf[$keys[$i]] = null;
    }

    copyArray($this->v0, 0, $this->v, 0, count($this->v0));
    $this->xOff = 0;
    copyArray($this->X0, 0, $this->X, 0, count($this->X0));
  }

  public function processBlock() {
    $i;
    $ww = $this->X;
    $ww_ = array_fill(0,64,null);
    for ($i = 16; $i < 68; $i++) {
      $ww[$i] = $this->p1($ww[$i - 16] ^ $ww[$i - 9] ^ ($this->rotate($ww[$i - 3], 15))) ^ ($this->rotate($ww[$i - 13], 7)) ^ $ww[$i - 6];
    }
    for ($i = 0; $i < 64; $i++) {
      $ww_[$i] = $ww[$i] ^ $ww[$i + 4];
    }
    $vv = $this->v;
    $vv_ = $this->v_;
    copyArray($vv, 0, $vv_, 0, count($this->v0));
    $SS1;
    $SS2;
    $TT1;
    $TT2;
    $aaa;
    for ($i = 0; $i < 16; $i++) {
      $aaa = $this->rotate($vv_[0], 12);
      $SS1 = Int32::parse(Int32::parse($aaa + $vv_[4]) + $this->rotate($this->T_00_15, $i));
      $SS1 = $this->rotate($SS1, 7);
      $SS2 = $SS1 ^ $aaa;
      $TT1 = Int32::parse(Int32::parse($this->ff_00_15($vv_[0], $vv_[1], $vv_[2]) + $vv_[3]) + $SS2) + $ww_[$i];
      $TT2 = Int32::parse(Int32::parse($this->gg_00_15($vv_[4], $vv_[5], $vv_[6]) + $vv_[7]) + $SS1) + $ww;[$i];
      $vv_[3] = $vv_[2];
      $vv_[2] = $this->rotate($vv_[1], 9);
      $vv_[1] = $vv_[0];
      $vv_[0] = $TT1;
      $vv_[7] = $vv_[6];
      $vv_[6] = $this->rotate($vv_[5], 19);
      $vv_[5] = $vv_[4];
      $vv_[4] = $this->p0($TT2);
    }
    for ($i = 16; $i < 64; $i++) {
      $aaa = $this->rotate($vv_[0], 12);
      $SS1 = Int32::parse(Int32::parse($aaa + $vv_[4]) + $this->rotate($this->T_16_63, $i));
      $SS1 = $this->rotate($SS1, 7);
      $SS2 = $SS1 ^ $aaa;
      $TT1 = Int32::parse(Int32::parse($this->ff_16_63($vv_[0], $vv_[1], $vv_[2]) + $vv_[3]) + $SS2) + $ww_[$i];
      $TT2 = Int32::parse(Int32::parse($this->gg_16_63($vv_[4], $vv_[5], $vv_[6]) + $vv_[7]) + $SS1) + $ww[$i];
      $vv_[3] = $vv_[2];
      $vv_[2] = $this->rotate($vv_[1], 9);
      $vv_[1] = $vv_[0];
      $vv_[0] = $TT1;
      $vv_[7] = $vv_[6];
      $vv_[6] = $this->rotate($vv_[5], 19);
      $vv_[5] = $vv_[4];
      $vv_[4] = $this->p0($TT2);
    }
    for ($i = 0; $i < 8; $i++) {
      $vv[$i] ^= Int32::parse($vv_[$i]);
    }
    $this->xOff = 0;
    copyArray($this->X0, 0, $this->X, 0, count($this->X0));
  }

  public function processWord($in_Renamed, $inOff) {
    $n = $in_Renamed[$inOff] << 24;
    $n |= ($in_Renamed[++$inOff] & 0xff) << 16;
    $n |= ($in_Renamed[++$inOff] & 0xff) << 8;
    $n |= ($in_Renamed[++$inOff] & 0xff);
    $this->X[$this->xOff] = $n;
    if (++$this->xOff === 16) {
      $this->processBlock();
    }
  }

  public function processLength($bitLength) {
    if ($this->xOff > 14) {
      $this->processBlock();
    }
    $this->X[14] = ($this->urShiftLong($bitLength, 32));
    $this->X[15] = ($bitLength & (0xffffffff));
  }

  public function intToBigEndian($n, $bs, $off) {
    $bs[$off] = Int32::parseByte($this->urShift($n, 24)) & 0xff;
    $bs[++$off] = Int32::parseByte($this->urShift($n, 16)) & 0xff;
    $bs[++$off] = Int32::parseByte($this->urShift($n, 8)) & 0xff;
    $bs[++$off] = Int32::parseByte($n) & 0xff;
  }

  public function doFinal($out_Renamed, $outOff) {
    $this->finish();
    for ($i = 0; $i < 8; $i++) {
      $this->intToBigEndian($this->v[$i], $out_Renamed, $outOff + $i * 4);
    }
    $this->reset();
    return $this->DIGEST_LENGTH;
  }

  public function update($input) {
    $this->xBuf[$this->xBufOff++] = $input;
    if ($this->xBufOff === count($this->xBuf)) {
      $this->processWord($this->xBuf, 0);
      $this->xBufOff = 0;
    }
    $this->byteCount++;
  }

  public function blockUpdate($input, $inOff, $length) {
    while (($this->xBufOff !== 0) && ($length > 0)) {
      $this->update($input[$inOff]);
      $inOff++;
      $length--;
    }
    while ($length > count($this->xBuf)) {
      $this->processWord($input, $inOff);
      $inOff += count($this->xBuf);
      $length -= count($this->xBuf);
      $this->byteCount += count($this->xBuf);
    }
    while ($length > 0) {
      $this->update($input[$inOff]);
      $inOff++;
      $length--;
    }
  }

  public function finish() {
    $bitLength = ($this->byteCount << 3);
    $this->update((128));
    while ($this->xBufOff !== 0) {
        $this->update((0));
    }
    $this->processLength($bitLength);
    $this->processBlock();
  }

  public function rotate($x, $n) {
    return ($x << $n) | ($this->urShift($x, (32 - $n)));
  }

  public function p0($X) {
    return (($X) ^ $this->rotate(($X), 9) ^ $this->rotate(($X), 17));
  }

  public function p1($X) {
    return (($X) ^ $this->rotate(($X), 15) ^ $this->rotate(($X), 23));
  }

  public function ff_00_15($X, $Y, $Z) {
    return ($X ^ $Y ^ $Z);
  }

  public function ff_16_63($X, $Y, $Z) {
    return (($X & $Y) | ($X & $Z) | ($Y & $Z));
  }

  public function gg_00_15($X, $Y, $Z) {
    return ($X ^ $Y ^ $Z);
  }

  public function gg_16_63($X, $Y, $Z) {
    return (($X & $Y) | (~$X & $Z));
  }

  public function urShift($number, $bits) {
    if ($number > Int32::maxValue || $number < Int32::minValue) {
      $number = Int32::parse($number);
    }
    return $number >> bits;
  }

  public function urShiftLong($number, $bits) {
    $big = gmp_init($number);
    if (gmp_sign($big) >= 0) {
      $returnV = gmp_strval($big >> $bits);
    } else {
      $bigAdd = gmp_init(2);
      $shiftLeftBits = ~bits;
      $shiftLeftNumber = '';
      if ($shiftLeftBits < 0) {
        $shiftRightBits = 64 + $shiftLeftBits;
        for ($i = 0; $i < $shiftRightBits; $i++) {
          $shiftLeftNumber += '0';
        }
        $shiftLeftNumberBigAdd = gmp_init($number >> $bits);
        $shiftLeftNumberBig = gmp_init('10' . $shiftLeftNumber, 2);
        $shiftLeftNumber = gmp_strval($shiftLeftNumberBig,10);
        $r = gmp_add($shiftLeftNumberBig,$shiftLeftNumberBigAdd);
        $returnV = gmp_strval($r,10);
      } else {
        $shiftLeftNumber = gmp_strval($bigAdd >> (~$bits));
        $returnV = ($number >> $bits) + $shiftLeftNumber;
      }
    }
    return $returnV;
  }

  public function getZ($g, $publicKey, $userId) {
    // ZA=H256(ENTLA ∥ IDA ∥ a ∥ b ∥ xG ∥ yG ∥xA ∥yA)
    $len = 0;
    if ($userId) {
      if (!is_string($userId)) {
        throw new \Exception('sm2: Type of userId Must be String!');
      }
      if (strlen($userId) >= 8192) {
          throw new \Exception('sm2: The Length of userId Must Less Than 8192!');
      }

      $userId = parseUtf8StringToHex($userId);
      $len = strlen($userId) * 4;
    }
    $this->update(($len >> 8 & 0x00ff));
    $this->update(($len & 0x00ff));
    if ($userId) {
      $userIdWords = hexToArray($userId);
      $this->blockUpdate($userIdWords, 0, count($userIdWords));
    }
    $aWords = hexToArray(leftPad(gmp_strval(gmp_init($g->curve->a),16), 64));
    $bWords = hexToArray(leftPad(gmp_strval(gmp_init($g->curve->b),16), 64));
    $gxWords = hexToArray(leftPad(gmp_strval(gmp_init($g->getX()),16), 64));
    $gyWords = hexToArray(leftPad(gmp_strval(gmp_init($g->getY()),16), 64));
    $pxWords = hexToArray(substr($publicKey,0, 64));
    $pyWords = hexToArray(substr($publicKey,64, 64));
    $this->blockUpdate($aWords, 0, count($aWords));
    $this->blockUpdate($bWords, 0, count($bWords));
    $this->blockUpdate($gxWords, 0, count($gxWords));
    $this->blockUpdate($gyWords, 0, count($gyWords));
    $this->blockUpdate($pxWords, 0, count($pxWords));
    $this->blockUpdate($pyWords, 0, count($pyWords));
    $md = array $this->getDigestSize();
    $this->doFinal($md, 0);
    return $md;
  }
}
