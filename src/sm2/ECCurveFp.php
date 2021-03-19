<?php
// +----------------------------------------------------------------------
// | huangbinghe <hbh112233abc@163.com>
// +----------------------------------------------------------------------
// | Copyright (c) 2021 https://github.com/hbh112233abc All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( https://choosealicense.com/licenses/mit/ )
// +----------------------------------------------------------------------
// | Author: huangbinghe <hbh112233abc@163.com>
// +----------------------------------------------------------------------
declare (strict_types = 1);
namespace bingher\sm\sm2;

/**
 * 椭圆曲线 y^2 = x^3 + ax + b
 *
 * @category  SM2
 * @package   ECPointFp
 * @author    hbh <hbh112233abc@163.com>
 * @copyright 2021 hbh112233abc@163.com
 * @license   MIT https://choosealicense.com/licenses/mit/
 * @link      https://github.com/hbh112233abc/sm-crypto
 */
class ECCurveFp
{
    /**
     * 系数a
     *
     * @var number
     */
    protected $a;
    /**
     * 系数b
     *
     * @var number
     */
    protected $b;
    /**
     * 系数q(取模用)
     *
     * @var number
     */
    protected $q;
    /**
     * 无穷远点
     *
     * @var ECPointFp
     */
    protected $infinity;

    /**
     * 构造函数
     *
     * @param number $q q系数(取模用)
     * @param number $a a系数
     * @param number $b b系数
     */
    public function __construct($q, $a, $b)
    {
        $this->q        = $q;
        $this->a        = $this->fromBigInteger($a);
        $this->b        = $this->fromBigInteger($b);
        $this->infinity = new ECPointFp($this, null, null); // 无穷远点
    }

    /**
     * 判断两个椭圆曲线是否相等
     *
     * @param ECCurveFp $other 另一个椭圆曲线
     *
     * @return boolean
     */
    public function equals($other)
    {
        if ($other === $this) {
            return true;
        }

        return (
            gmp_cmp($this->q, $other->q) == 0
            && gmp_cmp($this->a, $other->a) == 0
            && gmp_cmp($this->b, $other->b) == 0
        );
    }

    /**
     * 生成椭圆曲线域元素
     *
     * @param number $x x值
     *
     * @return ECFieldElementFp
     */
    public function fromBigInteger($x)
    {
        return new ECFieldElementFp($this->q, $x);
    }

    /**
     * 解析 16 进制串为椭圆曲线点
     *
     * @param string $s 16 进制串
     *
     * @return ECPointFp
     */
    public function decodePointHex($s)
    {
        switch (intval(substr($s, 0, 2), 16)) {
            // 第一个字节
            case 0:
                return $this->infinity;
            case 2:
            case 3:
                // 不支持的压缩方式
                return null;
            case 4:
            case 6:
            case 7:
                $len  = (strlen($s) - 2) / 2;
                $xHex = substr($s, 2, $len);
                $yHex = substr($s, $len + 2, $len);

                return new ECPointFp(
                    $this,
                    $this->fromBigInteger(gmp_init($xHex, 16)),
                    $this->fromBigInteger(gmp_init($yHex, 16))
                );
            default:
                // 不支持
                return null;
        }
    }
}
