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
 * 椭圆曲线域元素
 *
 * @category  SM2
 * @package   ECFieldElementFp
 * @author    hbh <hbh112233abc@163.com>
 * @copyright 2021 hbh112233abc@163.com
 * @license   MIT https://choosealicense.com/licenses/mit/
 * @link      https://github.com/hbh112233abc/sm-crypto
 */
class ECFieldElementFp
{
    protected $q;
    protected $x;

    /**
     * 构造函数
     *
     * @param GMP $q q
     * @param GMP $x x
     */
    public function __construct($q, $x)
    {
        if (gmp_cmp($x, $q) > 0) {
            throw new \Exception("Invalid arguments: $x > $q");
        }
        $this->x = $x;
        $this->q = $q;
    }

    /**
     * 判断相等
     *
     * @param ECFieldElementFp $other other ECFieldElementFp
     *
     * @return boolean
     */
    public function equals($other)
    {
        if ($other === $this) {
            return true;
        }
        return (gmp_cmp($this->q, $other->q) == 0 && gmp_cmp($this->x, $other->x));
    }

    /**
     * 返回具体数值
     *
     * @return GMP object
     */
    public function toBigInteger()
    {
        return $this->x;
    }

    /**
     * 取反
     *
     * @return ECFieldElementFp
     */
    public function negate()
    {
        return new ECFieldElementFp($this->q, gmp_mod(gmp_neg($this->x), $this->q));
    }

    /**
     * 相加
     *
     * @param ECFieldElementFp $b other ECFieldElementFp
     *
     * @return ECFieldElementFp
     */
    public function add($b)
    {
        return new ECFieldElementFp(
            $this->q,
            gmp_mod(gmp_add($this->x, $b->toBigInteger()), $this->q)
        );
    }

    /**
     * 相减
     *
     * @param ECFieldElementFp $b other ECFieldElementFp
     *
     * @return ECFieldElementFp
     */
    public function subtract($b)
    {
        return new ECFieldElementFp(
            $this->q,
            gmp_mod(gmp_sub($this->x, $b->toBigInteger()), $this->q)
        );
    }

    /**
     * 相乘
     *
     * @param ECFieldElementFp $b other ECFieldElementFp
     *
     * @return ECFieldElementFp
     */
    public function multiply($b)
    {
        return new ECFieldElementFp(
            $this->q,
            gmp_mod(gmp_mul($this->x, $b->toBigInteger()), $this->q)
        );
    }

    /**
     * 相除
     *
     * @param ECFieldElementFp $b other ECFieldElementFp
     *
     * @return ECFieldElementFp
     */
    public function divide($b)
    {
        return new ECFieldElementFp(
            $this->q,
            gmp_mod(
                gmp_mul(
                    $this->x,
                    gmp_invert($b->toBigInteger(), $this->q)
                ),
                $this->q
            )
        );
    }

    /**
     * 平方
     *
     * @return ECFieldElementFp
     */
    public function square()
    {
        return new ECFieldElementFp(
            $this->q,
            gmp_mod(gmp_pow($this->x, 2), $this->q)
        );
    }
}
