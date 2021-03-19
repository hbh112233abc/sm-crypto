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
 * 椭圆曲线点
 *
 * @category  SM2
 * @package   ECPointFp
 * @author    hbh <hbh112233abc@163.com>
 * @copyright 2021 hbh112233abc@163.com
 * @license   MIT https://choosealicense.com/licenses/mit/
 * @link      https://github.com/hbh112233abc/sm-crypto
 */
class ECPointFp
{
    /**
     * 曲线对象
     *
     * @var ECCurveFp
     */
    protected $curve;

    protected $x;
    protected $y;
    protected $z;

    protected $zinv;

    protected $zero;
    protected $three;

    /**
     * 构造函数
     *
     * @param ECCurveFp $curve 曲线对象
     * @param mixed     $x     x值
     * @param mixed     $y     y值
     * @param mixed     $z     z值
     *
     * @return self
     */
    public function __construct($curve, $x, $y, $z = null)
    {
        $this->zero  = gmp_init(0);
        $this->three = gmp_init(3);

        $this->curve = $curve;
        $this->x     = $x;
        $this->y     = $y;
        // 标准射影坐标系：zinv == null 或 z * zinv == 1
        $this->z    = $z == null ? gmp_init(1) : $z;
        $this->zinv = null;
        // TODO: compression flag
    }

    /**
     * 获取x值
     *
     * @return ECFieldElementFp
     */
    public function getX()
    {
        if (is_null($this->zinv)) {
            $this->zinv = gmp_invert(
                $this->z,
                $this->curve->q
            );
        }

        return $this->curve->fromBigInteger(
            gmp_mod(
                gmp_mul(
                    gmp_init($this->x),
                    $this->zinv
                ),
                $this->curve->q
            )
        );
    }

    /**
     * 获取y值
     *
     * @return ECFieldElementFp
     */
    public function getY()
    {
        if (is_null($this->zinv)) {
            $this->zinv = gmp_invert($this->z, $this->curve->q);
        }

        return $this->curve->fromBigInteger(
            gmp_mod(
                gmp_mul(
                    gmp_init($this->y),
                    $this->zinv
                ),
                $this->curve->q
            )
        );

    }

    /**
     * 判断相等
     *
     * @param ECPointFp $other other point
     *
     * @return boolean
     */
    public function equals($other)
    {
        if ($other === $this) {
            return true;
        }
        if ($this->isInfinity()) {
            return $other->isInfinity();
        }
        if ($other->isInfinity()) {
            return $this->isInfinity();
        }

        // u = y2 * z1 - y1 * z2
        $u = gmp_sub(
            gmp_mul(gmp_init($other->y), $this->z),
            gmp_mod(
                gmp_mul(gmp_init($this->y), $other->z),
                $this->curve->q
            )
        );
        if (gmp_cmp($u, $this->zero) !== 0) {
            return false;
        }

        // v = x2 * z1 - x1 * z2
        $v = gmp_sub(
            gmp_mul(gmp_init($other->x), $this->z),
            gmp_mod(gmp_mul(gmp_init($this->x), $other->z), $this->curve->q)
        );

        return (gmp_cmp($v, $this->zero) !== 0);

    }

    /**
     * 是否是无穷远点
     *
     * @return boolean
     */
    public function isInfinity()
    {
        if (($this->x === null) && ($this->y === null)) {
            return true;
        }
        return (
            gmp_cmp($this->z, $this->zero) === 0
            && gmp_cmp(gmp_init($this->y), $this->zero) !== 0
        );
    }

    /**
     * 取反，x 轴对称点
     *
     * @return ECPointFp
     */
    public function negate()
    {
        return new ECPointFp(
            $this->curve,
            $this->x,
            gmp_neg($this->y),
            $this->z
        );
    }

    /**
     * 相加
     *
     * 标准射影坐标系：
     *
     * λ1 = x1 * z2
     * λ2 = x2 * z1
     * λ3 = λ1 − λ2
     * λ4 = y1 * z2
     * λ5 = y2 * z1
     * λ6 = λ4 − λ5
     * λ7 = λ1 + λ2
     * λ8 = z1 * z2
     * λ9 = λ3^2
     * λ10 = λ3 * λ9
     * λ11 = λ8 * λ6^2 − λ7 * λ9
     * x3 = λ3 * λ11
     * y3 = λ6 * (λ9 * λ1 − λ11) − λ4 * λ10
     * z3 = λ10 * λ8
     *
     * @param ECPointFp $b 另一个point
     *
     * @return ECPointFp
     */
    public function add($b)
    {
        if ($this->isInfinity()) {
            return $b;
        }

        if ($b->isInfinity()) {
            return $this;
        }

        $x1 = gmp_init($this->x);
        $y1 = gmp_init($this->y);
        $z1 = $this->z;
        $x2 = gmp_init($b->x);
        $y2 = gmp_init($b->y);
        $z2 = $b->z;
        $q  = $this->curve->q;

        $w1 = gmp_mod(
            gmp_mul(
                $x1,
                $z2
            ),
            $q
        );
        $w2 = gmp_mod(
            gmp_mul(
                $x2,
                $z1
            ),
            $q
        );
        $w3 = gmp_sub(
            $w1,
            $w2
        );
        $w4 = gmp_mod(
            gmp_mul(
                $y1,
                $z2
            ),
            $q
        );
        $w5 = gmp_mod(
            gmp_mul(
                $y2,
                $z1
            ),
            $q
        );
        $w6 = gmp_sub(
            $w4,
            $w5
        );

        if (gmp_cmp($this->zero, $w3) === 0) {
            if (gmp_cmp($this->zero, $w6) === 0) {
                return $this->twice(); // this == b，计算自加
            }
            return $this->curve->infinity; // this == -b，则返回无穷远点
        }

        $w7 = gmp_add(
            $w1,
            $w2
        );
        $w8 = gmp_mod(
            gmp_mul(
                $z1,
                $z2
            ),
            $q
        );
        $w9 = gmp_mod(
            gmp_pow(
                $w3,
                2
            ),
            $q
        );
        $w10 = gmp_mod(
            gmp_mul(
                $w3,
                $w9
            ),
            $q
        );
        $w11 = gmp_sub(
            gmp_mul(
                $w8,
                gmp_pow(
                    $w6,
                    2
                )
            ),
            gmp_mod(
                gmp_mul(
                    $w7,
                    $w9
                ),
                $q
            )
        );

        $x3 = gmp_mod(
            gmp_mul(
                $w3,
                $w11
            ),
            $q
        );
        $y3 = gmp_sub(
            gmp_mul(
                $w6,
                gmp_sub(
                    gmp_mul(
                        $w9,
                        $w1
                    ),
                    $w11
                )
            ),
            gmp_mod(
                gmp_mul(
                    $w4,
                    $w10
                ),
                $q
            )
        );

        $z3 = gmp_mod(
            gmp_mul(
                $w10,
                $w8
            ),
            $q
        );

        return new ECPointFp(
            $this->curve,
            $this->curve->fromBigInteger($x3),
            $this->curve->fromBigInteger($y3),
            $z3
        );
    }

    /**
     * 自加
     *
     * 标准射影坐标系：
     *
     * λ1 = 3 * x1^2 + a * z1^2
     * λ2 = 2 * y1 * z1
     * λ3 = y1^2
     * λ4 = λ3 * x1 * z1
     * λ5 = λ2^2
     * λ6 = λ1^2 − 8 * λ4
     * x3 = λ2 * λ6
     * y3 = λ1 * (4 * λ4 − λ6) − 2 * λ5 * λ3
     * z3 = λ2 * λ5
     *
     * @return ECPointFp
     */
    public function twice()
    {
        if ($this->isInfinity()) {
            return $this;
        }
        if (!gmp_sign(gmp_init($this->y))) {
            return $this->curve->infinity;
        }

        $x1 = gmp_init($this->x);
        $y1 = gmp_init($this->y);
        $z1 = $this->z;
        $q  = $this->curve->q;
        $a  = gmp_init($this->curve->a);

        $w1 = gmp_add(
            gmp_mul(
                gmp_pow(
                    $x1,
                    2
                ),
                $this->three
            ),
            gmp_mod(
                gmp_mul(
                    $a,
                    gmp_pow(
                        $z1,
                        2
                    )
                ),
                $q
            )
        );
        $w2 = gmp_mod(
            gmp_mul(
                gmp_strval($y1) << 1,
                $z1
            ),
            $q
        );
        $w3 = gmp_mod(
            gmp_pow(
                $y1,
                2
            ),
            $q
        );
        $w4 = gmp_mod(
            gmp_mul(
                gmp_mul(
                    $w3,
                    $x1
                ),
                $z1
            ),
            $q
        );
        $w5 = gmp_mod(
            gmp_pow(
                $w2,
                2
            ),
            $q
        );
        $w6 = gmp_sub(
            gmp_pow(
                $w1,
                2
            ),
            gmp_mod(
                gmp_strval($w4) << 3,
                $q
            )
        );

        $x3 = gmp_mod(
            gmp_mul(
                $w2,
                $w6
            ),
            $q
        );
        $y3 = gmp_sub(
            gmp_mul(
                $w1,
                gmp_sub(
                    gmp_strval($w4) << 2,
                    $w6
                )
            ),
            gmp_mod(
                gmp_mul(
                    gmp_strval($w5) << 1,
                    $w3
                ),
                $q
            )
        );
        $z3 = gmp_mod(
            gmp_mul(
                $w2,
                $w5
            ),
            $q
        );

        return new ECPointFp(
            $this->curve,
            $this->curve->fromBigInteger($x3),
            $this->curve->fromBigInteger($y3),
            $z3
        );
    }

    /**
     * 倍点计算
     *
     * @param GMP $k 倍数
     *
     * @return ECPointFp
     */
    public function multiply($k)
    {
        if ($this->isInfinity()) {
            return $this;
        }
        if (!gmp_sign($k)) {
            return $this->curve->infinity;
        }

        // 使用加减法
        $k3 = gmp_mul(
            $k,
            $this->three
        );
        $neg         = $this->negate();
        $Q           = $this;
        $k3bitLength = strlen(
            gmp_strval(
                $k3,
                2
            )
        );
        for ($i = $k3bitLength - 2; $i > 0; $i--) {
            $Q = $Q->twice();

            $k3Bit = gmp_testbit(
                $k3,
                $i
            );
            $kBit = gmp_testbit(
                $k,
                $i
            );

            if ($k3Bit !== $kBit) {
                $Q = $Q->add($k3Bit ? $this : $neg);
            }
        }

        return $Q;
    }
}
