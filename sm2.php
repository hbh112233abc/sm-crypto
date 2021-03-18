<?php
class SM2Cipher
{
	protected $ct = 1;
	protected $p2;
	protected $sm3keyBase;
	protected $sm3c3;
	protected $key = [];
	protected $keyOff = 0;

	function __construct()
	{

	}

	public function reset(){}
	public function nextKey(){}
	public function initEncipher($userKey){}
	public function encryptBlock($data){}
	public function initDecipher($userD,$c1){}
	public function decryptBlock($data){}
	public function doFinal($c3){}
	public function createPoint($x,$y){
		$publicKey = '04'.$x.$y;
		$curve = getGlobalCurve();
		$point = $curve->decodePointHex($publicKey);
		return $point;
	}
}

function doEncrypt($msg,$publicKey,$cipherMode = 1)
{

}
?>
