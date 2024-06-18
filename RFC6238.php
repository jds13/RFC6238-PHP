<?php

define('TIMESTEP',    '30');     // seconds
define('TIMEWINDOW',   '2');     // 2 steps either way
define('TOKENLENGTH',  '6');     // characters
define('TOKENCEILING',  '1000000');     // 10**TOKENLENGTH

$myip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
$shash = hash('sha256', 'fwb~$_,xw'.$myip);
$UserSecretKey = strtolower(substr($shash,0,32));
$UserSecretKey = str_replace(['0','1','8','9'],['g','q','o','l'],$UserSecretKey);

function TimeStamp() { return floor(microtime(true)/TIMESTEP); }

class RFC6238 {

   public static function b32_decode($inarg) {
      $inarg  = strtoupper($inarg);
      if (!preg_match('/^[A-Z2-7]+$/', $inarg))
         throw new Exception('Invalid characters in the base32 string.');
      $n = $j = 0;
      $result = "";
      for ($i=0; $i<strlen($inarg); $i++) {
         $n = $n << 5;           // Each character gets 5 bits
         $c = ord($inarg[$i]);
         $c -= ($c>64) ? 65 : 24;  // A-Z or 2-7
         $n += $c;
         $j += 5;
         if ($j > 7) {
            $j -= 8;
            $result .= chr(($n & (0xFF << $j)) >> $j);
            }
         }
      return $result;
      }

   public static function oath_hotp($secretKey, $timeval) {
      if (strlen($secretKey) < 8)
         throw new Exception('Secret key must contain at least 16 base 32 characters');
      $bTimeval = pack('N*', 0) . pack('N*', $timeval);    // Timeval must be 64-bit int
      $hash = hash_hmac ('sha1', $bTimeval, $secretKey, true);
      $offset = ord($hash[19]) & 0xf;
      $token =
         ((ord($hash[$offset+0]) & 0x7f) << 24 ) |
         ((ord($hash[$offset+1]) & 0xff) << 16 ) |
         ((ord($hash[$offset+2]) & 0xff) << 8 ) |
         ( ord($hash[$offset+3]) & 0xff) ;
      while($token>TOKENCEILING) $token -= TOKENCEILING;
      return str_pad($token, TOKENLENGTH, '0', STR_PAD_LEFT);
      }


   public static function verify_key($secretKey, $testkey) {
      $tStamp = TimeStamp();
      $bSecretKey = self::b32_decode($secretKey);
      for ($ts=-TIMEWINDOW; $ts<=TIMEWINDOW; $ts++)
         if (self::oath_hotp($bSecretKey, $tStamp+$ts) == $testkey) return true;
      return false;
      }

   }   // end class


// Main program starts here

if(isset($_REQUEST['totp'])) {
   $secretkey = RFC6238::b32_decode($UserSecretKey);   // Decode it into binary
   $otp       = RFC6238::oath_hotp($secretkey, TimeStamp());  // Get current token
   $testkey   = $_REQUEST['totp'];
   echo("<table><tr><td>Correct value:<td>$otp");
   echo("<tr><td>You entered:<td>$testkey");
   $result = RFC6238::verify_key($UserSecretKey, $testkey);
   echo '<tr><th>';
   echo $result ? 'Success!' : 'Failure';
   echo '</table>';
   return;
   }
?>

<html><head><title>TOTP PHP demo</title>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.8.3/jquery.min.js"></script>
<script src="https://cdn.jsdelivr.net/gh/davidshimjs/qrcodejs/qrcode.min.js"></script>

<script>
function CheckAuth() {
   var telem = document.getElementById('authin').value;
   $.get('totp_auth.php',
      { totp: telem },
      function(data) { msg.innerHTML = data; },
      "html");
   }

function MakeQR(divid,secret) {
   const qrcode = new QRCode(divid, {
     text: 'otpauth://totp/yournamehere?secret='+secret,
     width: 128,
     height: 128,
     colorDark : '#000',
     colorLight : '#fff',
     correctLevel : QRCode.CorrectLevel.H
     });
   }
$(document).ready(function() {
   MakeQR(document.getElementById('qrcode'), $('#secret').text() )
   });
   </script>
</head>
<body>
<p>
<h3>Scan this QR code to set up TOTP authentication:</h3>
<div id="qrcode" style="display: block; margin-left: 50px;"></div>
<?php
echo '<p><div> If you can\'t scan the barcode: &nbsp; <div style="font-family: monospace; display: inline;" id="secret">'.$UserSecretKey.'</div></div>';
?>
<p><label for="authin">Check an authentication code: </label><input type="text" length=6 id="authin">
 &nbsp; <input type='button' value="Check" onclick='CheckAuth()'>
<p><div id="msg" style="border: 1px solid blue; height: 70px; width: 250px; padding: 10px"></div>
</body>
</html>
