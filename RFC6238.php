<?php

define('TIMESTEP',           '30');     // seconds
define('TIMEWINDOW',          '2');     // 2 steps either way
define('TOKENLENGTH',         '6');     // characters
define('TOKENCEILING',  '1000000');     // 10**TOKENLENGTH

// Secret key...  Must be retained on the server in plain text.


$UserSecretKey = "FWBXWGAQDSNLQQCQFXZW234";  // Must be [A-Z][2-7] !


function TimeStamp() { return floor(microtime(true)/TIMESTEP); }


class RFC6238 {

   public static function B32toB($inarg) {
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

// HMAC-Based One-Time Password Algorithm from RFC 4226
   public static function MakeOTP($secretKey, $timeval) {
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


   public static function TestKey($secretKey, $testkey) {
      $tStamp = TimeStamp();
      $bSecretKey = self::B32toB($secretKey);
      for ($ts=-TIMEWINDOW; $ts<=TIMEWINDOW; $ts++)
         if (self::MakeOTP($bSecretKey, $tStamp+$ts) == $testkey) return true;
      return false;
      }

   }   // end class


// Main program starts here

if(isset($_REQUEST['totp'])) {
   $secretkey = RFC6238::B32toB($UserSecretKey);   // Decode it into binary
   $otp       = RFC6238::MakeOTP($secretkey, TimeStamp());  // Get current token
   $testkey   = $_REQUEST['totp'];
   echo(" Secret Init key: $UserSecretKey");
   echo("<br>One time password: $otp");
   echo("<br>Challenge: $testkey<br>");
   $result = RFC6238::TestKey($UserSecretKey, $testkey);
   echo $result ? '<strong>Success!</strong>' : '<span style="color: red">Failure.</span>';
   return;
   }
?>

<html><head><title>TOTP PHP demo</title>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.8.3/jquery.min.js"></script>
<script>
   function CheckAuth() {
      var telem = document.getElementById('authin').value;
      $.get('totp_auth.php',
         { totp: telem },
         function(data) { msg.innerHTML = data; },
         "html");
      }
   </script>
</head>
<body>
<p>
<?php
echo ' <p> &nbsp; <p> &nbsp;  <img src="http://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/yournamehere?secret='.$UserSecretKey.'">';
?>
<p> <p>Use the QR code above to set up your authenticator.</a>
<p><label for="authin">Then check an authentication code: </label><input type="text" length=6 id="authin">
 &nbsp; <input type='button' value="Check" onclick='CheckAuth()'>
 <p> &nbsp; <p>
<div id="msg" style="border: 1px solid blue; height: 120px; width: 400px; padding: 10px"></div>
</body>
</html>
