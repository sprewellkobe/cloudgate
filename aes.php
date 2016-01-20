<?php
function strtohex($x) 
{
 $s='';
 foreach (str_split($x) as $c) $s.=sprintf("%02X",ord($c));
 return($s);
} 

$AES_PADDING_CHAR='X';
$source='123456781234567';
$iv=str_repeat($AES_PADDING_CHAR,16);
    
$key='kisslinkkisslink';
$method='aes-128-cbc';

echo "iv in hex: ".strtohex ($iv)."\n";
echo "key in hex: ".strtohex ($key)."\n";

$out="out.txt";
$content=openssl_encrypt($source,$method,$key,true,$iv);
echo "source:[".$source."]\n";
echo "encrypted:[".strtohex($content)."]\n";
file_put_contents($out,$content);
$exec ="openssl enc -".$method." -d -in out.txt -nosalt -nopad -K ".strtohex($key)." -iv ".strtohex($iv);
echo $exec."\n";
echo "decrypted:[";
echo exec ($exec)."]\n";
unlink($out);
?>
