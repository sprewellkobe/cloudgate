<?php
function strtohex($x) 
{
 $s='';
 foreach (str_split($x) as $c) $s.=sprintf("%02X",ord($c));
 return($s);
} 

$AES_PADDING_CHAR='0';
$source='{"apid":"b8:09:8a:c9:92:c1","version":"NBOS-1.0.3.1507","checksum":"4072f042c0ccb83181bd24a6149553ef","files":[{"checksum":"aec2c358a81be33852eb013ee8ece06d","timestamp":1453689516,"filename":"/etc/hosts"},{"checksum":"d41d8cd98f00b204e9800998ecf8427e","timestamp":1453689607,"filename":"/etc/kisslink"}]}';
$source="{\"result\":\"nothingtodo\"}";
$source="{\"result\":\"apupdate\",\"files\":[{\"/etc/kisslink\":\"c3NzMjIyMnNzcwo=\"}]}";
$iv=str_repeat($AES_PADDING_CHAR,16);
    
$key='kisslinkkisslink';
$method='aes-128-cbc';

echo "iv in hex: ".strtohex ($iv)."\n";
echo "key in hex: ".strtohex ($key)."\n";

$out="out.txt";
$content=openssl_encrypt($source,$method,$key,true,$iv);
echo "source:".$source."\n";
echo "encrypted:".strtohex($content)."\n";
file_put_contents($out,$content);
$exec ="openssl enc -".$method." -d -in out.txt -nosalt -nopad -K ".strtohex($key)." -iv ".strtohex($iv);
echo $exec."\n";
echo "decrypted:";
echo exec ($exec)."\n";
unlink($out);
?>
