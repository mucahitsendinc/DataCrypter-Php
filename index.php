<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Carbon;

class DataCrypter extends Controller
{

    /**
     *DataCrypter-Php  © 2021
     * Tüm hakları saklıdır
     *
     *
     *   mt = Süreli şifreleme fonksiyonlarıdır.
     *
     */

    public $explode_key="@Dehasoft@";
    public $access_time=31556926;  //seconds

    public $method="aes-128-cbc";
    public $key="c453f$";
    public $secret="5r?n81";

    public $methodd="aes-256-cbc";
    public $keyy="3e5!?s44b";
    public $secrett="as$$??!0";

    public $methoddd="aes-128-cfb8";
    public $keyyy="??$43.,";
    public $secrettt="4fdhf5$";

    public function crypter(Request $request){ // Test Request Method
        $data=$request->data;
        $time=$request->time=="true" ? true : false;
        $mode=$request->mode;
        if($mode=="encode"){
            return $this->crypt_router($data,$time,$mode);
        }else{
            return $this->crypt_router($data,$time,$mode);
        }
    }
    public static function md5R($string,$repeatVal=4){
        $string=base64_encode($string);
        for ($i=0;$i<$repeatVal;$i++){
            $string=md5(base64_encode($string));
        }
        return base64_encode($string);
    }
    public static function uniqidR(){
        return self::md5R(time(). md5(self::md5R(base64_encode(bcrypt(uniqid(rand(), true))))));
    }
    private function KEI1_mt_encode_data($string, $access_time = "")
    {
        $access_time = $access_time == "" ? $this->access_time : $access_time;
        $method = $this->method;
        $key = $this->key;
        $secret = $this->secret;
        $key = hash('sha256', $key);
        $iv = substr(hash('sha256', $secret), 0, 16);
        if ($string != "" && gettype($string) == "string") {
            $string = $string . $this->explode_key . strtotime('+' . $access_time . ' seconds');
            $output = openssl_encrypt($string, $method, $key, 0, $iv);
        } else if (count($string) > 0 && gettype($string) == "array") {
            array_push($string, strtotime('+' . $access_time . ' seconds'));
            $string = json_encode($string);
            $output = openssl_encrypt($string, $method, $key, 0, $iv);
        }

        return ($output);
    }
    private function KEI1_mt_decode_data($string, $type = "")
    {
        $method = $this->method;
        $key = $this->key;
        $secret = $this->secret;
        $key = hash('sha256', $key);
        $iv = substr(hash('sha256', $secret), 0, 16);
        $string = ($string);
        $string = openssl_decrypt($string, $method, $key, 0, $iv);
        if ($type == "") {
            $string = explode($this->explode_key, $string);
        }

        if ($string[count($string) - 1] <= time()) {
            $string[count($string) - 1] = "false";
            return false;
        }
        $response=[];
        foreach($string as $str){
            if($str!=$string[count($string)-1]){
                array_push($response,$str);
            }
        }
        return $response;
    }
    public function crypt_router($string,$time=false,$mode="encode",$access_time="empty"){

        /**
         * Bu fonksiyon içerisindeki komut satırına alınmış satırları sırasını değiştirerek
         * Algoritmada değişiklik yapın sonrasında else bloğunda tam tersine çevirin
         */
        if($mode=="encode"){
            //$crypt=$this->KEI1_encode($string);
            $crypt=$string;
            if($time==true){
                $crypt=$this->KEI1_mt_encode_data($crypt,$access_time=="empty" ? $this->access_time : $access_time);
            }
            $crypt=$this->KEI1_encode($crypt,$this->method,$this->key,$this->secret);
            //$crypt=$this->KEI1_encode($crypt,$this->method,$this->keyy,$this->secret);
            //$crypt=$this->KEI1_encode($crypt,$this->method,$this->keyyy,$this->secret);
            //$crypt=$this->KEI1_encode($crypt,$this->method,$this->key,$this->secrett);
            //$crypt=$this->KEI1_encode($crypt,$this->method,$this->key,$this->secrettt);
            //$crypt=$this->KEI1_encode($crypt,$this->method,$this->keyy,$this->secrett);
            //$crypt=$this->KEI1_encode($crypt,$this->method,$this->keyy,$this->secrettt);
            //$crypt=$this->KEI1_encode($crypt,$this->method,$this->keyyy,$this->secrett);
            $crypt=$this->KEI1_encode($crypt,$this->method,$this->keyyy,$this->secrettt);
            /*    ----- -- -- - - -- */
            $crypt=$this->KEI1_encode($crypt,$this->methodd,$this->key,$this->secret);
            //$crypt=$this->KEI1_encode($crypt,$this->methodd,$this->keyy,$this->secret);
            //$crypt=$this->KEI1_encode($crypt,$this->methodd,$this->keyyy,$this->secret);
            //$crypt=$this->KEI1_encode($crypt,$this->methodd,$this->key,$this->secrett);
            //$crypt=$this->KEI1_encode($crypt,$this->methodd,$this->key,$this->secrettt);
            //$crypt=$this->KEI1_encode($crypt,$this->methodd,$this->keyy,$this->secrett);
            $crypt=$this->KEI1_encode($crypt,$this->methodd,$this->keyy,$this->secrettt);
            //$crypt=$this->KEI1_encode($crypt,$this->methodd,$this->keyyy,$this->secrett);
            //$crypt=$this->KEI1_encode($crypt,$this->methodd,$this->keyyy,$this->secrettt);
            /*    ----- -- -- - - -- */
            $crypt=$this->KEI1_encode($crypt,$this->methoddd,$this->key,$this->secret);
            //$crypt=$this->KEI1_encode($crypt,$this->methoddd,$this->keyy,$this->secret);
            //$crypt=$this->KEI1_encode($crypt,$this->methoddd,$this->keyyy,$this->secret);
            //$crypt=$this->KEI1_encode($crypt,$this->methoddd,$this->key,$this->secrett);
            //$crypt=$this->KEI1_encode($crypt,$this->methoddd,$this->key,$this->secrettt);
            //$crypt=$this->KEI1_encode($crypt,$this->methoddd,$this->keyy,$this->secrett);
            $crypt=$this->KEI1_encode($crypt,$this->methoddd,$this->keyy,$this->secrettt);
            //$crypt=$this->KEI1_encode($crypt,$this->methoddd,$this->keyyy,$this->secrett);
            //$crypt=$this->KEI1_encode($crypt,$this->methoddd,$this->keyyy,$this->secrettt);

        }else{
            $crypt=($string);
            /*  -    -- -- - -- --- -- ---- --  */
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methoddd,$this->keyyy,$this->secrettt);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methoddd,$this->keyyy,$this->secrett);
            $crypt=$this->KEI1_decode($crypt,'off',$this->methoddd,$this->keyy,$this->secrettt);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methoddd,$this->keyy,$this->secrett);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methoddd,$this->key,$this->secrettt);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methoddd,$this->key,$this->secrett);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methoddd,$this->keyyy,$this->secret);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methoddd,$this->keyy,$this->secret);
            $crypt=$this->KEI1_decode($crypt,'off',$this->methoddd,$this->key,$this->secret);
            /*  - -- - -- - -- - --  */
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methodd,$this->keyyy,$this->secrettt);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methodd,$this->keyyy,$this->secrett);
            $crypt=$this->KEI1_decode($crypt,'off',$this->methodd,$this->keyy,$this->secrettt);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methodd,$this->keyy,$this->secrett);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methodd,$this->key,$this->secrettt);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methodd,$this->key,$this->secrett);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methodd,$this->keyyy,$this->secret);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->methodd,$this->keyy,$this->secret);
            $crypt=$this->KEI1_decode($crypt,'off',$this->methodd,$this->key,$this->secret);
            /*  -    -- -- - -- --- -- ---- --  */
            $crypt=$this->KEI1_decode($crypt,'off',$this->method,$this->keyyy,$this->secrettt);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->method,$this->keyyy,$this->secrett);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->method,$this->keyy,$this->secrettt);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->method,$this->keyy,$this->secrett);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->method,$this->key,$this->secrettt);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->method,$this->key,$this->secrett);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->method,$this->keyyy,$this->secret);
            //$crypt=$this->KEI1_decode($crypt,'off',$this->method,$this->keyy,$this->secret);
            $crypt=$this->KEI1_decode($crypt,'off',$this->method,$this->key,$this->secret);

            if($time==true){
                $crypt=$this->KEI1_mt_decode_data($crypt);
            }

        }
        return $crypt;

    }
    private function KEI1_encode($string,$method="",$key="",$secret=""){
        if($method=="") { $method=$this->methodd; }
        if($key=="") { $key=$this->keyy; }
        if($secret=="") { $secret=$this->secrett; }
        $string=($string);
        $key = hash('sha256', $key);
        $iv = substr(hash('sha256', $secret), 0, 16);
        if ($string != "" && gettype($string) == "string") {
            //$string = $string . '@DehaSoft@' . strtotime('+' . env('ACCESS_TIME') . ' seconds');

            $output = openssl_encrypt($string, $method, $key, 0, $iv);

        } else if (count($string) > 0 && gettype($string) == "array") {
            //array_push($string,strtotime('+' . env('ACCESS_TIME') . ' seconds'));
            $string = json_encode($string);
            $output = openssl_encrypt($string, $method, $key, 0, $iv);
        }

        return base64_encode($output);
    }
    private function KEI1_decode($string,$type="off",$method="",$key="",$secret="")
    {
        if($method=="") { $method=$this->methodd; }
        if($key=="") { $key=$this->keyy; }
        if($secret=="") { $secret=$this->secrett; }
        $key = hash('sha256', $key);
        $iv = substr(hash('sha256', $secret), 0, 16);
        $string = base64_decode($string);

        $string = openssl_decrypt($string, $method, $key, 0, $iv);

        if ($type != "off") {
            $string = json_decode($string);
        }
        $string=($string);
        return $string;
    }

    public static function timeHasPassed($time="2021-10-08 18:12:32"){
        $now=Carbon::now();

        $time=Carbon::parse($time);

        $saniye=$now->diffInSeconds($time, false);
        $dakika=$now->diffInMinutes($time, false);
        $saat=$now->diffInHours($time, false);
        $gun=$now->diffInDays($time, false);
        $ay=$now->diffInMonths($time, false);
        $yil=$now->diffInYears($time, false);
        $hafta=$gun>-7 ? 0 : ( $gun>-13 ? 1 : ( $gun>-20 ? 2 : 3 ) );
        $sure=$yil!= 0 ? $yil." yıl" : ($ay!=0 ? $ay." ay" : ( $hafta!=0 ? $hafta." hafta" : ( $gun!=0 ? $gun." gün" : ( $saat!=0 ? $saat." saat" : ( $dakika!=0 ? $dakika." dakika" : $saniye." saniye" ) ) ) ) );

        return str_replace("-","",$sure)." önce";

    }
    public static function slugify($str, $options = array()){
        $str = mb_convert_encoding((string)$str, 'UTF-8', mb_list_encodings());
        $defaults = array('delimiter' => '-','limit' => null,'lowercase' => true,'replacements' => array(),'transliterate' => true);
        $options = array_merge($defaults, $options);
        $char_map = array('À' => 'A', 'Á' => 'A', 'Â' => 'A', 'Ã' => 'A', 'Ä' => 'A', 'Å' => 'A', 'Æ' => 'AE', 'Ç' => 'C','È' => 'E', 'É' => 'E', 'Ê' => 'E', 'Ë' => 'E', 'Ì' => 'I', 'Í' => 'I', 'Î' => 'I', 'Ï' => 'I','Ð' => 'D', 'Ñ' => 'N', 'Ò' => 'O', 'Ó' => 'O', 'Ô' => 'O', 'Õ' => 'O', 'Ö' => 'O', 'Ő' => 'O','Ø' => 'O', 'Ù' => 'U', 'Ú' => 'U', 'Û' => 'U', 'Ü' => 'U', 'Ű' => 'U', 'Ý' => 'Y', 'Þ' => 'TH','ß' => 'ss','à' => 'a', 'á' => 'a', 'â' => 'a', 'ã' => 'a', 'ä' => 'a', 'å' => 'a', 'æ' => 'ae', 'ç' => 'c','è' => 'e', 'é' => 'e', 'ê' => 'e', 'ë' => 'e', 'ì' => 'i', 'í' => 'i', 'î' => 'i', 'ï' => 'i','ð' => 'd', 'ñ' => 'n', 'ò' => 'o', 'ó' => 'o', 'ô' => 'o', 'õ' => 'o', 'ö' => 'o', 'ő' => 'o','ø' => 'o', 'ù' => 'u', 'ú' => 'u', 'û' => 'u', 'ü' => 'u', 'ű' => 'u', 'ý' => 'y', 'þ' => 'th','ÿ' => 'y','©' => '(c)','Α' => 'A', 'Β' => 'B', 'Γ' => 'G', 'Δ' => 'D', 'Ε' => 'E', 'Ζ' => 'Z', 'Η' => 'H', 'Θ' => '8','Ι' => 'I', 'Κ' => 'K', 'Λ' => 'L', 'Μ' => 'M', 'Ν' => 'N', 'Ξ' => '3', 'Ο' => 'O', 'Π' => 'P','Ρ' => 'R', 'Σ' => 'S', 'Τ' => 'T', 'Υ' => 'Y', 'Φ' => 'F', 'Χ' => 'X', 'Ψ' => 'PS', 'Ω' => 'W','Ά' => 'A', 'Έ' => 'E', 'Ί' => 'I', 'Ό' => 'O', 'Ύ' => 'Y', 'Ή' => 'H', 'Ώ' => 'W', 'Ϊ' => 'I','Ϋ' => 'Y','α' => 'a', 'β' => 'b', 'γ' => 'g', 'δ' => 'd', 'ε' => 'e', 'ζ' => 'z', 'η' => 'h', 'θ' => '8','ι' => 'i', 'κ' => 'k', 'λ' => 'l', 'μ' => 'm', 'ν' => 'n', 'ξ' => '3', 'ο' => 'o', 'π' => 'p','ρ' => 'r', 'σ' => 's', 'τ' => 't', 'υ' => 'y', 'φ' => 'f', 'χ' => 'x', 'ψ' => 'ps', 'ω' => 'w','ά' => 'a', 'έ' => 'e', 'ί' => 'i', 'ό' => 'o', 'ύ' => 'y', 'ή' => 'h', 'ώ' => 'w', 'ς' => 's','ϊ' => 'i', 'ΰ' => 'y', 'ϋ' => 'y', 'ΐ' => 'i','Ş' => 'S', 'İ' => 'I', 'Ç' => 'C', 'Ü' => 'U', 'Ö' => 'O', 'Ğ' => 'G','ş' => 's', 'ı' => 'i', 'ç' => 'c', 'ü' => 'u', 'ö' => 'o', 'ğ' => 'g','А' => 'A', 'Б' => 'B', 'В' => 'V', 'Г' => 'G', 'Д' => 'D', 'Е' => 'E', 'Ё' => 'Yo', 'Ж' => 'Zh','З' => 'Z', 'И' => 'I', 'Й' => 'J', 'К' => 'K', 'Л' => 'L', 'М' => 'M', 'Н' => 'N', 'О' => 'O','П' => 'P', 'Р' => 'R', 'С' => 'S', 'Т' => 'T', 'У' => 'U', 'Ф' => 'F', 'Х' => 'H', 'Ц' => 'C','Ч' => 'Ch', 'Ш' => 'Sh', 'Щ' => 'Sh', 'Ъ' => '', 'Ы' => 'Y', 'Ь' => '', 'Э' => 'E', 'Ю' => 'Yu','Я' => 'Ya','а' => 'a', 'б' => 'b', 'в' => 'v', 'г' => 'g', 'д' => 'd', 'е' => 'e', 'ё' => 'yo', 'ж' => 'zh','з' => 'z', 'и' => 'i', 'й' => 'j', 'к' => 'k', 'л' => 'l', 'м' => 'm', 'н' => 'n', 'о' => 'o','п' => 'p', 'р' => 'r', 'с' => 's', 'т' => 't', 'у' => 'u', 'ф' => 'f', 'х' => 'h', 'ц' => 'c','ч' => 'ch', 'ш' => 'sh', 'щ' => 'sh', 'ъ' => '', 'ы' => 'y', 'ь' => '', 'э' => 'e', 'ю' => 'yu','я' => 'ya','Є' => 'Ye', 'І' => 'I', 'Ї' => 'Yi', 'Ґ' => 'G','є' => 'ye', 'і' => 'i', 'ї' => 'yi', 'ґ' => 'g','Č' => 'C', 'Ď' => 'D', 'Ě' => 'E', 'Ň' => 'N', 'Ř' => 'R', 'Š' => 'S', 'Ť' => 'T', 'Ů' => 'U','Ž' => 'Z','č' => 'c', 'ď' => 'd', 'ě' => 'e', 'ň' => 'n', 'ř' => 'r', 'š' => 's', 'ť' => 't', 'ů' => 'u','ž' => 'z','Ą' => 'A', 'Ć' => 'C', 'Ę' => 'e', 'Ł' => 'L', 'Ń' => 'N', 'Ó' => 'o', 'Ś' => 'S', 'Ź' => 'Z','Ż' => 'Z','ą' => 'a', 'ć' => 'c', 'ę' => 'e', 'ł' => 'l', 'ń' => 'n', 'ó' => 'o', 'ś' => 's', 'ź' => 'z','ż' => 'z','Ā' => 'A', 'Č' => 'C', 'Ē' => 'E', 'Ģ' => 'G', 'Ī' => 'i', 'Ķ' => 'k', 'Ļ' => 'L', 'Ņ' => 'N','Š' => 'S', 'Ū' => 'u', 'Ž' => 'Z','ā' => 'a', 'č' => 'c', 'ē' => 'e', 'ģ' => 'g', 'ī' => 'i', 'ķ' => 'k', 'ļ' => 'l', 'ņ' => 'n','š' => 's', 'ū' => 'u', 'ž' => 'z');
        $str = preg_replace(array_keys($options['replacements']), $options['replacements'], $str);
        if ($options['transliterate']) {
            $str = str_replace(array_keys($char_map), $char_map, $str);
        }
        $str = preg_replace('/[^\p{L}\p{Nd}]+/u', $options['delimiter'], $str);
        $str = preg_replace('/(' . preg_quote($options['delimiter'], '/') . '){2,}/', '$1', $str);
        $str = mb_substr($str, 0, ($options['limit'] ? $options['limit'] : mb_strlen($str, 'UTF-8')), 'UTF-8');
        $str = trim($str, $options['delimiter']);
        return $options['lowercase'] ? mb_strtolower($str, 'UTF-8') : $str;
    }

}
