<?php
/*!
* HybridAuth
* http://hybridauth.sourceforge.net | http://github.com/hybridauth/hybridauth
* (c) 2009-2012, HybridAuth authors | http://hybridauth.sourceforge.net/licenses.html 
*/

/**
 * Hybrid_Providers_ESIA provider adapter based on OAuth2 protocol
 */
class Hybrid_Providers_ESIA extends Hybrid_Provider_Model_OAuth2 {
  /**
   * IDp wrappers initializer
   */
  function initialize() {
    $this->config['state'] = $this->esia_uuid();
    $payload = $this->config['scope'] . $this->config['timestamp'] . $this->config['keys']['id'] . $this->config['state'];

    $signature = $this->esia_client_secret($payload);
    $signature = $this->esia_base64urldecode($signature);
    $this->config['keys']['secret'] = $signature;

    // START parent::initialize();
    if ( ! $this->config["keys"]["id"] || ! $this->config["keys"]["secret"] ){
      throw new Exception( "Your application id and secret are required in order to connect to {$this->providerId}.", 4 );
    }

    // override requested scope
    if( isset( $this->config["scope"] ) && ! empty( $this->config["scope"] ) ){
      $this->scope = $this->config["scope"];
    }

    // include OAuth2 client
    // require_once Hybrid_Auth::$config["path_libraries"] . "OAuth/OAuth2Client.php";

    // create a new OAuth2 client instance
    $this->api = new ESIA_OAuth2Client( $this->config["keys"]["id"], $this->config["keys"]["secret"], $this->endpoint );

    // If we have an access token, set it
    if( $this->token( "access_token" ) ){
      $this->api->access_token            = $this->token( "access_token" );
      $this->api->refresh_token           = $this->token( "refresh_token" );
      $this->api->access_token_expires_in = $this->token( "expires_in" );
      $this->api->access_token_expires_at = $this->token( "expires_at" );
    }

    // Set curl proxy if exist
    if( isset( Hybrid_Auth::$config["proxy"] ) ){
      $this->api->curl_proxy = Hybrid_Auth::$config["proxy"];
    }
    // END parent::initialize();

    // Provider api end-points.
    $base_url = $this->config['oauth2_server'];
    $this->api->api_base_url = $base_url;
    $this->api->authorize_url = $base_url . '/aas/oauth2/ac';
    $this->api->token_url = $base_url . '/aas/oauth2/te';

    $this->api->curl_useragent = '';
    // $this->api->curl_header = array('Content-Type: application/x-www-form-urlencoded');
  }

  /**
   * begin login step
   */
  function loginBegin() {
    $extras['client_secret'] = $this->api->client_secret;
    $extras['scope'] = $this->scope;
    $extras['state'] = $this->config['state'];
    $extras['timestamp'] = $this->config['timestamp'];
    $extras['access_type'] = 'online';

    Hybrid_Auth::redirect($this->api->authorizeUrl($extras));
  }

  /**
   * finish login step
   */
  function loginFinish() {
    $error = (array_key_exists('error',$_REQUEST)) ? $_REQUEST['error'] : "";

    // check for errors
    if ( $error ) {
      throw new Exception( "Authentication failed! {$this->providerId} returned an error: $error", 5 );
    }

    // try to authenicate user
    $code = (array_key_exists('code', $_REQUEST)) ? $_REQUEST['code'] : "";

    $extras['scope'] = $this->scope;
    $extras['state'] = $this->config['state'];
    $extras['timestamp'] = $this->config['timestamp'];
    $extras['token_type'] = 'Bearer';
    try{
      $this->api->authenticate( $code, $extras );
    }
    catch( Exception $e ){
      throw new Exception( "User profile request failed! {$this->providerId} returned an error: $e", 6 );
    }

    // check if authenticated
    if ( ! $this->api->access_token ){
      throw new Exception( "Authentication failed! {$this->providerId} returned an invalid access token.", 5 );
    }

    // store tokens
    $this->token( "access_token" , $this->api->access_token  );
    $this->token( "refresh_token", $this->api->refresh_token );
    $this->token( "expires_in"   , $this->api->access_token_expires_in );
    $this->token( "expires_at"   , $this->api->access_token_expires_at );
    $this->token( "id_token"     , $this->api->id_token );

    // set user connected locally
    $this->setUserConnected();
  }

  function getUserProfile()
  {
    // TODO: Refresh tokens if needed.
    // $this->refreshToken();

    $id_token = $this->token('id_token');
    $id_token = $this->esia_base64urldecode($id_token);
    list($header, $payload, $signature) = explode('.', $id_token);
    $header = json_decode(base64_decode($header));
    $payload = json_decode(base64_decode($payload));
    // TODO: add signature check.

    $oid = $payload->{'urn:esia:sbj'}->{'urn:esia:sbj:oid'};
    $data = $this->api->api('/rs/prns/' . $oid);

    // if ( ! isset( $data->response->user->id ) ){
    //   throw new Exception( "User profile request failed! {$this->providerId} returned an invalid response.", 6 );
    // }

    $this->user->profile->identifier    = $oid;
    $this->user->profile->firstName     = $data->firstName;
    $this->user->profile->lastName      = $data->lastName;
    $this->user->profile->displayName   = trim( $this->user->profile->firstName . " " . $this->user->profile->lastName );
    // $this->user->profile->photoURL      = $data->photo;
    // $this->user->profile->profileURL    = '';
    $this->user->profile->gender        = $data->gender;
    // $this->user->profile->city          = $data->homeCity;
    // $this->user->profile->email         = $data->contact->email;
    // $this->user->profile->emailVerified = $data->contact->email;

    return $this->user->profile;
  }

  /**
   * Generate UUID.
   * @link http://stackoverflow.com/a/15875555
   */
  public function esia_uuid() {
    $data = openssl_random_pseudo_bytes(16);

    $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
  }

  public function esia_client_secret($string) {
    $input_file = tempnam(sys_get_temp_dir(), 'ESIA_');
    $output_file = tempnam(sys_get_temp_dir(), 'ESIA_');
    $fp = fopen($input_file, 'w');
    fwrite($fp, $string);
    fclose($fp);

    if (openssl_pkcs7_sign($input_file, $output_file,
      'file://' . $this->config['certificate_path'],
      array(
        'file://' . $this->config['private_key_path'],
        $this->config['private_key_pass'],
      ),
      array())) {
      $signature = file_get_contents($output_file);
      $signature = explode("\n\n", $signature);
      $signature = explode("\n", $signature[3]);
      $signature = implode('', $signature);
      return $signature;
    }
    return FALSE;
  }

  /**
   * Make base64 encoded string URL safe.
   * @link http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-02#appendix-B
   */
  public function esia_base64urlencode($string) {
    $string = strtr($string, '+/=', '-_,');
    return $string;
  }

  /**
   * Convert back from URL safe to usual base64 encoded string.
   */
  public function esia_base64urldecode($string) {
    $string = strtr($string, '-_,', '+/=');
    return $string;
  }
}

/**
 * Modified OAuth2Client from HybridAuth library.
 */
class ESIA_OAuth2Client
{
  public $api_base_url     = "";
  public $authorize_url    = "";
  public $token_url        = "";
  public $token_info_url   = "";

  public $client_id        = "" ;
  public $client_secret    = "" ;
  public $redirect_uri     = "" ;
  public $access_token     = "" ;
  public $refresh_token    = "" ;

  public $access_token_expires_in = "" ;
  public $access_token_expires_at = "" ;

  //--

  public $sign_token_name          = "access_token";
  public $decode_json              = true;
  public $curl_time_out            = 30;
  public $curl_connect_time_out    = 30;
  public $curl_ssl_verifypeer      = false;
  public $curl_header              = array();
  public $curl_useragent           = "OAuth/2 Simple PHP Client v0.1; HybridAuth http://hybridauth.sourceforge.net/";
  public $curl_authenticate_method = "POST";
  public $curl_proxy               = null;

  //--

  public $http_code             = "";
  public $http_info             = "";

  //--

  public function __construct( $client_id = false, $client_secret = false, $redirect_uri='' )
  {
    $this->client_id     = $client_id;
    $this->client_secret = $client_secret;
    $this->redirect_uri  = $redirect_uri;
  }

  public function authorizeUrl( $extras = array() )
  {
    $params = array(
      "client_id"     => $this->client_id,
      "redirect_uri"  => $this->redirect_uri,
      "response_type" => "code"
    );

    if( count($extras) )
      foreach( $extras as $k=>$v )
        $params[$k] = $v;

    return $this->authorize_url . "?" . http_build_query( $params );
  }

  public function authenticate( $code , $extras = array() )
  {
    $params = array(
      "client_id"     => $this->client_id,
      "client_secret" => $this->client_secret,
      "grant_type"    => "authorization_code",
      "redirect_uri"  => $this->redirect_uri,
      "code"          => $code
    );

    if( count($extras) )
      foreach( $extras as $k=>$v )
        $params[$k] = $v;

    $response = $this->request( $this->token_url, $params, $this->curl_authenticate_method );

    $response = $this->parseRequestResult( $response );

    if( ! $response || ! isset( $response->access_token ) ){
      throw new Exception( "The Authorization Service has return: " . $response->error );
    }

    if (isset ($response->id_token)) {
      $this->id_token = $response->id_token;
      // list($header, $payload, $signature) = explode('.', $response->id_token);
    }

    if( isset( $response->access_token  ) ) $this->access_token           = $response->access_token;
    if( isset( $response->refresh_token ) ) $this->refresh_token           = $response->refresh_token;
    if( isset( $response->expires_in    ) ) $this->access_token_expires_in = $response->expires_in;

    // calculate when the access token expire
    if( isset($response->expires_in)) {
      $this->access_token_expires_at = time() + $response->expires_in;
    }

    return $response;
  }

  public function authenticated()
  {
    if ( $this->access_token ){
      if ( $this->token_info_url && $this->refresh_token ){
        // check if this access token has expired,
        $tokeninfo = $this->tokenInfo( $this->access_token );

        // if yes, access_token has expired, then ask for a new one
        if( $tokeninfo && isset( $tokeninfo->error ) ){
          $response = $this->refreshToken( $this->refresh_token );

          // if wrong response
          if( ! isset( $response->access_token ) || ! $response->access_token ){
            throw new Exception( "The Authorization Service has return an invalid response while requesting a new access token. given up!" );
          }

          // set new access_token
          $this->access_token = $response->access_token;
        }
      }

      return true;
    }

    return false;
  }

  /**
   * Format and sign an oauth for provider api
   */
  public function api( $url, $method = "GET", $parameters = array() )
  {
    if ( strrpos($url, 'http://') !== 0 && strrpos($url, 'https://') !== 0 ) {
      $url = $this->api_base_url . $url;
    }

    // $parameters[$this->sign_token_name] = $this->access_token;
    $this->curl_header = array('Authorization: Bearer ' . $this->access_token);
    $response = null;

    switch( $method ){
      case 'GET'  : $response = $this->request( $url, $parameters, "GET"  ); break;
      case 'POST' : $response = $this->request( $url, $parameters, "POST" ); break;
    }

    if( $response && $this->decode_json ){
      $response = json_decode( $response );
    }

    return $response;
  }

  /**
   * GET wrappwer for provider apis request
   */
  function get( $url, $parameters = array() )
  {
    return $this->api( $url, 'GET', $parameters );
  }

  /**
   * POST wreapper for provider apis request
   */
  function post( $url, $parameters = array() )
  {
    return $this->api( $url, 'POST', $parameters );
  }

  // -- tokens
  public function tokenInfo($accesstoken)
  {
    $params['access_token'] = $this->access_token;
    $response = $this->request( $this->token_info_url, $params );
    return $this->parseRequestResult( $response );
  }

  public function refreshToken( $parameters = array() )
  {
    $params = array(
      "client_id"     => $this->client_id,
      "client_secret" => $this->client_secret,
      "grant_type"    => "refresh_token"
    );

    foreach($parameters as $k=>$v ){
      $params[$k] = $v;
    }

    $response = $this->request( $this->token_url, $params, "POST" );
    return $this->parseRequestResult( $response );
  }

  // -- utilities

  private function request( $url, $params=false, $type="GET" )
  {
    Hybrid_Logger::info( "Enter OAuth2Client::request( $url )" );
    Hybrid_Logger::debug( "OAuth2Client::request(). dump request params: ", serialize( $params ) );

    if( $type == "GET" ){
      $url = $url . ( strpos( $url, '?' ) ? '&' : '?' ) . http_build_query( $params );
    }

    $this->http_info = array();
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL            , $url );
    curl_setopt($ch, CURLOPT_RETURNTRANSFER , 1 );
    curl_setopt($ch, CURLOPT_TIMEOUT        , $this->curl_time_out );
    curl_setopt($ch, CURLOPT_USERAGENT      , $this->curl_useragent );
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT , $this->curl_connect_time_out );
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER , $this->curl_ssl_verifypeer );
    curl_setopt($ch, CURLOPT_HTTPHEADER     , $this->curl_header );

    if($this->curl_proxy){
      curl_setopt( $ch, CURLOPT_PROXY        , $this->curl_proxy);
    }

    if( $type == "POST" ){
      // curl_setopt($ch, CURLOPT_HEADER, 1);
      curl_setopt($ch, CURLOPT_POST, 1);
      // We need to set postfields as string, that is why http_build_query().
      if($params) curl_setopt( $ch, CURLOPT_POSTFIELDS, http_build_query($params) );
    }

    $response = curl_exec($ch);
    Hybrid_Logger::debug( "OAuth2Client::request(). dump request info: ", serialize( curl_getinfo($ch) ) );
    Hybrid_Logger::debug( "OAuth2Client::request(). dump request result: ", serialize( $response ) );

    $this->http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $this->http_info = array_merge($this->http_info, curl_getinfo($ch));

    curl_close ($ch);

    return $response;
  }

  private function parseRequestResult( $result )
  {
    if( json_decode( $result ) ) return json_decode( $result );

    parse_str( $result, $ouput );

    $result = new StdClass();

    foreach( $ouput as $k => $v )
      $result->$k = $v;

    return $result;
  }
}
