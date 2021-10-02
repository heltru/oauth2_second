<?php


class Token
{
    public $access_lifetime = 10000;//sec

/*
 * begin --> https://senler.ru/oauth2/token&code=1f9572946684b4b15d8b01cd427fb378def07fd8
 * end -- {"access_token":"03807cb390319329bdf6c777d4dfae9c0d3b3c35","expires_in":3600,"scope":delivery bot lead stat}
 *
 * */
    //
    public function begin(){

        $clientParams = ['client_secret'=>$_REQUEST['client_secret'],'client_id'=>$_REQUEST['client_id']];

        $clientData = $this->db->prepare(sprintf('SELECT * from oauth_clients where client_id = :client_id'));
         
        if ($clientData['client_secret'] != $clientParams['client_secret']){
            return  false;
        }

        $code = $_REQUEST('code');

        $authCode = $this->db->prepare(sprintf('SELECT * from oauth_authorization_codes where authorization_code = :code'));
        if ($authCode) {
            $authCode['expires'] = strtotime($code['expires']);
        }
        if (urldecode($_REQUEST['redirect_uri']) != urldecode($authCode['redirect_uri'])){
            return  false;
        }
        if ($authCode["expires"] < time()) {
              return false;
        }
        if ($authCode['clientId'] != $clientData['client_id']){
            return false;
        }

        $requestedScope = $_REQUEST['scope'];
        $availableScope = $clientData['scope'];
        if (!$this->checkScope($requestedScope, $availableScope)){
            $scope = $this->getDefaultScope($clientData['client_id']);
        } else {
            $scope = $availableScope;
        }

         $token = array(
             "access_token" => $this->generateAccessToken(),
             "expires_in" => $this->access_lifetime,
             "scope" => $scope
         );

        $expires = date('Y-m-d H:i:s', time() + $this->access_lifetime );
        $token = $this->db->prepare(sprintf('SELECT * from oauth_access_tokens where access_token = :access_token'));
        if ($token) {
            $token = $this->db->prepare(sprintf('UPDATE oauth_access_tokens SET client_id=:client_id, expires=:expires, user_id=:user_id, scope=:scope where access_token=:access_token'));
        } else {
            $token = $this->db->prepare(sprintf('INSERT INTO oauth_access_tokens (access_token, client_id, expires, user_id, scope) VALUES (:access_token, :client_id, :expires, :user_id, :scope)'));
        }

        header('Content-Type: application/json; charset=utf-8');
        $arr = [
            'access_token'=> $token['access_token'],
            'expires_in' => $expires
        ];

        echo json_encode($arr);

    }


    public function checkScope($required_scope, $available_scope)
    {
        $required_scope = explode(' ', trim($required_scope));
        $available_scope = explode(' ', trim($available_scope));

        return (count(array_diff($required_scope, $available_scope)) == 0);
    }

    public function getDefaultScope($client_id = null)
    {
        return 'delivery bot lead subscription lead_stat delivery_stat global_vars process utms';
    }

    protected function generateAccessToken()
    {
        if (function_exists('random_bytes')) {
            $randomData = random_bytes(20);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }
        if (function_exists('openssl_random_pseudo_bytes')) {
            $randomData = openssl_random_pseudo_bytes(20);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }
        if (function_exists('mcrypt_create_iv')) {
            $randomData = mcrypt_create_iv(20, MCRYPT_DEV_URANDOM);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }
        if (@file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 20);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }
        // Last resort which you probably should just get rid of:
        $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);

        return substr(hash('sha512', $randomData), 0, 40);
    }

}