<?php


class Authorization
{

    public $auth_code_lifetime = 10000;//sec

    /*
     * begin --> senler.ru/oauth2/authorize?response_type=code&client_id=1937553&state=user&scope=delivery bots leads&redirect_uri=http://app.com/callback_senler
     *
     * end   --> "http://app.com/callback_senler?code=1f9572946684b4b15d8b01cd427fb378def07fd8&state=user"
     */

    public function begin()
    {
        $is_authorized = (Service\Sessions::getAuthUser()) ? true : false; //user дб залогинен в senler
        if ($is_authorized === false) {
            return false;
        }
        $user_id = VkSender / Core / App::getUserId(); // authorization_codes привязывается к user_id
        $state = $_REQUEST['state'];
        $scope = $_REQUEST['scope'];
        $client_id = $_REQUEST['client_id'];


        $clientData = $this->db->prepare(sprintf('SELECT * from oauth_clients where client_id = :client_id'));
        if (!$clientData) {
            return false;
        }


        if (!$this->validateRedirectUri($_REQUEST['redirect_uri'], $clientData['redirect_uri'])) {
            return false;
        };

        if (!$this->checkScope($scope, $clientData['scope'])) {
            return false;
        };

        $params = array(
            'scope' => $scope,
            'state' => $state,
            'client_id' => $client_id,
            'redirect_uri' => $clientData['redirect_uri']
        );

        $code = $this->generateAuthorizationCode();
        $code_ = $this->db->prepare(sprintf('SELECT * from oauth_authorization_codes where authorization_code = :code'));

        $expires = date('Y-m-d H:i:s', time() + $this->auth_code_lifetime);
        if ($code_) {
            $stmt = $this->db->prepare($sql = sprintf('UPDATE oauth_authorization_codes SET client_id=:client_id, user_id=:user_id, redirect_uri=:redirect_uri, expires=:expires, scope=:scope where authorization_code=:code'));
        } else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO oauth_authorization_codes (authorization_code, client_id, user_id, redirect_uri, expires, scope) VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope)'));
        }


        header("Location: http://{$clientData['redirect_uri']}/?code={$code}&state={$state}");
        exit;

    }


    ///helpers


    public function checkScope($required_scope, $available_scope)
    {
        $required_scope = explode(' ', trim($required_scope));
        $available_scope = explode(' ', trim($available_scope));

        return (count(array_diff($required_scope, $available_scope)) == 0);
    }

    protected function generateAuthorizationCode()
    {
        $tokenLen = 40;
        if (function_exists('random_bytes')) {
            $randomData = random_bytes(100);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $randomData = openssl_random_pseudo_bytes(100);
        } elseif (function_exists('mcrypt_create_iv')) {
            $randomData = mcrypt_create_iv(100, MCRYPT_DEV_URANDOM);
        } elseif (@file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 100) . uniqid(mt_rand(), true);
        } else {
            $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);
        }

        return substr(hash('sha512', $randomData), 0, $tokenLen);
    }

    private function validateRedirectUri($inputUri, $registeredUriString)
    {
        if (!$inputUri || !$registeredUriString) {
            return false; // if either one is missing, assume INVALID
        }

        $registered_uris = preg_split('/\s+/', $registeredUriString);
        foreach ($registered_uris as $registered_uri) {
            if (strcmp($inputUri, $registered_uri) === 0) {
                return true;

            } else {
                $registered_uri_length = strlen($registered_uri);
                if ($registered_uri_length === 0) {
                    return false;
                }

                // the input uri is validated against the registered uri using case-insensitive match of the initial string
                // i.e. additional query parameters may be applied
                if (strcasecmp(substr($inputUri, 0, $registered_uri_length), $registered_uri) === 0) {
                    return true;
                }
            }
        }

        return false;
    }


}