<?php

namespace Cockpit\Controller;

class RestApi extends \LimeExtra\Controller {

    protected function before() {
        $this->app->response->mime = 'json';
    }

    public function authUser() {

        $data = [ 'user' => $this->param('user'), 'password' => $this->param('password') ];

        if (!$data['user'] || !$data['password']) {
            return $this->stop('{"error": "Missing user or password"}', 412);
        }

        $user = $this->module('cockpit')->authenticate($data);

        if (!$user) {
            return $this->stop('{"error": "The email address or password you entered is incorrect!<br/>Or maybe your account is not verified yet."}', 401);
        }
  
        $token = array();
        $token['whoisit'] = $user["_id"];
        $token['expire'] = time() + (15 * 60); // 15 minutes;

        return ["user" => $user, "jwt" => \Firebase\JWT\JWT::encode($token, COCKPIT_JWT)];
    }

    public function isLogged() {
        $data = [ "jwt" => $this->param('jwt') ];
        
        if (!$data['jwt']) {
            return $this->stop('{"error": "Missing jwt"}', 412);
        }

        $token = \Firebase\JWT\JWT::decode($data['jwt'], COCKPIT_JWT, ["HS256"]);
        
        //check expiration
        if($token->expire < time()) {
            return $this->stop('{"error": "jwt expired"}', 401);
        }

        $user = $this->storage->findOne("cockpit/accounts", ["_id" => $token->whoisit]);
        unset($user["password"]);
 
        return ["user" => $user];
    }

    public function saveUser() {
        $data = $this->param("user", false);
        $user = $this->module('cockpit')->getUser();

        if (!$data) {
            return false;
        }

        if ($user) {

            if (!isset($data["_id"]) && !$this->module('cockpit')->isSuperAdmin()) {
                return $this->stop(401);
            }

            if (!$this->module('cockpit')->isSuperAdmin() && $data["_id"] != $user["_id"] ) {
                return $this->stop(401);
            }
        }

        // new user needs a password
        if (!isset($data["_id"])) {

            // new user needs a password
            if (!isset($data["password"])) {
                return $this->stop('{"error": "User password required"}', 412);
            }

            // new user needs a username
            if (!isset($data["user"])) {
                return $this->stop('{"error": "User nickname required"}', 412);
            }

            $data = array_merge($account = [
                "user"     => "admin",
                "name"     => "",
                "email"    => "",
                "active"   => true,
                "group"    => "user",
                "i18n"     => "en"
            ], $data);

            if (isset($data['api_key'])) {
                $data['api_key'] = uniqid('account-').uniqid();
            }

            // check for duplicate users
            if ($user = $this->app->storage->findOne("cockpit/accounts", ["user" => $data["user"]])) {
                return $this->stop('{"error": "Sorry, this email already exists!"}', 412);
            }
        }

        if (isset($data["password"])) {

            if (strlen($data["password"])){
                $data["password"] = $this->app->hash($data["password"]);
            } else {
                unset($data["password"]);
            }
        }

        $data["_modified"] = time();

        if (!isset($data['_id'])) {
            $data["_created"] = $data["_modified"];
        }
        
        $data["hash"] = password_hash($data["email"], PASSWORD_DEFAULT);
        $this->app->storage->save("cockpit/accounts", $data);

        if (isset($data["password"])) {
            unset($data["password"]);
        }

        //verify links
        $urls = ["verify.html", "verify_plain.html"];
        $bodies = array();

        foreach($urls as $url) {
            $body = file_get_contents(COCKPIT_DIR."/mail_templates/".$url);
            $body = preg_replace("/{{server}}/", $this->app->config["fiiiirst"]["host"], $body);
            $body = preg_replace("/{{name}}/", $data["name"], $body);
            $body = preg_replace("/{{code}}/", preg_replace('/@/', "~", $data["email"]), $body);

            array_push($bodies, $body);
        }

        return $this->app->mailer->mail($data["email"], "Activating your account", $bodies[0], ["alt_body" => $bodies[1]]);
    }

    public function verifyEmail() {
        $data = [
            "email" => $this->param('email')
        ];
        
        if (!$data['email']) {
            return $this->stop('{"error": "Missing email"}', 412);
        }

        //check if the key is correct
        $user = $this->storage->findOne("cockpit/accounts", ["email" => $data['email']]);
        
        if(!$user) {
            return $this->stop('{"error": "Sorry, there is a problem with your account. Please contact me at guillaume@fiiiirst.com"}', 412);
        }

        if(!password_verify($data["email"], $user["hash"])) {
            return $this->stop('{"error": "Sorry, this link is not valid."}', 412);
        }

        unset($user["hash"]);
        
        if($user["active"]) {
            return $this->stop('{"warning": "Thank you, your account is already activated!"}', 412);
        }

        $user["active"] = true;

        $this->app->storage->save("cockpit/accounts", $user);
        
        if (isset($user["password"])) {
            unset($user["password"]);
        }
 
        return $user;
    }

    public function listUsers() {

        $user = $this->module('cockpit')->getUser();

        if ($user) {
            // Todo: user specific checks
        }

        $options = ["sort" => ["user" => 1]];

        if ($filter = $this->param('filter')) {

            $options['filter'] = $filter;

            if (is_string($filter)) {

                $options['filter'] = [
                    '$or' => [
                        ['name' => ['$regex' => $filter]],
                        ['user' => ['$regex' => $filter]],
                        ['email' => ['$regex' => $filter]],
                    ]
                ];
            }
        }

        $accounts = $this->storage->find("cockpit/accounts", $options)->toArray();

        foreach ($accounts as &$account) {
            unset($account["password"]);
        }

        return $accounts;
    }

    public function image() {

        $options = [
            'src' => $this->param('src', false),
            'mode' => $this->param('m', 'thumbnail'),
            'width' => intval($this->param('w', null)),
            'height' => intval($this->param('h', null)),
            'quality' => intval($this->param('q', 100)),
            'rebuild' => intval($this->param('r', false)),
            'base64' => intval($this->param('b64', false)),
            'output' => intval($this->param('o', false)),
            'domain' => intval($this->param('d', false)),
        ];

        foreach([
            'blur', 'brighten',
            'colorize', 'contrast',
            'darken', 'desaturate',
            'edge detect', 'emboss',
            'flip', 'invert', 'opacity', 'pixelate', 'sepia', 'sharpen', 'sketch'
        ] as $f) {
            if ($this->param($f)) $options[$f] = $this->param($f);
        }

        return $this->module('cockpit')->thumbnail($options);
    }

    public function assets() {

        $options = [
            'sort' => ['created' => -1]
        ];

        if ($filter = $this->param("filter", null)) $options["filter"] = $filter;
        if ($fields = $this->param('fields', null)) $options['fields'] = $fields;
        if ($limit  = $this->param("limit", null))  $options["limit"] = $limit;
        if ($sort   = $this->param("sort", null))   $options["sort"] = $sort;
        if ($skip   = $this->param("skip", null))   $options["skip"] = $skip;

        $assets = $this->storage->find("cockpit/assets", $options);
        $total  = (!$skip && !$limit) ? count($assets) : $this->storage->count("cockpit/assets", $filter);

        $this->app->trigger('cockpit.assets.list', [&$assets]);

        return [
            'assets' => $assets->toArray(),
            'total' => $total
        ];
    }

}
