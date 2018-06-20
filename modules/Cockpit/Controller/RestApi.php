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

        $data["group"] = ($data['user'] === "guillaume@fiiiirst.com") ? "admin" : "photographer";

        $user = $this->module('cockpit')->authenticate($data);

        if (!$user) {
            return $this->stop('{"error": "The email address or password you entered is incorrect!<br/>Or maybe your account is not verified yet."}', 401);
        }
  
        $token = array();
        $token['whoisit'] = $user["_id"];
        $token['group'] = $user["group"];
        $token['expire'] = time() + (30 * 60); // 30 minutes;

        return ["user" => $user, "jwt" => \Firebase\JWT\JWT::encode($token, $this->app->config["fiiiirst"]["jwt"])];
    }

    public function isLogged() {
        $data = [ "jwt" => $this->param('jwt'), "group" => $this->param("group")];
        
        if (!$data['jwt']) {
            return $this->stop('{"error": "Missing jwt"}', 412);
        }

        $token = \Firebase\JWT\JWT::decode($data['jwt'], $this->app->config["fiiiirst"]["jwt"], ["HS256"]);
        
        //check expiration
        if($token->expire < time()) {
            return $this->stop('{"error": "jwt expired"}', 401);
        }

        $new_token = array();
        $new_token['whoisit'] = $token->whoisit;
        $new_token['group'] = $token->group;
        $new_token['expire'] = time() + (30 * 60); // 30 minutes;

        $user = $this->storage->findOne("cockpit/accounts", ["_id" => $token->whoisit, "group" => $data["group"] ? $data["group"] : $token->group]);
        unset($user["password"]);
 
        return ["user" => $user, "jwt" => \Firebase\JWT\JWT::encode($new_token, $this->app->config["fiiiirst"]["jwt"])];
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

            //create an api_key directly
            $data['api_key'] = uniqid('account-').uniqid();
            
            // check for duplicate users
            if ($user = $this->app->storage->findOne("cockpit/accounts", ["user" => $data["user"]])) {
                return $this->stop('{"error": "Sorry, this email already exists!"}', 412);
            }
        }

        if (isset($data["password"])) {

            if (strlen($data["password"])){
                $data["password"] = $this->app->hash($data["password"], PASSWORD_DEFAULT);
            } else {
                unset($data["password"]);
            }
        }

        $data["_modified"] = time();

        if (!isset($data['_id'])) {
            $data["_created"] = $data["_modified"];
        }
        
        $this->app->storage->save("cockpit/accounts", $data);

        if (isset($data["password"])) {
            unset($data["password"]);
        }

        //---create photography entry
        $photographer = $this->module('collections')->save("photographers", [
            'name' => $data["name"],
            'starting_month' => "*",
            'edition' => $this->app->config["fiiiirst"]["edition"],
            'email' => $data["email"]
        ]);

        //verify links
        $urls = ["verify.html", "verify_plain.html"];
        $bodies = array();

        $token = array();
        $token['whoisit'] = $data["_id"];
        $token['group'] = $data["group"];
        $jwt = \Firebase\JWT\JWT::encode($token, $this->app->config["fiiiirst"]["jwt"]);

        foreach($urls as $url) {
            $body = file_get_contents(COCKPIT_DIR."/mail_templates/".$url);
            $body = preg_replace("/{{server}}/", $this->app->config["fiiiirst"]["host"], $body);
            $body = preg_replace("/{{name}}/", $data["name"], $body);
            $body = preg_replace("/{{code}}/", $jwt, $body);

            array_push($bodies, $body);
        }

        //send email
        return $this->app->mailer->mail($data["email"], "Activating your account", $bodies[0], ["alt_body" => $bodies[1]]);
    }

    public function resetPassword() {
        $email = $this->param("email");
        
        if (!$email) {
            return $this->stop('{"error": "Missing email"}', 412);
        }

        //get user from mail
        $user = $this->storage->findOne("cockpit/accounts", ["email" => $email]);

        if(!$user) {
            return $this->stop('{"error": "This email is not registered in our system!<br/>Please try again!"}', 412);
        }

        //createthe jwt token
        $token = array();
        $token['whoisit'] = $user["_id"];
        $token['group'] = $user["group"];
        $token['expire'] = time() + (60 * 60); // 1h
        $jwt = \Firebase\JWT\JWT::encode($token, $this->app->config["fiiiirst"]["jwt"]);
        
        //verify links
        $urls = ["reset_password.html", "reset_password_plain.html"];
        $bodies = array();

        foreach($urls as $url) {
            $body = file_get_contents(COCKPIT_DIR."/mail_templates/".$url);
            $body = preg_replace("/{{server}}/", $this->app->config["fiiiirst"]["host"], $body);
            $body = preg_replace("/{{name}}/", $user["name"], $body);
            $body = preg_replace("/{{code}}/", $jwt, $body);

            array_push($bodies, $body);
        }

        //send email
        return $this->app->mailer->mail($email, "Reset your password", $bodies[0], ["alt_body" => $bodies[1]]);
    }

    public function verifyEmail() {
        $data = [
            "jwt" => $this->param('jwt')
        ];
        
        if (!$data['jwt']) {
            return $this->stop('{"error": "Missing jwt"}', 412);
        }

        //check if the jwt is correct
        $token = \Firebase\JWT\JWT::decode($data['jwt'], $this->app->config["fiiiirst"]["jwt"], ["HS256"]);

        //check if the key is correct
        $user = $this->storage->findOne("cockpit/accounts", ["_id" => $token->whoisit]);
        
        if(!$user) {
            return $this->stop('{"error": "Sorry, there is a problem with your account. Please contact me at guillaume@fiiiirst.com"}', 412);
        }

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

    public function verifyLostPassLink() {
        $data = [
            "jwt" => $this->param('code')
        ];
        
        if (!$data['jwt']) {
            return $this->stop('{"error": "Missing JWT"}', 412);
        }

        //check if the jwt is correct
        $token = \Firebase\JWT\JWT::decode($data['jwt'], $this->app->config["fiiiirst"]["jwt"], ["HS256"]);
        
        //check expiration
        if($token->expire < time()) {
            return $this->stop('{"error": "Sorry, this link to reset your password has expired.<br/>Please, send a new request to reset."}', 401);
        }

        $user = $this->storage->findOne("cockpit/accounts", ["_id" => $token->whoisit]);
        
        if(!$user) {
            return $this->stop('{"error": "Sorry, this link is not valid.<br/>Please contact me at guillaume@fiiiirst.com"}', 412);
        }

        if (isset($user["password"])) unset($user["password"]);
        if (isset($user["api_key"])) unset($user["api_key"]);

        return $user;
    }

    public function savePassword() {
        $data = [
            "password" => $this->param('password'),
            "jwt" => $this->param('jwt')
        ];
        
        if (!$data['password'] || !$data['jwt']) {
            return $this->stop('{"error": "Missing parameters"}', 412);
        }

        //check if the jwt is correct
        $token = \Firebase\JWT\JWT::decode($data['jwt'], $this->app->config["fiiiirst"]["jwt"], ["HS256"]);

        //get user
        $user = $this->storage->findOne("cockpit/accounts", ["_id" => $token->whoisit]);
       
        if(!$user) {
            return $this->stop('{"error": "Sorry, there is a problem with your account.<br/>Please contact me at guillaume@fiiiirst.com"}', 412);
        }

        $user["password"] = $this->app->hash($data["password"], PASSWORD_DEFAULT);
        
        $this->app->storage->save("cockpit/accounts", $user);

        if (isset($user["password"])) unset($user["password"]);
        if (isset($user["api_key"])) unset($user["api_key"]);

        return $user;
    }

    public function upload() {
       
        if(empty($_FILES)) return $this->stop('{"error": "Your request to upload is not valid"}', 412);
        $id = $this->param('_id');

        if(!$id) return $this->stop('{"error": "Missing user id"}', 412);
        
        $photographer = $this->module('collections')->find("photographers", ['filter' => ["_id" => $id]]);
        
        if(!count($photographer)) return $this->stop('{"error": "Sorry, we can\'t find your profile."}', 412);
        
        //upload File
        $photographer = $photographer[0];
        $user_slug = $photographer["name_slug"];
        
        if(count($photographer["uploads"]) >= 15) return $this->stop('{"error": "Sorry, you cannot upload more than 15 pictures"}', 412);
        
        $path = $this->app->path('#folios:')."_".$user_slug;
        $generatedpath = $this->app->path('#folios:').$user_slug;
        
        //create folders
        if (!is_dir($path)) mkdir($path);
        if (!is_dir($generatedpath)) mkdir($generatedpath);
        
        $total_files = count($_FILES["file"]["name"]);
        
        for($i=0;$i<$total_files;$i++)
        {
            $filename = preg_replace('/[^a-zA-Z0-9-_\.]/','', str_replace(' ', '-', $_FILES['file']['name'][$i]));
            $filename = rand(0, 1000)."_".$filename;
            $tempFile = $_FILES['file']['tmp_name'][$i];
            $targetpath = $path."/".$filename;
            
            if(!move_uploaded_file($tempFile,$targetpath)) {
                return $this->stop('{"error": "There was an error during the upload of the picture '.$_FILES['file']['name'][$i].'"}', 412);
            }
       
            //---create thumbnails
            $options = array(
                "cachefolder" => $path,
                "src" => preg_replace("/".addcslashes(COCKPIT_SITE_DIR, "/")."/", "", $targetpath),
                "mode" => "resize",
                "width" => 200,
            );
    
            $thumbnail = $this->module('cockpit')->thumbnail($options);
       
            if(!isset($photographer["uploads"])) $photographer["uploads"] = [];
            $photographer["uploads"][] = ["original" => $options["src"], "width" => getimagesize("http://".$this->app->config["fiiiirst"]["api"].$options["src"])[0], "thumb" => $thumbnail];
        }


        // ---update photography entry
        $photographer = $this->module('collections')->save("photographers", $photographer);

        return json_encode($photographer, JSON_PRETTY_PRINT);
    }

    public function removePicture() {
        $data = $this->param('data');
        if(!$data) return $this->stop('{"error": "Missing data"}', 412);

        //--remove both pictures
        if(is_file(COCKPIT_SITE_DIR.$data["asset"]["original"])) {
            $original = unlink(COCKPIT_SITE_DIR.$data["asset"]["original"]);

            if(!$original) return $this->stop('{"error": "Error when removing original picture"}', 412);
        }

        if(is_file(COCKPIT_SITE_DIR.$data["asset"]["thumb"])) {
            $thumb = unlink(COCKPIT_SITE_DIR.$data["asset"]["thumb"]);

            if(!$thumb) return $this->stop('{"error": "Error when removing thumb picture"}', 412);
        }

        //--return the list
        $photographer = $this->module('collections')->save("photographers", $data["profile"]);
        return json_encode($photographer, JSON_PRETTY_PRINT);
    }

    public function sendEmail() {
        
        $urls;
        $title;
        $bodies = array();
        
        $type = $this->param('type');
        if(!$type) return $this->stop('{"error": "Missing param1"}', 412);

        $photographers = $this->param('photographers');
        if(!$photographers) return $this->stop('{"error": "Missing param2"}', 412);

        $date = $this->param('date');
        if(!$date) return $this->stop('{"error": "Missing param3"}', 412);

        switch($type) {
            case "em-created":
            $urls = ["duo_created.html", "duo_created_plain.html"];
            $title = "Your discussion is going to start on ".date("m-Y", strtotime($date));
            
            foreach($photographers as $author) {
                foreach($urls as $url) {
                    $body = file_get_contents(COCKPIT_DIR."/mail_templates/".$url);
                    $body = preg_replace("/{{server}}/", $this->app->config["fiiiirst"]["host"], $body);
                    $body = preg_replace("/{{name}}/", $author["name"], $body);
                    $body = preg_replace("/{{date}}/", date("F Y", strtotime($date)), $body);
                    
                    array_push($bodies, $body);
                }
            }
            
            break;

            case "em-reminder":
            $urls= ["duo_reminder.html", "duo_reminder_plain.html"];
            $title = "Fiiiirst - Reminder";
            
            foreach($photographers as $author) {
                foreach($urls as $url) {
                    $body = file_get_contents(COCKPIT_DIR."/mail_templates/".$url);
                    $body = preg_replace("/{{server}}/", $this->app->config["fiiiirst"]["host"], $body);
                    $body = preg_replace("/{{name}}/", $author["name"], $body);
                    $body = preg_replace("/{{date}}/", date("F Y", strtotime($date)), $body);
                    
                    array_push($bodies, $body);
                }
            }
            break;

            case "em-1week-reminder":
            $urls= ["duo_week_reminder_first.html", "duo_week_reminder_first_plain.html", "duo_week_reminder.html", "duo_week_reminder_plain.html"];
            $title = "Fiiiirst - Your discussion is going to start in 7 days!";
            
            $i = 0;
            foreach($urls as $url) {
                $author = ($i < 2) ? $photographers[0] : $photographers[1];
                $body = file_get_contents(COCKPIT_DIR."/mail_templates/".$url);
                $body = preg_replace("/{{server}}/", $this->app->config["fiiiirst"]["host"], $body);
                $body = preg_replace("/{{name}}/", $author["name"], $body);
                
                array_push($bodies, $body);
                $i++;
            }
            break;

            case "em-activated":
            $urls= ["discussion_activated_first.html", "discussion_activated_first_plain.html", "discussion_activated.html", "discussion_activated_plain.html"];
            $title = "Fiiiirst - Your discussion can start now!";
            
            $i = 0;
            foreach($urls as $url) {
                $author = ($i < 2) ? $photographers[0] : $photographers[1];
                $body = file_get_contents(COCKPIT_DIR."/mail_templates/".$url);
                $body = preg_replace("/{{server}}/", $this->app->config["fiiiirst"]["host"], $body);
                $body = preg_replace("/{{name}}/", $author["name"], $body);
                
                array_push($bodies, $body);
                $i++;
            }
            break;

            case "em-published":
            $urls = ["discussion_published.html", "discussion_published_plain.html"];
            $title = "Fiiiirst: Publication!";

            foreach($photographers as $author) {
                foreach($urls as $url) {
                    $body = file_get_contents(COCKPIT_DIR."/mail_templates/".$url);
                    $body = preg_replace("/{{server}}/", $this->app->config["fiiiirst"]["host"], $body);
                    $body = preg_replace("/{{final}}/", $this->app->config["fiiiirst"]["host_min"].'/discussion/'.$photographers[0]["name_slug"]."-".$photographers[1]["name_slug"], $body);
                    
                    array_push($bodies, $body);
                }
            }
            break;

            case "remindAuthor":
            $urls = ["author_reminder.html", "author_reminder_plain.html"];
            $title = "Fiiiirst - Reminder";

            $turn = $this->param('turn');
            if(!$turn) return $this->stop('{"error": "Missing param4"}', 412);
            
            foreach($photographers as $author) {
                if($author["_id"] === $turn["_id"]) {
                    foreach($urls as $url) {
                        $body = file_get_contents(COCKPIT_DIR."/mail_templates/".$url);
                        $body = preg_replace("/{{server}}/", $this->app->config["fiiiirst"]["host"], $body);
                        $body = preg_replace("/{{name}}/", $author["name"], $body);
                        
                        array_push($bodies, $body);
                    }
                }
            }
            break;

            case "em-portfolio-reminder":
            $urls = ["author_portfolio_reminder.html", "author_portfolio_reminder_plain.html"];
            $title = "Fiiiirst - Portfolio Reminder";

            foreach($photographers as $author) {
                foreach($urls as $url) {
                    $body = file_get_contents(COCKPIT_DIR."/mail_templates/".$url);
                    $body = preg_replace("/{{server}}/", $this->app->config["fiiiirst"]["host"], $body);
                    $body = preg_replace("/{{name}}/", $author["name"], $body);
                    
                    array_push($bodies, $body);
                }
            }
            break;
        } 
 
        //send email
        if($type === "remindAuthor") {
            foreach($photographers as $author) {
                if($author["_id"] === $turn["_id"]) {
                    return $this->app->mailer->mail($author["email"], $title, $bodies[0], ["alt_body" => $bodies[1]]);
                }
            }
        }
        else if($type == "em-portfolio-reminder") {
            foreach($photographers as $author) {
                return $this->app->mailer->mail($author["email"], $title, $bodies[0], ["alt_body" => $bodies[1]]);
            }
        }
        else {
            $i = 0;
            foreach($photographers as $author) {
    
                if(!$this->app->mailer->mail($author["email"], $title, $bodies[$i], ["alt_body" => $bodies[$i+1]])) {
                    return $this->stop('{"error": "Email error"}', 412);
                }
                
                $i += 2;
            }
    
            return 1;
        }
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
            'path' => $this->param('path', false),
            'cachefolder' => $this->param('cachefolder', false)
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
