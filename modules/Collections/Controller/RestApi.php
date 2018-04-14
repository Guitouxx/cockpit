<?php
namespace Collections\Controller;

class RestApi extends \LimeExtra\Controller {

    protected function before() {
        $this->app->response->mime = 'json';
    }

    public function get($collection=null) {

        if (!$collection) {
            return $this->stop('{"error": "Missing collection name"}', 412);
        }

        if (!$this->module('collections')->exists($collection)) {
            return $this->stop('{"error": "Collection not found"}', 412);
        }

        $collection = $this->module('collections')->collection($collection);
        $user = $this->module('cockpit')->getUser();

        if ($user) {

            if (!$this->module('collections')->hasaccess($collection['name'], 'entries_view')) {
                return $this->stop('{"error": "Unauthorized"}', 401);
            }
        }

        $options = [];

        if ($filter   = $this->param('filter', null))   $options['filter'] = $filter;
        if ($limit    = $this->param('limit', null))    $options['limit'] = intval($limit);
        if ($sort     = $this->param('sort', null))     $options['sort'] = $sort;
        if ($fields   = $this->param('fields', null))   $options['fields'] = $fields;
        if ($skip     = $this->param('skip', null))     $options['skip'] = intval($skip);
        if ($populate = $this->param('populate', null)) $options['populate'] = $populate;

        // cast string values if get request
        if ($filter && isset($_GET['filter'])) $options['filter'] = $this->_fixStringBooleanNumericValues($filter);
        if ($fields && isset($_GET['fields'])) $options['fields'] = $this->_fixStringBooleanNumericValues($fields);

        // fields filter
        $fieldsFilter = [];

        if ($fieldsFilter = $this->param('fieldsFilter', [])) $options['fieldsFilter'] = $fieldsFilter;
        if ($lang = $this->param('lang', false)) $fieldsFilter['lang'] = $lang;
        if ($ignoreDefaultFallback = $this->param('ignoreDefaultFallback', false)) $fieldsFilter['ignoreDefaultFallback'] = $ignoreDefaultFallback;
        if ($user) $fieldsFilter["user"] = $user;

        if (is_array($fieldsFilter) && count($fieldsFilter)) {
            $options['fieldsFilter'] = $fieldsFilter;
        }

        if (isset($options["sort"])) {

            foreach ($sort as $key => &$value) {
                $options["sort"][$key]= intval($value);
            }
        }

        $entries = $this->module('collections')->find($collection['name'], $options);

        // return only entries array - due to legacy
        if ((boolean) $this->param('simple', false)) {
            return $entries;
        }

        $fields = [];

        foreach ($collection['fields'] as $field) {

            if (
                $user && isset($field['acl']) &&
                is_array($field['acl']) && count($field['acl']) &&
                !(in_array($user['_id'] , $field['acl']) || in_array($user['group'] , $field['acl']))
            ) {
                continue;
            }

            $fields[$field['name']] = [
                'name' => $field['name'],
                'type' => $field['type'],
                'localize' => $field['localize'],
                'options' => $field['options'],
            ];
        }

        return [
            'fields'   => $fields,
            'entries'  => $entries,
            'total'    => (!$skip && !$limit) ? count($entries) : $this->module('collections')->count($collection['name'], $filter ? $filter : [])
        ];

        return $entries;
    }

    public function save($collection=null) {

        $user = $this->module('cockpit')->getUser();
        $data = $this->param('data', null);

        if (!$collection || !$data) {
            return false;
        }

        if (!$this->module('collections')->exists($collection)) {
            return $this->stop('{"error": "Collection not found"}', 412);
        }

        if ($user && !$this->module('collections')->hasaccess($collection, isset($data['_id']) ? 'entries_edit':'entries_create')) {
            return $this->stop('{"error": "Unauthorized"}', 401);
        }

        $data['_by'] = $this->module('cockpit')->getUser('_id');

        $data = $this->module('collections')->save($collection, $data);

        return $data;
    }

    public function remove($collection=null) {

        $user   = $this->module('cockpit')->getUser();
        $filter = $this->param('filter', null);
        $count  = $this->param('count', false);

        if (!$collection || !$filter) {
            return $this->stop('{"error": "Please provide a collection name and filter"}', 417);
        }

        // handele single item cases
        if (is_string($filter)) {
            $filter = ['_id' => $filter];
        } elseif (isset($filter['_id'])) {
            $filter = ['_id' => $filter['_id']];
        }

        if (!$this->module('collections')->exists($collection)) {
            return $this->stop('{"error": "Collection not found"}', 412);
        }

        if ($user && !$this->module('collections')->hasaccess($collection, 'entries_delete')) {
            return $this->stop('{"error": "Unauthorized"}', 401);
        }

        if ($count) {
            $count = $this->module('collections')->count($collection, $filter);
        }

        $this->module('collections')->remove($collection, $filter);

        return ['success' => true, 'count' => $count];
    }

    public function createCollection() {

        $user = $this->module('cockpit')->getUser();
        $name = $this->param('name', null);
        $data = $this->param('data', null);

        if (!$name || !$data) {
            return false;
        }

        if ($user && !$this->module('cockpit')->isSuperAdmin()) {
            return $this->stop('{"error": "Unauthorized"}', 401);
        }

        $collection = $this->module('collections')->createCollection($name, $data);

        return $collection;
    }

    public function updateCollection($name = null) {

        $user = $this->module('cockpit')->getUser();
        $data = $this->param('data', null);

        if (!$name || !$data) {
            return false;
        }

        $collection = $this->module('collections')->collection($name);

        if ($user && !$this->module('collections')->hasaccess($collection, 'collection_edit')) {
            return $this->stop('{"error": "Unauthorized"}', 401);
        }

        $collection = $this->module('collections')->updateCollection($name, $data);

        return $collection;
    }

    public function collection($name) {

        $user = $this->module('cockpit')->getUser();

        if ($user) {
            $collections = $this->module("collections")->getCollectionsInGroup($user['group'], true);
        } else {
            $collections = $this->module("collections")->collections(true);
        }

        if (!isset($collections[$name])) {
           return $this->stop('{"error": "Collection not found"}', 412);
        }

        return $collections[$name];
    }

    public function listCollections($extended = false) {

        $user = $this->module('cockpit')->getUser();

        if ($user) {
            $collections = $this->module("collections")->getCollectionsInGroup($user['group'], $extended);
        } else {
            $collections = $this->module('collections')->collections($extended);
        }

        return $extended ? $collections : array_keys($collections);
    }

    public function upload($name = null) {
        $user = $this->module('cockpit')->getUser();

        ///-------

        if(empty($_FILES)) return $this->stop('{"error": "Your request to upload is not valid"}', 412);
        
        $id = $this->param('_id');
        $userid = $this->param('_userid');
        if(!$id || !$userid) return $this->stop('{"error": "Missing id"}', 412);
        
        $discussion = $this->module('collections')->find("discussions", ['filter' => ["_id" => $id]]);
        
        if(!count($discussion)) return $this->stop('{"error": "Sorry, we can\'t find your discussion."}', 412);
        
        $discussion = $discussion[0];
        $discussion_slug = $discussion["name_slug"];

        //my turn?
        if($discussion["turn"]["_id"] !== $userid) return $this->stop('{"error": "Sorry it\'s not your turn yet"}', 412);
    
        //get next author
        $nextauthor;
        foreach($discussion["photographers"] as $author) {
            if($author["_id"] != $userid) {
                $nextauthor = $this->module('collections')->find("photographers", ['filter' => ["_id" => $author["_id"]]])[0];
            }
        }
        
        if($discussion["completed"]) return $this->stop('{"error": "Sorry, the discussion is already completed"}', 412);
        
        //path
        $path = $this->app->path('#discussions:')."_".$discussion_slug;
        $generatepath = $this->app->path('#discussions:').$discussion_slug;
        
        //create folder
        if (!is_dir($path)) mkdir($path);
        if (!is_dir($generatepath)) mkdir($generatepath);
        
        //upload
        $filename = preg_replace('/[^a-zA-Z0-9-_\.]/','', str_replace(' ', '-', $_FILES['file']['name']));
        $tempFile = $_FILES['file']['tmp_name'];
        $targetpath = $path."/".$filename;
            
        if(!move_uploaded_file($tempFile,$targetpath)) {
            return $this->stop('{"error": "There was an error during the upload of the picture '.$_FILES['file']['name'].'"}', 412);
        }
    
        if(!isset($discussion["uploads"])) $discussion["uploads"] = [];
        $original = preg_replace("/".addcslashes(COCKPIT_SITE_DIR, "/")."/", "", $targetpath);
        $discussion["uploads"][] = [
            "original" => $original,
            "time" => time(),
            "width" => getimagesize("http://".$this->app->config["fiiiirst"]["api"].$original)[0]
        ];

        // ---update discussion entry
        $discussion["cancelled"] = $this->param('cancelled');
        $discussion["continued"] = $this->param('continued');
        $discussion["completed"] = $this->param('completed');
        $discussion["turn"] = [
            "_id" => $nextauthor["_id"],
            "display" => $nextauthor["name"],
            "link" => "photographers"
        ];

        $discussion = $this->module('collections')->save("discussions", $discussion);

        //---send email
        $urls = $discussion["completed"] ? ["discussion_completed.html", "discussion_completed_plain.html"] : ["discussion_new_photo.html", "discussion_new_photo_plain.html"];
        $bodies = array();

        foreach($urls as $url) {
            $body = file_get_contents(COCKPIT_DIR."/mail_templates/".$url);
            $body = preg_replace("/{{server}}/", $this->app->config["fiiiirst"]["host"], $body);
            $body = preg_replace("/{{name}}/", $nextauthor["name"], $body);
            $body = preg_replace("/{{img}}/", $this->app->config["fiiiirst"]["api"].end($discussion["uploads"])["original"], $body);
            
            array_push($bodies, $body);
        }

        //send email
        if(!$this->app->mailer->mail($nextauthor["email"], ($discussion["completed"]) ? "Your discussion is completed !!" : "New photo in your discussion", $bodies[0], ["alt_body" => $bodies[1]])) {
            return $this->stop('{"warning": "There was an error to contact your penfriend, but your picture has been uploaded"}', 412);
        }

        return json_encode($discussion, JSON_PRETTY_PRINT);
    }

    protected function _fixStringBooleanNumericValues(&$array) {

        if (!is_array($array)) {
            return $array;
        }

        foreach ($array as $k => $v) {

            if (is_array($array[$k])) {
                $array[$k] = $this->_fixStringBooleanNumericValues($array[$k]);
            }

            if (is_string($v)) {

                if ($v === 'true' || $v === 'false') {
                    $v = filter_var($v, FILTER_VALIDATE_BOOLEAN);
                } elseif(is_numeric($v)) {
                    $v = $v + 0;
                }
            }

            $array[$k] = $v;
        }

        return $array;
    }
}
