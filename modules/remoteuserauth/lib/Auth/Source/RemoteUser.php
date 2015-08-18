<?php

/**
 * Example authentication source.
 *
 * This class is an example authentication source which will always return a user with
 * a static set of attributes.
 *
 * @author Carl Waldbieser <waldbiec@lafayette.edu>.
 * @package simpleSAMLphp
 */
class sspmod_remoteuserauth_Auth_Source_RemoteUser extends SimpleSAML_Auth_Source {
	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */

    private $header_name;
    private $attrib_url;

	public function __construct($info, $config) {
		assert('is_array($info)');
		assert('is_array($config)');

		/* Call the parent constructor first, as required by the interface. */
		parent::__construct($info, $config);
        $this->header_name = 'HTTP_REMOTE_USER';
        $this->attrib_url = 'http://127.0.0.1:9444/';
        ini_set("log_errors", 1);
        error_log('RemoteUser auth source initialized.');

		/* Parse attributes. */
		#try {
		#	$this->attributes = SimpleSAML\Utils\Arrays::normalizeAttributesArray($config);
		#} catch(Exception $e) {
		#	throw new Exception('Invalid attributes for authentication source ' .
		#		$this->authId . ': ' . $e->getMessage());
		#}
	}


	/**
	 * Log in using static attributes.
	 *
	 * @param array &$state  Information about the current authentication.
	 */
	public function authenticate(&$state) {
		assert('is_array($state)');
        error_log("_SERVER == " . print_r($_SERVER, true));
        $remote_user = $_SERVER['HTTP_REMOTE_USER'];
        error_log("[DEBUG] REMOTE_USER => '$remote_user'");
        $attributes = $this->get_attribs($remote_user);
        error_log("[DEBUG] attribs => " . print_r($attributes, true));
		$state['Attributes'] = SimpleSAML_Utilities::parseAttributes($attributes);
	}

    private function get_attribs($username) {
        $ch = curl_init();
        // set url
        $attrib_url = $this->attrib_url;
        curl_setopt($ch, CURLOPT_URL, "$attrib_url/$username");
        //return the transfer as a string
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        // $output contains the output string
        $output = curl_exec($ch);
        // close curl resource to free up system resources
        curl_close($ch);
        #$jsonIterator = new RecursiveIteratorIterator(
        #    new RecursiveArrayIterator(json_decode($output, TRUE)),
        #    RecursiveIteratorIterator::SELF_FIRST);
        $doc = json_decode($output);
        $attribs = array('uid' => $username);
        #foreach ($jsonIterator as $key => $val)
        #{
        #    error_log("[DEBUG] Adding key '$key' ...");
        #    $attribs[$key] = implode('|', $val);
        #}
        foreach ($doc as $key => $val)
        {
            error_log("[DEBUG] Adding key '$key' ...");
            #$attribs[$key] = implode('|', $val);
            $attribs[$key] = $val;
        }
        error_log("[DEBUG] attribs to be returned => " . print_r($attribs, true));
        return $attribs;
    }
}
