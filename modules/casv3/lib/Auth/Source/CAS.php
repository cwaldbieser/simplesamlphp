<?php

/**
 * Authenticate using CAS.
 *
 * Based on www/auth/login-cas.php by Mads Freek, RUC.
 *
 * @author Danny Bollaert, UGent.
 * @package simpleSAMLphp
 */
class sspmod_casv3_Auth_Source_CAS  extends SimpleSAML_Auth_Source  {

	/**
	 * The string used to identify our states.
	 */
	const STAGE_INIT = 'sspmod_casv3_Auth_Source_CAS.state';

	/**
	 * The key of the AuthId field in the state.
	 */
	const AUTHID = 'sspmod_casv3_Auth_Source_CAS.AuthId';

	/**
	 * @var cas configuration
	 */
	private $_casConfig;

	/**
	 * @var cas chosen validation method
	 */
	private $_validationMethod;
	/**
	 * @var cas login method
	 */
	private $_loginMethod;


	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */
	public function __construct($info, $config) {
		assert('is_array($info)');
		assert('is_array($config)');

		/* Call the parent constructor first, as required by the interface. */
		parent::__construct($info, $config);

		if (!array_key_exists('cas', $config)){
			throw new Exception('cas authentication source is not properly configured: missing [cas]');
		}

		$this->_casConfig = $config['cas'];

		if(isset($this->_casConfig['serviceValidate'])){
			$this->_validationMethod = 'serviceValidate';
		}elseif(isset($this->_casConfig['validate'])){
			$this->_validationMethod = 'validate';
		}else{
			throw new Exception("validate or serviceValidate not specified");
		}

		if(isset($this->_casConfig['login'])){
			$this->_loginMethod =  $this->_casConfig['login'];
		}else{
			throw new Exception("cas login URL not specified");
		}
	}


	/**
	 * This the most simple version of validating, this provides only authentication validation
	 *
	 * @param string $ticket
	 * @param string $service
	 * @return list username and attributes
	 */
	private function casValidate($ticket, $service){
		$url = SimpleSAML_Utilities::addURLparameter($this->_casConfig['validate'], array(
				'ticket' => $ticket,
				'service' => $service,
		));
        if(isset($this->_casConfig['cacert']))
        {
            $cacert_path = $this->_casConfig['cacert'];
            $context_opts = array(
                "ssl" => array(
                    "cafile" => $cacert_path,
                    "verify_peer" => true,
                    "verify_peer_name" => true,
                ),
            );
            $result = SimpleSAML_Utilities::fetch($url, $context_opts);
        }
        else
        {
		    $result = SimpleSAML_Utilities::fetch($url);
        }
		$res = preg_split("/\r?\n/",$result);

		if (strcmp($res[0], "yes") == 0) {
			return array($res[1], array());
		} else {
			throw new Exception("Failed to validate CAS service ticket: $ticket");
		}
	}


	/**
	 * Uses the cas service validate, this provides additional attributes
	 *
	 * @param string $ticket
	 * @param string $service
	 * @return list username and attributes
	 */
	private function casServiceValidate($ticket, $service){
		$url = SimpleSAML_Utilities::addURLparameter($this->_casConfig['serviceValidate'], array(
				'ticket' => $ticket,
				'service' => $service,
		));
        
        if(isset($this->_casConfig['cacert']))
        {
            $cacert_path = $this->_casConfig['cacert'];
            $context_opts = array(
                "ssl" => array(
                    "cafile" => $cacert_path,
                    "verify_peer" => true,
                    "verify_peer_name" => true,
                ),
            );
            $result = SimpleSAML_Utilities::fetch($url, $context_opts);
        }
        else
        {
		    $result = SimpleSAML_Utilities::fetch($url);
        }

        #error_log("raw response => $result");
		$dom = DOMDocument::loadXML($result);
		$xPath = new DOMXpath($dom);
		$xPath->registerNamespace("cas", 'http://www.yale.edu/tp/cas');
		$success = $xPath->query("/cas:serviceResponse/cas:authenticationSuccess/cas:user");
		if ($success->length == 0) {
			$failure = $xPath->evaluate("/cas:serviceResponse/cas:authenticationFailure");
			throw new Exception("Error when validating CAS service ticket: " . $failure->item(0)->textContent);
		} else {

			$attributes = array();
			if ($casattributes = $this->_casConfig['attributes']) { # some has attributes in the xml - attributes is a list of XPath expressions to get them
				foreach ($casattributes as $name => $query) {
                    #error_log("name => '$name' , query => '$query'");
					$attrs = $xPath->query($query);
					foreach ($attrs as $attrvalue) {
                        #error_log("attrvalue -> " . $attrvalue->textContent);
                        $attributes[$name][] = $attrvalue->textContent;
                    }
				}
			}
			$casusername = $success->item(0)->textContent;

			return array($casusername, $attributes);

		}
	}


	/**
	 * Main validation method, redirects to correct method
	 * (keeps finalStep clean)
	 *
	 * @param string $ticket
	 * @param string $service
	 * @return list username and attributes
	 */
	protected function casValidation($ticket, $service){
		switch($this->_validationMethod){
			case 'validate':
				return  $this->casValidate($ticket, $service);
				break;
			case 'serviceValidate':
				return $this->casServiceValidate($ticket, $service);
				break;
			default:
				throw new Exception("validate or serviceValidate not specified");
		}
	}


	/**
	 * Called by linkback, to finish validate/ finish logging in.
	 * @param state $state
	 * @return list username, casattributes/ldap attributes
	 */
	public function finalStep(&$state) {


		$ticket = $state['cas:ticket'];
		$stateID = SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT);
		$service =  SimpleSAML_Module::getModuleURL('casv3/linkback.php', array('stateID' => $stateID));
		list($username, $casattributes) = $this->casValidation($ticket, $service);
		$attributes = array_merge_recursive($casattributes);
		$state['Attributes'] = $attributes;

		SimpleSAML_Auth_Source::completeAuth($state);
	}


	/**
	 * Log-in using cas
	 *
	 * @param array &$state  Information about the current authentication.
	 */
	public function authenticate(&$state) {
		assert('is_array($state)');

		/* We are going to need the authId in order to retrieve this authentication source later. */
		$state[self::AUTHID] = $this->authId;

		$stateID = SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT);



		$serviceUrl = SimpleSAML_Module::getModuleURL('casv3/linkback.php', array('stateID' => $stateID));

		SimpleSAML_Utilities::redirectTrustedURL($this->_loginMethod, array(
			'service' => $serviceUrl));
	}


	/**
	 * Log out from this authentication source.
	 *
	 * This function should be overridden if the authentication source requires special
	 * steps to complete a logout operation.
	 *
	 * If the logout process requires a redirect, the state should be saved. Once the
	 * logout operation is completed, the state should be restored, and completeLogout
	 * should be called with the state. If this operation can be completed without
	 * showing the user a page, or redirecting, this function should return.
	 *
	 * @param array &$state  Information about the current logout operation.
	 */
	public function logout(&$state) {
		assert('is_array($state)');
		$logoutUrl = $this->_casConfig['logout'];

		SimpleSAML_Auth_State::deleteState($state);
		// we want cas to log us out
		SimpleSAML_Utilities::redirectTrustedURL($logoutUrl);
	}

}
