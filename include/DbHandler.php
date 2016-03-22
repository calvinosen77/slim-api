<?php
	class DbHandler {
		private $conn;
		function __construct() {
			require_once  'DbConnect.php';
			// opening db connection
			$db = new DbConnect();
			$this->conn = $db->connect();
		}
		
		function generateRandomString($length = 8) {
			$characters = '01 23456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
			$charactersLength = strlen($characters);
			$randomString = '';
			for ($i = 0; $i < $length; $i++) {
				$randomString .= $characters[rand(0, $charactersLength - 1)];
			}
			return $randomString;
		}
		
		
		function getcolumnvalue($table,$column,$ref,$refvalue){
			$stmt = $this->conn->query("SELECT $column FROM $table where $ref = '$refvalue'");
			$detail = $stmt->fetch_array(MYSQLI_ASSOC);
			return $detail[$column];
		}
		
		
		/* ------------- `user` table method ------------------ */
		/**
		 * Creating new user
		 * @param String $name User full name
		 * @param String $email User login email id
		 * @param String $password User login password
	    */
		
		public function createUser($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$name 	  	= $data['name'];
			$email 	   = $data['email'];
			$password 	= $data['password'];
			$dob         = date('Y-m-d',strtotime($data['dob']));
			if(isset($data['roleid'])){
				$roleid  = $data['roleid'];
			}else{
				$roleid  = 0;
			}
			if (!$this->isUserExists($email)) { 
				// Generating password hash
				$password_hash = PassHash::hash($password);
				// Generating API key
				$api_key = $this->generateApiKey();
				// insert query
				$date = date('Y-m-d H:i:s');
				
				$stmt = $this->conn->prepare("INSERT INTO user(user_name, user_email, user_password, user_api_key,version_date,qr_api_key,id_role,user_dob,user_create_date) values('$name','$email','$password_hash','$api_key','$date','$qr_api_key','$roleid','$dob','$date')");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$lastid = $this->conn->insert_id;
					if(isset($_SESSION['user'])){
						$id = $_SESSION['user']['id'];
					}else{
						$id = $lastid;
					}
					$stmt->close();
					
					$stmt1 = $this->conn->prepare("UPDATE user SET `id_user_version` = $id,`version` = 0 WHERE id = $lastid");
					$result1 = $stmt1->execute();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		
		
		
		public function changepassword($data){
			require_once 'PassHash.php';
			$current_password = $data['current_password'];
			$new_password     = $data['new_password'];
			$currenthash = PassHash::hash($current_password);
			if(!$this->isUserExists($email)){
				$email = $data['email'];
				$result=$this->conn->query("SELECT * FROM user WHERE user_email = '$email'");
				$detail = $result->fetch_array(MYSQLI_ASSOC);
				$password_hash = $detail['user_password'];
				$currentversion = $detail['version'];
				if (PassHash::check_password($password_hash, $current_password )) {
					$user_password  = PassHash::hash($new_password);
					$version = $currentversion + 1;
					$sqlset = $sqlset . "`user_password` = '$user_password',";
					if(isset($_SESSION['user'])){
						$versionuserid = $_SESSION['user']['id'];
						$sqlset = $sqlset . "`id_user_version` = '$versionuserid',";
					}
					$sqlset = $sqlset . "`version` = '$version',";
					$date = date('Y-m-d H:i:s');
					$sqlset = $sqlset . "`version_date` = '$date'";
					$stmt = $this->conn->prepare("UPDATE user SET ".$sqlset." WHERE user_email = '$email'");
					if ($stmt === FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt->execute();
						$stmt->close();
					}
					if ($result) {
						if(isset($_SESSION['user'])){
							session_destroy();
						}
						return SUCCESS;
					} else {
						return FAIL;
					}
				}else{
					return CURRENT_PASSWORD_NOTMATCHED;
				}
			}else{
				return USER_NOT_EXIST;
			}
			// Check for successful insertion
		}
		
		
		public function forgetpassword($data){
			$email = $data['user_email'];
			if($this->isUserExists($email)){
				$url = "http://" . $_SERVER['SERVER_NAME'] .'/v1/resetpassword?email='.$email;
			    $message = "you have request for change password. click here for reset password <a href=".$url.">".$url."</a>";
				$to      = $email;
				$subject = 'Change Password';
				$headers = 'From: info@nwaresoft.com' . "\r\n" .
					'Reply-To: info@nwaresoft.com' . "\r\n" .
					'X-Mailer: PHP/' . phpversion();
				
				
				if (mail($to, $subject, $message, $headers)) {
					// User successfully inserted
					return MAIL_SENT_SUCCESSFULLY;
				} else {
					// Failed to create user
					return MAIL_SENT_FAIL;
				}				
			}else{
				return EMAIL_ISNOT_VALID;
			}
		}
		
		
		
		
		public function resetPassword($data) {
			require_once 'PassHash.php';
			$response = array();
			$user_email = $data['user_email'];
			$password =$this->generateRandomString();
			$user_password  = PassHash::hash($password);
			$sqlset = $sqlset . "`user_password` = '$user_password'";
			$stmt = $this->conn->prepare("UPDATE user SET ".$sqlset." WHERE user_email = '$user_email'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				$message = "you have changed password.<br/> Email : ".$user_email."<br /> password :".$password ;
				$to      = $user_email;
				$subject = 'Password Reset';
				$headers = 'From: info@nwaresoft.com' . "\r\n" .
					'Reply-To: info@nwaresoft.com' . "\r\n" .
					'X-Mailer: PHP/' . phpversion();
				if(mail($to, $subject, $message, $headers)){ 
					return PASSWORD_CHANGED_SUCCESSFULLY;
				}
			} else {
				//Failed to create user
				return PASSWORD_CHANGED_FAILED;
			}
			return $response;
		}
		
		
		/* ------------- `user` table method ------------------ */
		/**
		 * Creating new user
		 * @param String $name User full name
		 * @param String $email User login email id
		 * @param String $password User login password
		 */
		
		public function userAction($data,$action) {
			$response = array();
			// update query
			
			if($action == 'edit'){
				$id  = $data['id'];
				$user_name  = $data['user_name'];
				$previoususername = $this->getcolumnvalue('user','user_name','id',$id);
				if(isset($user_name) && ($previoususername != $user_name)){
					$sqlset = $sqlset . "`user_name` = '$user_name'";
				}
				
				$sqlset = rtrim($sqlset, ',');
				if ($sqlset!=''){
					$stmt = $this->conn->prepare("UPDATE user SET ".$sqlset." WHERE id = $id");
					if ($stmt === FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt->execute();
						$stmt->close();
					}
					// Check for successful insertion
					if ($result) {
						// User successfully inserted
						return USER_UPDATED_SUCCESSFULLY;
					} else {
						// Failed to create user
						return USER_UPDATED_FAILED;
					}
				}else{
					return SYSTEM_ERROR;
				}
			}else if($action == 'delete'){
				$id  = $data['id'];
				if($id == $_SESSION['user']['id']){
					$stmt = $this->conn->query("SELECT * from user WHERE `id` = $id");
					if ($stmt == FALSE){
						die($this->conn->error);
					} else{
						$num_rows = $stmt->num_rows;
						if($num_rows > 0){
							$result = $stmt->fetch_array(MYSQLI_ASSOC);
							if($result['flag_user_visible'] == 0){
								return USER_ALREADY_DELETED;
								exit; 	
							}
						}else{
							return USER_DOESNOT_EXIST;
							exit; 	
						}
					}
					$email = date('YmdHis').'#'.$_SESSION['user']['email'];
					$sql = "UPDATE user SET user_email = '$email',flag_user_visible =0 WHERE id = $id";
					
					
					$stmt = $this->conn->prepare($sql);
					if($stmt === FALSE){
						die($this->conn->error);
					}else{
						$result = $stmt->execute();
						$stmt->close();
					}
					// Check for successful insertion
					if ($result) {
						$userid = $id;
						$sessionuserid = $_SESSION['user']['id'];
						$this->updateuserversion($userid,$sessionuserid);
						// User successfully inserted
						if($id == $_SESSION['user']['id']){
							session_destroy();
						}
						return USER_DELETED_SUCCESSFULLY; 
					} else {
						// Failed to create user
						return USER_DELETED_FAILED;
					}
				}else{
					return USER_NOT_CORRECT;
				}
				
			}
			return $response;
		}
		
		public function getalluser() {
			$stmt = $this->conn->query("SELECT * FROM user where flag_user_active = 1");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$user = $stmt;
				return $user;
			}
		}
		
		public function listusers() {
			$stmt = $this->conn->query("SELECT user.id as userid,user.*,role.* FROM user 
										LEFT JOIN role ON user.id_role = role.id_role 
										where user.flag_user_visible = 1");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$user = $stmt;
				return $user;
			}
		}
		
		
		/**
		 * Checking user login
		 * @param String $email User login email id
		 * @param String $password User login password
		 * @return boolean User login status success/fail
		 
		 */
		
		public function checkLogin($email, $password) {
			// fetching user by email
			$stmt = $this->conn->prepare("SELECT user_password,id FROM user WHERE `flag_user_visible` = 1 AND user_email = ?");
			if ($stmt === FALSE){
				die($this->conn->error);
			}else{ 
				$stmt->bind_param("s",$email);
				$stmt->execute();
				$stmt->bind_result($password_hash,$id);
				$stmt->store_result();
					if ($stmt->num_rows > 0) {
						// Found user with the email
						// Now verify the password
						$stmt->fetch();
						$stmt->close();
						if (PassHash::check_password($password_hash, $password)) {
							$this->updateusersesion($id,'login');
							// User password is correct
							return TRUE;
						} else {
							// user password is incorrect
							return FALSE;
						}
					}else{
						$stmt->close();
						// user not existed with the email
						return FALSE;
					}
			}
		}
		/**
		 * Checking for duplicate user by email address
		 * @param String $email email to check in db
		 * @return boolean
		 */
		public function isUserExists($email) {
			$stmt = $this->conn->prepare("SELECT id from user WHERE `user_email` = ?");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$stmt->bind_param("s", $email);
				$stmt->execute();
				$stmt->store_result();
				$num_rows = $stmt->num_rows;
				$stmt->close();
				return $num_rows > 0;
			}
		}
		
		public function updateusersesion($id,$type){
			$date = date('Y-m-d H:i:s');
			$ip = $this->get_client_ip();
			$stmt1 = $this->conn->prepare("INSERT INTO `user_session` (`id_user`,`ip_user`,`version_date`,`version_type`) values('$id','$ip','$date','$type')");
			if ($stmt1 === FALSE){
				die($this->conn->error);
			} else  {
				$result1 = $stmt1->execute();
				$stmt1->close();
			}
		} 
		
		public function updateuserversion($userid,$sessionuserid){
			$result=$this->conn->query("SELECT * FROM user WHERE id = '$userid'");
			$detail = $result->fetch_array(MYSQLI_ASSOC);
			$currentversion = $detail['version'];
			$version = $currentversion + 1;
			$sqlset = $sqlset . "`id_user_version` = '$sessionuserid',";
			$sqlset = $sqlset . "`version` = '$version',";
			$date = date('Y-m-d H:i:s');
			$sqlset = $sqlset . "`version_date` = '$date'";
			$sql = "UPDATE user SET ".$sqlset." WHERE id = '$userid'";
			$stmt = $this->conn->prepare($sql);
			$result = $stmt->execute();
			$stmt->close();
			
		} 
		
		
		public function updateversion($table,$ref,$refvalue){
			$result=$this->conn->query("SELECT version FROM $table WHERE $ref= '$refvalue'");
			$detail = $result->fetch_array(MYSQLI_ASSOC);
			$currentversion = $detail['version'];
			$version = $currentversion + 1;
			$sqlset = $sqlset . "`version` = '$version',";
			$date = date('Y-m-d H:i:s');
			$sqlset = $sqlset . "`version_date` = '$date',";
			$sqlset = rtrim($sqlset, ',');
			$sql = "UPDATE $table SET ".$sqlset." WHERE $ref = '$refvalue'";
			$stmt = $this->conn->prepare($sql);
			$result = $stmt->execute();
			$stmt->close();
			}
		
		function get_client_ip() {
			$ipaddress = '';
			if (getenv('HTTP_CLIENT_IP'))
				$ipaddress = getenv('HTTP_CLIENT_IP');
			else if(getenv('HTTP_X_FORWARDED_FOR'))
				$ipaddress = getenv('HTTP_X_FORWARDED_FOR');
			else if(getenv('HTTP_X_FORWARDED'))
				$ipaddress = getenv('HTTP_X_FORWARDED');
			else if(getenv('HTTP_FORWARDED_FOR'))
				$ipaddress = getenv('HTTP_FORWARDED_FOR');
			else if(getenv('HTTP_FORWARDED'))
			   $ipaddress = getenv('HTTP_FORWARDED');
			else if(getenv('REMOTE_ADDR'))
				$ipaddress = getenv('REMOTE_ADDR');
			else
				$ipaddress = 'UNKNOWN';
			return $ipaddress;
		}		
		
		/**
		 * Checking for duplicate user by email address
		 * @param String $email email to check in db
		 * @return boolean
		 */
		public function isUserExistsById($id) {
			$stmt = $this->conn->prepare("SELECT id from user WHERE `id` = ?");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$stmt->bind_param("i", $id);
				$stmt->execute();
				$stmt->store_result();
				$num_rows = $stmt->num_rows;
				$stmt->close();
				return $num_rows > 0;
			}
		}    
		   
		/**
		 * Fetching user by email
		 * @param String $email User email id
		 */
		public function getUserByEmail($email) {
			
			$result = $this->conn->query("SELECT user.id as userid,user.*,role.* FROM user LEFT JOIN role ON user.id_role = role.id_role WHERE user.user_email = '$email'");
			$user = array();
	
			while ($detail = $result->fetch_array(MYSQLI_ASSOC) ) {
				$user["user_name"] = $detail["user_name"];
				$user["user_email"] = $detail["user_email"];
				$user["api_key"] = $detail["user_api_key"];
				$user["user_active"] = $detail["flag_user_active"];
				$user["version_date"] = $detail["version_date"];
				$user['id'] = $detail["userid"];
				$user["role_id"] = $detail["id_role"];
				$user["dob"]     = $detail["user_dob"];;
				$user["rolename"]     = $detail["role_name"];;
				$user["created"]     = $detail["user_create_date"];;
			}
			return $user;
			//$userdetail = json_encode($user);
			
			//return array('detail' => $this->encrypt($userdetail,$user["api_key"]));
		}
		/**
		 * Fetching user by email
		 * @param String $email User email id
		 */
		public function getUserById($id) {
			
			$result=$this->conn->query("SELECT * FROM user WHERE id = '$id'");
						$user = array();
	
			while ($detail = $result->fetch_array(MYSQLI_ASSOC) ) {
				$user["user_name"] = $detail["user_name"];
				$user["user_email"] = $detail["user_email"];
				$user["api_key"] = $detail["user_api_key"];
				$user["user_active"] = $detail["flag_user_active"];
				$user["version_date"] = $detail["version_date"];
			}
			return $user;
			//$userdetail = json_encode($user);
			
			//return array('detail' => $this->encrypt($userdetail,$user["api_key"]));
		}
		
		/**
		 * Fetching user api key
		 * @param String $user_id user id primary key in user table
		 */
		public function getApiKeyById($user_id) {
			$stmt = $this->conn->prepare("SELECT api_key FROM user WHERE id = ?");
			$stmt->bind_param("i", $user_id);
			if ($stmt->execute()) {
				// $api_key = $stmt->get_result()->fetch_assoc();
				// TODO
				$stmt->bind_result($api_key);
				$stmt->close();
				return $api_key;
			} else {
				return NULL;
			}
		}
		/**
		 * Fetching user id by api key
		 * @param String $api_key user api key
		 */
		public function getUserId($api_key) {
			$stmt = $this->conn->prepare("SELECT id FROM user WHERE api_key = ?");
			$stmt->bind_param("s", $api_key);
			if ($stmt->execute()) {
				$stmt->bind_result($user_id);
				$stmt->fetch();
				// TODO
				// $user_id = $stmt->get_result()->fetch_assoc();
				$stmt->close();
				return $user_id;
			} else {
				return NULL;
			}
		}
		/**
		 * Validating user api key
		 * If the api key is there in db, it is a valid key
		 * @param String $api_key user api key
		 * @return boolean
		 */
		public function isValidApiKey($api_key) {
			$stmt = $this->conn->prepare("SELECT id from user WHERE api_key = ?");
			$stmt->bind_param("s", $api_key);
			$stmt->execute();
			$stmt->store_result();
			$num_rows = $stmt->num_rows;
			$stmt->close();
			return $num_rows > 0;
		}
		/**
		 * Generating random Unique MD5 String for user Api key
		 */
		private function generateApiKey() {
			return md5(uniqid(rand(), true));
		}
		/* ------------- `tasks` table method ------------------ */
		/**
		 * Creating new task
		 * @param String $user_id user id to whom task belongs to
		 * @param String $task task text
		 */
		public function createTask($user_id, $task) {
			$stmt = $this->conn->prepare("INSERT INTO tasks(task) VALUES(?)");
			$stmt->bind_param("s", $task);
			$result = $stmt->execute();
			$stmt->close();
			if ($result) {
				// task row created
				// now assign the task to user
				$new_task_id = $this->conn->insert_id;
				$res = $this->createUserTask($user_id, $new_task_id);
				if ($res) {
					// task created successfully
					return $new_task_id;
				} else {
					// task failed to create
					return NULL;
				}
			} else {
				// task failed to create
				return NULL;
			}
		}
		
		/**
		 * Fetching single task
		 * @param String $task_id id of the task
		 */
		public function getTask($task_id, $user_id) {
			$stmt = $this->conn->prepare("SELECT t.id, t.task, t.status, t.created_at from tasks t, user_tasks ut WHERE t.id = ? AND ut.task_id = t.id AND ut.user_id = ?");
			$stmt->bind_param("ii", $task_id, $user_id);
			if ($stmt->execute()) {
				$res = array();
				$stmt->bind_result($id, $task, $status, $created_at);
				// TODO
				// $task = $stmt->get_result()->fetch_assoc();
				$stmt->fetch();
				$res["id"] = $id;
				$res["task"] = $task;
				$res["status"] = $status;
				$res["created_at"] = $created_at;
				$stmt->close();
				return $res;
			} else {
				return NULL;
			}
		}
		
		public function updateTask($user_id, $task_id, $task, $status) {
			$stmt = $this->conn->prepare("UPDATE tasks t, user_tasks ut set t.task = ?, t.status = ? WHERE t.id = ? AND t.id = ut.task_id AND ut.user_id = ?");
			$stmt->bind_param("siii", $task, $status, $task_id, $user_id);
			$stmt->execute();
			$num_affected_rows = $stmt->affected_rows;
			$stmt->close();
			return $num_affected_rows > 0;
		}
		
		/**
		* Deleting a task	
		* @param String $task_id id of the task to delete
		*/
		
		public function deleteTask($user_id, $task_id) {
			$stmt = $this->conn->prepare("DELETE t FROM tasks t, user_tasks ut WHERE t.id = ? AND ut.task_id = t.id AND ut.user_id = ?");
			$stmt->bind_param("ii", $task_id, $user_id);
			$stmt->execute();
			$num_affected_rows = $stmt->affected_rows;
			$stmt->close();
			return $num_affected_rows > 0;
		}
	   
		/* ------------- `user_tasks` table method ------------------ */
		/**
		 * Function to assign a task to user
		 * @param String $user_id id of the user
		 * @param String $task_id id of the task
		 */
	   
		public function createUserTask($user_id, $task_id) {
			$stmt = $this->conn->prepare("INSERT INTO user_tasks(user_id, task_id) values(?, ?)");
			$stmt->bind_param("ii", $user_id, $task_id);
			$result = $stmt->execute();
			if (false === $result) {
				die('execute() failed: ' . htmlspecialchars($stmt->error));
			}
			$stmt->close();
			return $result;
		}
		
		public function encrypt($plainText){
			//$secretKey = $this->hextobin(md5($key));
			$initVector = pack("C*", 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f);
			$openMode = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '','cbc', '');
			$blockSize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, 'cbc');
			$plainPad = $this->pkcs5_pad($plainText, $blockSize);
			if (mcrypt_generic_init($openMode, $initVector) != -1){
				$encryptedText = mcrypt_generic($openMode, $plainPad);
				mcrypt_generic_deinit($openMode);
			} 
			return bin2hex($encryptedText);
		}
		
		public function decrypt($encryptedText,$key){
			if($this->isValidApiKey($key) == true){
				$secretKey = $this->hextobin(md5($key));
				$initVector = pack("C*", 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f);
				$encryptedText=$this->hextobin($encryptedText);
				$openMode = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '','cbc', '');
				mcrypt_generic_init($openMode, $secretKey, $initVector);
				$decryptedText = mdecrypt_generic($openMode, $encryptedText);
				$decryptedText = rtrim($decryptedText, "\0");
				mcrypt_generic_deinit($openMode);
				return $decryptedText;
			}else{
				return 0;
			}
		}
		
		//*********** Padding Function *********************
		function pkcs5_pad ($plainText, $blockSize){
			$pad = $blockSize - (strlen($plainText) % $blockSize);
			return $plainText . str_repeat(chr($pad), $pad);
		}
		
		//********** Hexadecimal to Binary function for php 4.0 version ********
		function hextobin($hexString){ 
			$length = strlen($hexString); 
			$binString="";   
			$count=0; 
			while($count<$length){       
				$subString =substr($hexString,$count,2);           
				$packedString = pack("H*",$subString); 
				if ($count==0){
					$binString=$packedString;
				}else{
					$binString.=$packedString;
				} 
				$count+=2;
			} 
			return $binString; 
		} 
		
		/**
		 * Fetching user id by api key
		 * @param String $api_key user api key
		 */
		private function getUserIdByEmail($email) {
			$result = $this->conn->query("SELECT id FROM user WHERE `user_email` = '$email'");
			
			if ($result === FALSE){
				die($this->conn->error);
			} else  {
				$detail = $result->fetch_array(MYSQLI_ASSOC);
				$user_id = $detail['id'];
				return $user_id;
			}
		}
		
		
		function qrgenerator($id,$type,$startdate,$enddate) {
			require_once  'phpqrcode/qrlib.php';
			$pharmacode = $this->pharmacyaccesss($id,$type,$startdate,$enddate);
			$qrimage = array();
			$tempDir = dirname(dirname(__FILE__)).'/v1/qrcode/';
			$codeContentsPharmacists = 'code='.$pharmacode;
			
			$fileNamePharmacists = 'pp_qr_pharmacist_'.$pharmacode.'.png';
			$pngAbsoluteFilePathPharmacists = $tempDir.$fileNamePharmacists;
			$urlRelativeFilePathPharmacists = $this->url().'/'.APP_VERSION.'/qrcode/'.$fileNamePharmacists;
			
			if (!file_exists($pngAbsoluteFilePathPharmacists)) {
				//$this->updateUserQrkey($userid,$fileNamePharmacists,$type,$qrkey);
				QRcode::png($codeContentsPharmacists,$pngAbsoluteFilePathPharmacists);
				$qrimage['pharmacist'] = $urlRelativeFilePathPharmacists;
			} else {
				$qrimage['pharmacist'] = $urlRelativeFilePathPharmacists;
			}
			
			return $qrimage;
		}
		
		
		public function pharmacyaccesss($id,$type,$startdate,$enddate) {
			// First check if user already existed in db
			$id_role = $data['id_role'];
			$pharmacy_code = md5($this->generateRandomString($length = 8));
			$pharmacy_code_start_date = $data['pharmacy_code_start_date'];
			$pharmacy_code_end_date = $data['pharmacy_code_end_date'];
			$iduserversion = $_SESSION['user']['id'];
				// insert query
			$date = date('Y-m-d H:i:s');
			$stmt = $this->conn->prepare("INSERT INTO pharmacy_access
			(id_pharmacy, pharmacy_code, id_role, pharmacy_code_start_date, pharmacy_code_end_date, pharmacy_code_active,id_user_version,version_date)
			values('$id','$pharmacy_code','$type', '$startdate', '$enddate', 1,'$iduserversion','$date')");
				
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$stmt->execute();
					$stmt->close();
					return $pharmacy_code;
				}
		}
		
		
		
		
		private function isQrExist($field,$email) {
			$result = $this->conn->query("SELECT $field FROM user WHERE user_email = '$email'");
			$detail = $result->fetch_array(MYSQLI_ASSOC);
			if($detail[$field] != NULL){
				return true;
			}else{
				return false;
			}
		} 
		
		public function updateUserQrkey($userid,$pharmacist,$type,$qrkey) {
	
			$stmt = $this->conn->prepare("UPDATE pharmacy set `is_qrimage` = 1 WHERE id_pharmacy = '$userid'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$stmt->execute();
				$stmt->close();
			}
			
			$stmt1 = $this->conn->prepare("INSERT INTO `user_qrimage` (`pharma_id`,`qrimage_pharmacist`,`type`) values('$userid','$pharmacist','$type')");
			if ($stmt1 === FALSE){
				die($this->conn->error);
			} else  {
				$result1 = $stmt1->execute();
				$stmt1->close();
			}
		}
		
		function url(){
		  return sprintf(
			"%s://%s",
			isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off' ? 'https' : 'http',
			$_SERVER['SERVER_NAME']
			
		  );
		}
		
		public function updateUser($data) {
				$id  = $data['id'];
				$name = $data['name'];
				$email  = $data['email'];
				$roleid  = $data['roleid'];
				$dob  = $data['dob'];
				if ($this->isUserExists($email)) {
					return USER_ALREADY_EXISTED;
					exit;
				}
				$previoususername = $this->getcolumnvalue('user','user_name','id',$id);
				$previousemail = $this->getcolumnvalue('user','user_email','id',$id);
				$previousedob = $this->getcolumnvalue('user','user_dob','id',$id);
				$previouseroleid = $this->getcolumnvalue('user','id_role','id',$id);
				
				if(isset($name) && ($previoususername != $name)){
					$sqlset = $sqlset . "`user_name` = '$name',";
				}
				if(isset($email) && ($previousemail != $email)){
					$sqlset = $sqlset . "`user_email` = '$email',";
				}
				if(isset($roleid) && ($previouseroleid != $roleid)){
					$sqlset = $sqlset . "`id_role` = '$roleid',";
				}
				if(isset($dob) && ($previousedob != $dob)){
					if($dob != ''){
						$dob  = date('Y-m-d',strtotime($dob));
					}else{
						$dob = '';
					}
					$sqlset1 = $sqlset1 . "`user_dob` = '$dob',";
				}
				
				$sqlset = rtrim($sqlset, ',');
				
				$sqlset1 = rtrim($sqlset1, ',');
				if ($sqlset!='' ){
					$stmt = $this->conn->prepare("UPDATE user SET ".$sqlset." WHERE id = $id");
					if ($stmt == FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt->execute();
						$userid = $id;
						$sessionuserid = $_SESSION['user']['id'];
						$this->updateuserversion($userid,$sessionuserid);
						$stmt->close();
					}
					// Check for successful insertion
					
					return true;
				}else{
					return false;
				}
				
				
				if ($sqlset1!='' ){
					$stmt1 = $this->conn->prepare("UPDATE user_access SET ".$sqlset1." WHERE id_user = $id");
					if ($stmt1 === FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt1->execute();
						$stmt1->close();
					}
					// Check for successful insertion
					return true;
				}else{
					return false;
				}
				
								
				if (true) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
				
		}
		
		public function deleteuser($data){
			$id  = $data['id'];
			$stmt = $this->conn->query("SELECT * from user WHERE `id` = $id");
			if ($stmt == FALSE){
				die($this->conn->error);
			} else{
				$num_rows = $stmt->num_rows;
				if($num_rows > 0){
					$result = $stmt->fetch_array(MYSQLI_ASSOC);
					if($result['flag_user_visible'] == 0){
						return USER_ALREADY_DELETED;
						exit; 	
					}
				}else{
					return USER_DOESNOT_EXIST;
					exit; 	
				}
			}
			if($id == $_SESSION['user']['id']){
				$email = date('YmdHis').'#'.$_SESSION['user']['email'];
				$sql = "UPDATE user SET user_email = '$email',flag_user_visible =0 WHERE id = $id";
			}else{
				$sql = "UPDATE user SET flag_user_visible =0 WHERE id = $id";
			}
			
			
			$stmt = $this->conn->prepare($sql);
			if($stmt === FALSE){
				die($this->conn->error);
			}else{
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				$userid = $id;
				$sessionuserid = $_SESSION['user']['id'];
				$this->updateuserversion($userid,$sessionuserid);
				// User successfully inserted
				if($id == $_SESSION['user']['id']){
					session_destroy();
				}
				return USER_UPDATED_SUCCESSFULLY; 
			} else {
				// Failed to create user
				return USER_UPDATE_FAILED;
			}
		}
		
		public function createPharma($data) {
			$response = array();
			// First check if user already existed in db
			$name = $data['name'];
			$groupid = $data['groupid'];
            $address1 = $data['address1'];
            $address2 = $data['address2'];
            $zip = $data['zip'];
            $town = $data['town'];
            $latitude = $data['latitude'];
            $longitude = $data['longitude'];
            $phone = $data['phone'];
			$email = $data['email'];
			$pharmacistname = $data['pharmacistname'];
			$version = $data['version'];
			$versionid = $data['versionid'];
			$version_date = date('Y-m-d H:i:s');	
			$pharmacy_active = $data['pharmacy_active'];
			
			
			if (!$this->isPharmaExists($email)) { 
				// Generating password hash
				$api_key = $this->generateApiKey();
				  // insert query
				$idpharmacy = md5($email);
				$stmt = $this->conn->prepare("INSERT INTO pharmacy(id_pharmacy, pharmacy_name, pharmacy_addr1, pharmacy_addr2, pharmacy_zip,pharmacy_city,pharmacy_latitude,pharmacy_longitude,pharmacy_email,pharmacy_phone,pharmacy_active,pharmacist_name,id_group,version,id_user_version,version_date) values('$idpharmacy','$name','$address1','$address2','$zip','$town','$latitude','$longitude','$email','$phone', 1,'$pharmacistname','$groupid','$version','$versionid','$version_date')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0); 
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return PHARMA_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return PHARMA_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return PHARMA_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function getallpharmacy() {
			$stmt = $this->conn->query("SELECT * FROM pharmacy WHERE flag_pharmacy = 0");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$details = $stmt; 
				return $details;
			}
		}
		
		public function useraccesscheck($pharmacy_code){
			$date = date('Y-m-d H:i:s');
			$qry = "SELECT id_pharmacy FROM pharmacy_access 
										WHERE pharmacy_code = '$pharmacy_code' 
										AND pharmacy_code_active = 1 
										AND CURDATE() between pharmacy_code_start_date and pharmacy_code_end_date";
			
										
			$stmt = $this->conn->query($qry);
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt->fetch_array(MYSQLI_ASSOC);
				$id_pharmacy = $pharmacy["id_pharmacy"];
				return $id_pharmacy;
			}
		}
		
		public function infopharma($data) {
			$pharmacy_code = $data['pharmacy_code'];
			
			$id = $this->useraccesscheck($pharmacy_code);
			if($id == '' || is_null($id)){
				return CODE_ERROR;
				exit;
			}
			$stmt = $this->conn->query("SELECT * FROM pharmacy WHERE id_pharmacy = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				// looping through result and preparing tasks array
				$i = 0;
				$response["pharmacy"] = array();
				$response["pharmacy"]["position"] = array();
				$response["pharmacy"]["address"] = array();

				while ($pharmacy = $stmt->fetch_array(MYSQLI_ASSOC)) {
					$tmp = array();
					$tmp1 = array();


					//$tmp["user_id"]      	   = $pharmacy["id"];
					$tmp["user_name"]    	   = $pharmacy["pharmacy_name"];
					$tmp["id_group"]   	  	   = $pharmacy["id_group"];
					$tmp1["pharmacy_addr1"]     = $pharmacy["pharmacy_addr1"];
					$tmp1["pharmacy_addr2"]     = $pharmacy["pharmacy_addr2"];
					$tmp["pharmacy_zip"]       = $pharmacy["pharmacy_zip"];
					$tmp["pharmacy_city"] 	   = $pharmacy["pharmacy_city"];
					$tmp2["pharmacy_latitude"]  = $pharmacy["pharmacy_latitude"];
					$tmp2["pharmacy_longitude"] = $pharmacy["pharmacy_longitude"];
					$tmp["user_email"]   	   = $pharmacy["pharmacy_email"];
					$tmp["pharmacy_phone"]     = $pharmacy["pharmacy_phone"];
					$tmp["pharmacist_name"]    = $pharmacy["pharmacist_name"];
					$tmp["active"]       	   = $pharmacy["pharmacy_active"];
					//$tmp["version"]      	   = $pharmacy["version"];
					//$tmp["id_user_version"]    = $pharmacy["id_user_version"]; 
					$tmp["version_date"] 	   = $pharmacy["version_date"];
					array_push($response["pharmacy"], $tmp);
					array_push($response["pharmacy"]["address"], $tmp1);
					array_push($response["pharmacy"]["position"], $tmp2);
				
					$stmt1 = $this->conn->query("SELECT * FROM pharmacy_day WHERE id_pharmacy = '$id'");
					if ($stmt1 === FALSE){
						die($this->conn->error);
					} else  {
						$response["pharmacy"][$i]["day"] = array();
						while ($day = $stmt1->fetch_array(MYSQLI_ASSOC)) {
							$tem3 = array();
							//$tem3["user_id"]        = $day["id"];
							$tem3["id_day"]   	   = $day["id_day"];
							$tem3["day_start_time"] = $day["day_start_time"];
							$tem3["day_end_time"]   = $day["day_end_time"];
							//$tem3["version"]        = $day["version"];
							//$tem3["id_user_version"]= $day["id_user_version"];
							$tem3["version_date"]   = $day["version_date"];
							
							array_push($response["pharmacy"][$i]["day"], $tem3);
				 		}
					}
					
					$stmt2 = $this->conn->query("SELECT * FROM promotion WHERE id_pharmacy = '$id'");
					if ($stmt2 === FALSE){
						die($this->conn->error);
					} else  {
						$response["pharmacy"][$i]["promotion"] = array();
						while ($promo = $stmt2->fetch_array(MYSQLI_ASSOC)) {
							$tem4 = array();
							//$tem4["user_id"]        = $promo["id"];
							//$tem4["id_pharmacy"]    = $promo["id_promotion"];
							$tem4["promotion_start_date"] = $promo["promotion_start_date"];
							$tem4["promotion_end_date"]   = $promo["promotion_end_date"];
							//$tem4["version"]        = $promo["version"];
							//$tem4["id_user_version"]= $promo["id_user_version"];
							$tem4["version_date"]   = $promo["version_date"];
							$promoid = $promo["id_promotion"];
							array_push($response["pharmacy"][$i]["promotion"], $tem4);
				 		}
					}
					$stmt4 = $this->conn->query("SELECT * FROM promotion_item WHERE id_promotion = '$promoid'");
					if ($stmt4 === FALSE){
						die($this->conn->error);
					} else  {
						$response["pharmacy"][$i]["promotion_item"] = array();
						while ($promotion = $stmt4->fetch_array(MYSQLI_ASSOC)) {
							$tem5 = array();
							//$tem5["user_id"]        = $promotion["id"];
							$tem5["id_typepromotion"]    = $promotion["id_typepromotion"];
							$tem5["id_asset"] = $promotion["id_asset"];
							$tem5["promotion_price_old"]   = $promotion["promotion_price_old"];
							$tem5["promotion_price_new"]        = $promotion["promotion_price_new"];
							$tem5["promotion_discount_amt"]    = $promotion["promotion_discount_amt"];
							$tem5["promotion_discount_pct"] = $promotion["promotion_discount_pct"];
							$tem5["promotion_discount_number"]   = $promotion["promotion_discount_number"];
							$tem5["promotion_buy_number"]   = $promotion["promotion_buy_number"];
							//$tem5["version"]        = $promotion["version"];
							//$tem5["id_user_version"]= $promotion["id_user_version"];
							$tem5["version_date"]   = $promotion["version_date"];
							
							array_push($response["pharmacy"][$i]["promotion_item"], $tem5);
				 		}
					}
				$i++;	
				}
			}
            return $response;
		}
		
		public function editpharmacyaccess($data) {
				$id_pharmacy  = $data['id_pharmacy'];
				$id_role = $data['id_role'];
				$pharmacy_code_start_date  = $data['pharmacy_code_start_date'];
				$pharmacy_code_end_date  = $data['pharmacy_code_end_date'];
				$id_user_version = $_SESSION['user']['id'];
				
				$previousid_role = $this->getcolumnvalue('pharmacy_access','id_role','id_pharmacy',$id_pharmacy);
				$previoustart_date = $this->getcolumnvalue('pharmacy_access','pharmacy_code_start_date','id_pharmacy',$id_pharmacy);
				$previousend_date = $this->getcolumnvalue('pharmacy_access','pharmacy_code_end_date','id_pharmacy',$id_pharmacy);
				
				if(isset($id_role) && ($previousid_role != $id_role)){
					$sqlset = $sqlset . "`id_role` = '$id_role',";
				}
				if(isset($pharmacy_code_start_date) && ($previoustart_date != $pharmacy_code_start_date)){
					$sqlset = $sqlset . "`pharmacy_code_start_date` = '$pharmacy_code_start_date',";
				}
				if(isset($pharmacy_code_end_date) && ($previousend_date != $pharmacy_code_end_date)){
					$sqlset = $sqlset . "`pharmacy_code_end_date` = '$pharmacy_code_end_date',";
				}
				
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version',";
				$sqlset = rtrim($sqlset, ',');
				if ($sqlset!='' ){
					$stmt = $this->conn->prepare("UPDATE pharmacy_access SET ".$sqlset." WHERE pharmacy_code = '$id_pharmacy'");
					if ($stmt == FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt->execute();
						$this->updateversion('pharmacy_access','id_pharmacy',$id_pharmacy);
						$stmt->close();
					}
					return PHARMACYACCESS_UPDATED_SUCCESSFULLY;
				} else {
					return PHARMACYACCESS_UPDATE_FAILED	;
				}
		}
		
		public function deletepharmacyaccess($data){
			$id  = $data['id'];
			$this->redeletedcheck('pharmacy_access','pharmacy_code_active','pharmacy_code',$id);
			$stmt = $this->conn->prepare("UPDATE pharmacy_access SET pharmacy_code_active =0 WHERE pharmacy_code = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_DELETED_SUCCESSFULLY; 
			} else {
				// Failed to create user
				return PHARMA_DELETED_FAILED;
			}
		}
		
		public function redeletedcheck($table,$field,$ref,$refvalue){
			$sql = "SELECT $field FROM $table WHERE $ref = '$refvalue'";
			$stmt = $this->conn->query($sql);
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$detail = $stmt->fetch_array(MYSQLI_ASSOC);
				$result = $detail[$field];
			}
			if($result == 0){
				$response["error"] = true;
                $response["message"] = "Oops! Already Deleted";
				echoRespnse(201, $response);
				exit();
			}
		}
		
		 public function updatepharmacy($data) {
			$id = $data['id'];
			$name = $data['name'];
			$groupid = $data['groupid'];
            $address1 = $data['address1'];
            $address2 = $data['address2'];
            $zip = $data['zip'];
            $town = $data['town'];
            $latitude = $data['latitude'];
            $longitude = $data['longitude'];
            $phone = $data['phone'];
			$email = $data['email'];
			$pharmacistname = $data['pharmacistname'];
			$version = $data['version'];
			$versionid = $data['versionid'];
			$version_date = date('Y-m-d H:i:s');
			$pharmacy_active = $data['pharmacy_active'];
			$id_pharmacy = md5($email);
			
			$sqlset = $sqlset . "`pharmacy_name` = '$name',";
			$sqlset = $sqlset . "`id_group` = '$groupid',";
			$sqlset = $sqlset . "`pharmacy_addr1` = '$address1',";
			$sqlset = $sqlset . "`pharmacy_addr2` = '$address2',";
			$sqlset = $sqlset . "`pharmacy_zip` = '$zip',";
			$sqlset = $sqlset . "`pharmacy_city` = '$town',";
			$sqlset = $sqlset . "`pharmacy_latitude` = '$latitude',";
			$sqlset = $sqlset . "`pharmacy_longitude` = '$longitude',";
			$sqlset = $sqlset . "`pharmacy_phone` = '$phone',";
			$sqlset = $sqlset . "`pharmacy_email` = '$email',";
			$sqlset = $sqlset . "`pharmacist_name` = '$pharmacistname',";
			$sqlset = $sqlset . "`version` = '$version',";
			$sqlset = $sqlset . "`id_user_version` = '$versionid',";
			$sqlset = $sqlset . "`version_date` = '$version_date',";
			$sqlset = $sqlset . "`id_pharmacy` = '$id_pharmacy',";
			$sqlset = $sqlset . "`pharmacy_active` = '$pharmacy_active'";

			$stmt = $this->conn->prepare("UPDATE pharmacy SET ".$sqlset." WHERE id = $id");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				if ($result) {
					// User successfully inserted
					return true;
				} else {
					// Failed to create user
					return false;
				}
				$stmt->close();
		}
		}
		
		public function deletepharmacy($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE pharmacy SET flag_pharmacy =1 WHERE id = $id");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY; 
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		
		public function addpharmacyday($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$idpharmacy = $data['idpharmacy'];
			$idday = $data['idday'];
			$start = $data['starttime'];
			$end = $data['endtime'];
			$version = $data['version'];
			$iduserversion = $data['iduserversion'];
			$versiondate = date('Y-m-d H:i:s');
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$date = date('Y-m-d H:i:s');
				$stmt = $this->conn->prepare("INSERT INTO pharmacy_day(id_pharmacy, id_day, day_start_time, day_end_time,version,id_user_version,version_date) values('$idpharmacy','$idday','$start', '$end','$version','$iduserversion','$versiondate')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function editpharmacyday($data) {
				$response = array();
				// update query
				$id  = $data['id'];
				$daystarttime = $data['daystarttime'];
				$dayendtime = $data['dayendtime'];
				$id_day = $data['id_day'];
				$version = $data['version'];
				$id_user_version = $data['id_user_version'];
				
				$sqlset = $sqlset . "`id` = '$id',";
				$sqlset = $sqlset . "`day_end_time` = '$dayendtime',";
				$sqlset = $sqlset . "`day_start_time` = '$daystarttime',";
				$sqlset = $sqlset . "`day_end_time` = '$id_day',";
				$sqlset = $sqlset . "`version` = '$version',";
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE pharmacy_day SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
			
		public function deletepharmacyday($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE pharmacy_day SET flag_pharmacy_day =1 WHERE id = $id");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getallpharmacyday() {
			$stmt = $this->conn->query("SELECT * FROM pharmacy_day WHERE flag_pharmacy_day = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function addpharmacylaboratory($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_pharmacy = $data['id_pharmacy'];
			$laboratoryid = $data['laboratoryid'];
			$start = $data['startday'];
			$end = $data['endday'];
			$version = $data['version'];
			$iduserversion = $data['iduserversion'];
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$versiondate = date('Y-m-d H:i:s');
				$stmt = $this->conn->prepare("INSERT INTO pharmacy_laboratory(id_pharmacy, id_laboratory, laboratory_start_date, laboratory_end_date,version,id_user_version,version_date) values('$id_pharmacy','$laboratoryid','$start', '$end','$version','$iduserversion','$versiondate')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}

		public function editpharmacylaboratory($data) {
				$response = array();
				// update query
				$id  = $data['id'];
				$laboratoryid = $data['laboratoryid'];
				$start = $data['startday'];
				$end = $data['endday'];
				$version = $data['version'];
				$iduserversion = $data['iduserversion'];
				
				$sqlset = $sqlset . "`id_laboratory` = '$laboratoryid',";
				$sqlset = $sqlset . "`laboratory_start_date` = '$start',";
				$sqlset = $sqlset . "`laboratory_end_date` = '$end',";
				$sqlset = $sqlset . "`version` = '$version',";
				$sqlset = $sqlset . "`id_user_version` = '$iduserversion'";
				$stmt = $this->conn->prepare("UPDATE pharmacy_laboratory SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletepharmacylaboratory($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE pharmacy_laboratory SET flag_pharmacy_day =1 WHERE id = $id");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getallpharmacylaboratory() {
			$stmt = $this->conn->query("SELECT * FROM pharmacy_laboratory WHERE flag_pharmacy_day = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt;  
				return $pharmacy;
			}
		}
		
		public function addpharmacyrole($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_user = $data['id_user'];
			$id_role = $data['id_role'];
			
			$pharmacy_role_start_date = $data['pharmacy_role_start_date'];
			$pharmacy_role_end_date = $data['pharmacy_role_end_date'];
			$version = $data['version'];
			$iduserversion = $data['iduserversion'];
			$email = $data['email'];
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$date = date('Y-m-d H:i:s');
				$idpharmacy = $data['id_pharmacy'];;
				$stmt = $this->conn->prepare("INSERT INTO pharmacy_role(id_pharmacy, id_user, id_role, pharmacy_role_start_date,pharmacy_role_end_date,pharmacy_role_active,version,id_user_version,version_date) values('$idpharmacy','$id_user','$id_role', '$pharmacy_role_start_date','$pharmacy_role_end_date',1,'$version','$iduserversion','$date')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function editpharmacyrole($data) {
				$response = array();
				// update query
				$id  = $data['id'];
				$id_user = $data['id_user'];
				$id_role = $data['id_role'];
				$start = $data['startday'];
				$end = $data['endday'];
				
				$sqlset = $sqlset . "`id_user` = '$id_user',";
				$sqlset = $sqlset . "`id_role` = '$id_role',";
				$sqlset = $sqlset . "`pharmacy_role_start_date` = '$start',";
				$sqlset = $sqlset . "`pharmacy_role_end_date` = '$end'";
				$stmt = $this->conn->prepare("UPDATE pharmacy_role SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletepharmacyrole($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE pharmacy_role SET flag_pharmacy =1 WHERE id = $id");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getallpharmacyrole() {
			$stmt = $this->conn->query("SELECT * FROM pharmacy_role WHERE flag_pharmacy = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt;  
				return $pharmacy;
			}
		}
		
		public function dayschedule($data) {
			$idpharma = $data['idpharma'];
			$stmt = $this->conn->query("SELECT * FROM pharmacy_day WHERE id_pharmacy = '$idpharma'");
			if ($stmt === FALSE){
				die($this->conn->error); 
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function product($data) {
			$response = array();
			// First check if user already existed in db
			$id_product = $data['id_product'];
			$id_laboratory = $data['id_laboratory'];
			$id_range = $data['id_range'];
			$product_name = $data['product_name'];
			$product_description = $data['product_description'];
			$product_indication = $data['product_indication'];
			$product_posology = $data['product_posology'];
			$id_typeprice = $data['id_typeprice'];
			$id_unit = $data['id_unit'];
			$id_user_version = $_SESSION['user']['id'];
			$version_date = date('Y-m-d H:i:s');
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$stmt = $this->conn->prepare("INSERT INTO product(id_product, id_laboratory, id_range, product_name,product_description,product_indication,product_posology,id_typeprice,id_unit,product_active,id_user_version,version_date) values('$id_product','$id_laboratory','$id_range', '$product_name','$product_description','$product_indication','$product_posology','$id_typeprice','$id_unit',1,'$id_user_version','$version_date')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		} 
		
		public function editproduct($data) {
				$response = array();
				// update query
				$id = $data['id'];
				$id_product = $data['id_product'];
				$id_laboratory = $data['id_laboratory'];
				$id_range = $data['id_range'];
				$product_name = $data['product_name'];
				$product_description = $data['product_description'];
				$product_indication = $data['product_indication'];
				$product_posology = $data['product_posology'];
				$id_typeprice = $data['id_typeprice'];
				$id_unit = $data['id_unit'];
				$version = $data['version'];
				$id_user_version = $data['id_user_version'];
				$sqlset = $sqlset . "`id_product` = '$id_product',";
				$sqlset = $sqlset . "`id_laboratory` = '$id_laboratory',";
				$sqlset = $sqlset . "`id_range` = '$id_range',";
				$sqlset = $sqlset . "`product_name` = '$product_name',";
				$sqlset = $sqlset . "`product_description` = '$product_description',";
				$sqlset = $sqlset . "`product_indication` = '$product_indication',";
				$sqlset = $sqlset . "`product_posology` = '$product_posology',";
				$sqlset = $sqlset . "`id_typeprice` = '$id_typeprice',";
				$sqlset = $sqlset . "`id_unit` = '$id_unit',";
				$sqlset = $sqlset . "`version` = '$version',";
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				$stmt = $this->conn->prepare("UPDATE product SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}  
		
		public function deleteproduct($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE product SET flag_product =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		} 
		
		public function getallproduct() {
			$stmt = $this->conn->query("SELECT * FROM product WHERE flag_product = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt;  
				return $pharmacy; 
			}
		} 
		
		public function addproducttag($data) {
			$response = array();
			// First check if user already existed in db
			$id_product = $data['id_product'];
			$id_tag = $data['id_tag'];
			$product_tag_score = $data['product_tag_score'];
			$version = $data['version'];
			$id_user_version = $data['id_user_version'];
			$version_date = date('Y-m-d H:i:s');
			if (!$this->isPharmaExists($email)) {
				$stmt = $this->conn->prepare("INSERT INTO product_tag(id_product, id_tag, product_tag_score, product_tag_active, version,id_user_version,version_date) values('$id_product','$id_tag','$product_tag_score', 1, '$version','$id_user_version','version_date')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();

					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
				public function editproducttag($data) {
				$response = array();
				// update query
				$id = $data['id'];
				$id_product = $data['id_product'];
				$id_tag = $data['id_tag'];
				$product_tag_score = $data['product_tag_score'];
				$version = $data['version'];
				$id_user_version = $data['id_user_version'];
				$sqlset = $sqlset . "`id` = '$id',";
				$sqlset = $sqlset . "`id_product` = '$id_product',";
				$sqlset = $sqlset . "`id_tag` = '$id_tag',";
				$sqlset = $sqlset . "`product_tag_score` = '$product_tag_score',";
				$sqlset = $sqlset . "`version` = '$version',";
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";

				
				$stmt = $this->conn->prepare("UPDATE product_tag SET ".$sqlset." WHERE id = '$id'");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}  

        public function deleteproducttag($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE product_tag SET flag_product_tag =1 WHERE id = $id");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getproducttag($id_product) {
			$stmt = $this->conn->query("SELECT * FROM product_tag WHERE id_product = '$id_product' ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$prodtag = $stmt;  
				return $prodtag; 
			}
		} 
 
		public function composition($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
		    $id_product = $data['id_product'];
            $id_ingredient = $data['id_ingredient'];
			$version = $data['version'];
            $id_user_version = $data['id_user_version'];
			$version_date = date('Y-m-d H:i:s');
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$stmt = $this->conn->prepare("INSERT INTO product_composition(id_product, id_ingredient, product_ingredient_active, version,id_user_version,version_date) values('$id_product','$id_ingredient',1,'$version','$id_user_version','$version_date')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function editcomposition($data) {
				$response = array();
				// update query
				$id = $data['id'];
				$id_product = $data['id_product'];
				$id_ingredient = $data['id_ingredient'];
				$version = $data['version'];
				$id_user_version = $data['id_user_version'];

				$sqlset = $sqlset . "`id_product` = '$id_product',";
				$sqlset = $sqlset . "`id_ingredient` = '$id_ingredient',";
				$sqlset = $sqlset . "`version` = '$version',";
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE product_composition SET ".$sqlset." WHERE id = '$id'");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletecomposition($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE product_composition SET flag_composition =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) { 
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function productcomposition() {
			$stmt = $this->conn->query("SELECT * FROM product_composition WHERE flag_composition = 0");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function addproductform($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
		    $form_id = $data['form_id'];
            $form_name = $data['form_name'];
			$form_description = $data['form_description'];
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$stmt = $this->conn->prepare("INSERT INTO product_form(form_id, form_name, form_description) values('$form_id','$form_name','$form_description')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function editproductform($data) {
				$response = array();
				// update query
				$id = $data['id'];
				 $form_id = $data['form_id'];
				$form_name = $data['form_name'];
				$form_description = $data['form_description'];

				$sqlset = $sqlset . "`form_id` = '$form_id',";
				$sqlset = $sqlset . "`form_name` = '$form_name',";
				$sqlset = $sqlset . "`form_description` = '$form_description'";
				
				$stmt = $this->conn->prepare("UPDATE product_form SET ".$sqlset." WHERE id = '$id'");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deleteproductform($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE product_form SET flag_product_form =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) { 
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function productform() {
			$stmt = $this->conn->query("SELECT * FROM product_form WHERE flag_product_form = 0");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function addproductingredient($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
		    $ingredient_id = $data['ingredient_id'];
            $cosing_reference = $data['cosing_reference'];
			$ingredient_name = $data['ingredient_name'];
			$rating = $data['rating'];
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$stmt = $this->conn->prepare("INSERT INTO product_ingredient(ingredient_id, cosing_reference, ingredient_name,rating) values('$ingredient_id','$cosing_reference','$ingredient_name','$rating')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function editproductingredient($data) {
				$response = array();
				// update query
				$id = $data['id'];
				$ingredient_id = $data['ingredient_id'];
				$cosing_reference = $data['cosing_reference'];
				$ingredient_name = $data['ingredient_name'];
				$rating = $data['rating'];

				$sqlset = $sqlset . "`ingredient_id` = '$ingredient_id',";
				$sqlset = $sqlset . "`cosing_reference` = '$cosing_reference',";
				$sqlset = $sqlset . "`ingredient_name` = '$ingredient_name',";
				$sqlset = $sqlset . "`rating` = '$rating'";
				
				$stmt = $this->conn->prepare("UPDATE product_ingredient SET ".$sqlset." WHERE id = '$id'");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deleteproductingredient($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE product_ingredient SET flag_product_ingredent =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) { 
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function productingredient() {
			$stmt = $this->conn->query("SELECT * FROM product_ingredient WHERE flag_product_ingredent = 0");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function productrangeprice($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db 
			$range_price_id = $data['range_price_id'];
			$range_price_text = $data['range_price_text'];
			$range_price_picture = $data['range_price_picture'];
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$stmt = $this->conn->prepare("INSERT INTO  product_range_price (range_price_id,  range_price_text, range_price_picture) values('$range_price_id','$range_price_text','$range_price_picture')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function editproductrangeprice($data) {
				$response = array();
				// update query
				$id = $data['id'];
				$range_price_id = $data['range_price_id'];
				$range_price_text = $data['range_price_text'];
				$range_price_picture = $data['range_price_picture'];
				
				$sqlset = $sqlset . "`range_price_id` = '$range_price_id',";
				$sqlset = $sqlset . "`range_price_text` = '$range_price_text',";
				$sqlset = $sqlset . "`range_price_picture` = '$range_price_picture'";
				
				$stmt = $this->conn->prepare("UPDATE product_range_price SET ".$sqlset." WHERE id = '$id'");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion 
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deleteproductrangeprice($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE product_range_price SET range_price_flag =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) { 
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function productproductrangeprice() {
			$stmt = $this->conn->query("SELECT * FROM product_range_price WHERE range_price_flag = 0");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function addpharmacypromotion($data) {
			
			// First check if user already existed in db 
			$pharmacy_id = $data['pharmacy_id'];
			$promotion_start_date = $data['promotion_start_date'];
			$promotion_end_date = $data['promotion_end_date'];
			$id_promotion = md5($this->generateRandomString($length = 8));
			$id_user_version = $_SESSION['user']['id']; 
			$date = date('Y-m-d H:i:s');
			
				// insert query
				$stmt = $this->conn->prepare("INSERT INTO promotion (id_pharmacy, id_promotion, promotion_start_date, promotion_end_date, id_user_version, version_date)
											values('$pharmacy_id', '$id_promotion','$promotion_start_date','$promotion_end_date','$id_user_version','$date')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return PROMOTION_SUCCESSFULLY; 
				} else {
					// Failed to create user
					return PROMOTION_FAILED;
				}
		}
		
		public function editpharmacypromotion($data) {
			
				// update query
				$id_promotion = $data['id_promotion'];
				$promotion_start_date = $data['promotion_start_date'];
				$promotion_end_date = $data['promotion_end_date'];
				$version = $this->updateversion('promotion','id_promotion',$id_promotion);
				$id_user_version = $_SESSION['user']['id'];
				
				$previousstart = $this->getcolumnvalue('promotion','promotion_start_date','id_promotion',$id_promotion); 
				$previousend = $this->getcolumnvalue('promotion','promotion_end_date','id_promotion',$id_promotion);
				
				if(isset($promotion_start_date) && ($previousstart != $promotion_start_date)){
					$sqlset = $sqlset . "`promotion_start_date` = '$promotion_start_date',";
				}
				if(isset($promotion_end_date) && ($previousend != $promotion_end_date)){
					$sqlset = $sqlset . "`promotion_end_date` = '$promotion_end_date',";
				}
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version',";
				$sqlset = rtrim($sqlset, ',');
				if ($sqlset!='' ){
					$sql = "UPDATE promotion SET ".$sqlset." WHERE id_promotion = '$id_promotion'";
					$stmt = $this->conn->prepare($sql);
					if ($stmt === FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt->execute();
						$stmt->close();
					}
				}
				// Check for successful insertion 
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
		}
		
		public function deletepharmacypromotion($data){
			$id_promotion  = $data['id_promotion'];
			$this->redeletedcheck('promotion','promotion_active','id_promotion',$id_promotion);
			$stmt = $this->conn->prepare("UPDATE  promotion SET promotion_active =0 WHERE id_promotion = '$id_promotion'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) { 
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function listpharmacypromotion() {
			$stmt = $this->conn->query("SELECT * FROM pharmacy_promotions WHERE flag_pharmacy_promotions = 0");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function addpharmacypromotionitem($data) {
			
			// First check if user already existed in db 
			$id_typepromotion = $data['id_typepromotion'];
			$id_asset = $data['id_asset'];
			$promotion_price_old = $data['promotion_price_old'];
			$promotion_price_new = $data['promotion_price_new'];
			$promotion_discount_amt = $data['promotion_discount_amt'];
			$promotion_discount_pct = $data['promotion_discount_pct'];
			$promotion_discount_number = $data['promotion_discount_number'];
			$promotion_buy_number = $data['promotion_buy_number'];
			$id_promotion = md5($this->generateRandomString($length = 8));
			$id_user_version = $_SESSION['user']['id'];
			$date = date('Y-m-d H:i:s');
			
				// insert query
				$stmt = $this->conn->prepare("INSERT INTO promotion_item (id_promotion, id_typepromotion, id_asset, promotion_price_old, promotion_price_new, promotion_discount_amt, promotion_discount_pct, promotion_discount_number, promotion_buy_number, id_user_version, version_date)
values('$id_promotion', '$id_typepromotion','$id_asset','$promotion_price_old','$promotion_price_new','$promotion_discount_amt','$promotion_discount_pct','$promotion_discount_number','$promotion_buy_number','$id_user_version','$date')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return PROMOTION_SUCCESSFULLY; 
				} else {
					// Failed to create user
					return PROMOTION_FAILED;
				}
		}

		public function editpharmacypromotionitem($data) {
			
				// update query
				$id_promotion = $data['id_promotion'];
				$id_typepromotion = $data['id_typepromotion'];
				$id_asset = $data['id_asset'];
				$promotion_price_old = $data['promotion_price_old'];
				$promotion_price_new = $data['promotion_price_new'];
				$promotion_discount_amt = $data['promotion_discount_amt'];
				$promotion_discount_pct = $data['promotion_discount_pct'];
				$promotion_discount_number = $data['promotion_discount_number'];
				$promotion_buy_number = $data['promotion_buy_number'];
				$version = $this->updateversion('promotion','id_promotion',$id_promotion);
				$id_user_version = $_SESSION['user']['id'];

				
				$previousid_type = $this->getcolumnvalue('promotion_item','id_typepromotion','id_promotion',$id_promotion);
				$previousid_asset = $this->getcolumnvalue('promotion_item','id_asset','id_promotion',$id_promotion);
				$previousprice_old = $this->getcolumnvalue('promotion_item','promotion_price_old','id_promotion',$id_promotion);
				$previousprice_new = $this->getcolumnvalue('promotion_item','promotion_price_new','id_promotion',$id_promotion); 
				$previousamt = $this->getcolumnvalue('promotion_item','promotion_discount_amt','id_promotion',$id_promotion);
				$previouspct = $this->getcolumnvalue('promotion_item','promotion_discount_pct','id_promotion',$id_promotion);
				$previousnumber = $this->getcolumnvalue('promotion_item','promotion_discount_number','id_promotion',$id_promotion); 
				$previousbuy_number = $this->getcolumnvalue('promotion_item','promotion_buy_number','id_promotion',$id_promotion);
				
				if(isset($id_typepromotion) && ($previousid_type != $id_typepromotion)){
					$sqlset = $sqlset . "`id_typepromotion` = '$id_typepromotion',";
				}
				if(isset($id_asset) && ($previousid_asset != $id_asset)){
					$sqlset = $sqlset . "`id_asset` = '$id_asset',";
				}
				if(isset($promotion_price_old) && ($previousprice_old != $promotion_price_old)){
					$sqlset = $sqlset . "`promotion_price_old` = '$promotion_price_old',";
				}
				if(isset($promotion_price_new) && ($previousprice_new != $promotion_price_new)){
					$sqlset = $sqlset . "`promotion_price_new` = '$promotion_price_new',";
				}
				if(isset($promotion_discount_amt) && ($previousamt != $promotion_discount_amt)){
					$sqlset = $sqlset . "`promotion_discount_amt` = '$promotion_discount_amt',";
				}
				if(isset($promotion_discount_pct) && ($previouspct != $promotion_discount_pct)){
					$sqlset = $sqlset . "`promotion_discount_pct` = '$promotion_discount_pct',";
				}
				if(isset($promotion_discount_number) && ($previousnumber != $promotion_discount_number)){
					$sqlset = $sqlset . "`promotion_discount_number` = '$promotion_discount_number',";
				}
				if(isset($promotion_buy_number) && ($previousbuy_number != $promotion_buy_number)){
					$sqlset = $sqlset . "`promotion_buy_number` = '$promotion_buy_number',";
				}
				
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version',";
				$sqlset = rtrim($sqlset, ',');
				if ($sqlset!='' ){
					$version = $this->updateversion('promotion_item','id_promotion',$id_promotion);
					$stmt = $this->conn->prepare("UPDATE promotion_item SET ".$sqlset." WHERE id_promotion = '$id_promotion'");
					if ($stmt === FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt->execute();
						$stmt->close();
					}
				}
				// Check for successful insertion 
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
		}

		public function deletepharmacypromotionitem($data){
			$id_promotion  = $data['id_promotion'];
			$this->redeletedcheck('promotion_item','promotion_item_active','id_promotion',$id_promotion);
			$stmt = $this->conn->prepare("UPDATE  promotion_item SET promotion_item_active =0 WHERE id_promotion = '$id_promotion'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) { 
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function productexist($id_product){
			$qry = "SELECT * FROM product WHERE id_product = '$id_product'";
			$stmt = $this->conn->query($qry);
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$num_rows = $stmt->num_rows;
				print_r($num_rows);
					if($num_rows == 0){
						echo "sorry product id doesn't exist";
						exit();
					}
			}
		}
		
		public function addproductrating($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db 
			$id_product = $data['id_product'];
			$this->productexist($id_product);
			$product_rating = $data['product_rating'];
			$product_rating_comments = $data['product_rating_comments'];
			$version_date =  date('Y-m-d H:i:s');
			$id_user_version = $_SESSION['user']['id'];
			$product_rating_date = date('Y-m-d H:i:s');
			$id_productrating = md5($this->generateRandomString($length = 8));
				// insert query
				$stmt = $this->conn->prepare("INSERT INTO  product_rating (id_product,  product_rating_date, product_rating, product_rating_comments,id_user_version,version_date, id_user, id_productrating) values('$id_product','$product_rating_date','$product_rating','$product_rating_comments','$id_user_version','$version_date', '$id_user_version', '$id_productrating')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return PRODUCTRATING_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return PRODUCTRATING_CREATE_FAILED;
				}
			return $response;
		}
		
		public function editproductrating($data) {
				$response = array();
				// update query
				$id_product = $data['id_product'];
				$this->productexist($id_product);
				$product_rating = $data['product_rating'];
				$product_rating_comments = $data['product_rating_comments'];
				$product_rating_active = $data['product_rating_active'];
				$this->updateversion('product_rating','id_product',$id_product); 
				$id_user_version = $_SESSION['user']['id'];
				
				$previousproduct_rating = $this->getcolumnvalue('product_rating','product_rating','id_product',$id_product); 
				$previousproduct_rating_comments = $this->getcolumnvalue('product_rating','product_rating_comments','id_product',$id_product);
				$previousproduct_rating_active = $this->getcolumnvalue('product_rating','product_rating_active','id_product',$id_product);
				
				if(isset($product_rating) && ($previousproduct_rating != $product_rating)){
					$sqlset = $sqlset . "`product_rating` = '$product_rating',";
				}
				if(isset($product_rating_comments) && ($previousproduct_rating_comments != $product_rating_comments)){
					$sqlset = $sqlset . "`product_rating_comments` = '$product_rating_comments',";
				}
				if(isset($product_rating_active) && ($previousproduct_rating_active != $product_rating_active)){
					$sqlset = $sqlset . "`product_rating_active` = '$product_rating_active',";
				}
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version',";
				$sqlset = rtrim($sqlset, ',');
				if ($sqlset!='' ){
					
					$stmt = $this->conn->prepare("UPDATE product_rating SET ".$sqlset." WHERE id_product = '$id_product'");
					if ($stmt === FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt->execute();
						$stmt->close();
					}
					// Check for successful insertion 
					if ($result) {
						// User successfully inserted
						return PRODUCTRATING_UPDATED_SUCCESSFULLY;
					}
				} else {
					// Failed to create user
					return PRODUCTRATING_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deleteproductrating($id_productrating){
			
			$this->redeletedcheck('product_rating','product_rating_active','id_productrating',$id_productrating);
			$stmt = $this->conn->prepare("UPDATE product_rating SET product_rating_active = 0 WHERE id_productrating = '$id_productrating'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PRODUCTRATING_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PRODUCTRATING_UPDATED_FAILED;
			}
		}
		
		public function usersessioncheck($table,$ref,$refvalue){
			$date = date('Y-m-d H:i:s');
			$qry = "SELECT id_user_version FROM $table 
										WHERE $ref = '$refvalue'";
			$stmt = $this->conn->query($qry);
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$product = $stmt->fetch_array(MYSQLI_ASSOC);
				$oldssn = $product["id_user_version"];
				$newssn = $_SESSION['user']['id'];
				if ($newssn !== $oldssn){
					echo "sorry you can not delete this data";
					exit();
					}
			}
		}
  
		public function getallproductrating($id_product) {
			$stmt = $this->conn->query("SELECT * FROM product_rating WHERE flag_product_rating = 1 AND id_product = '$id_product'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$prod = $stmt; 
				return $prod;
			}
		}
			
			/*today api*/
		public function productcode($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_product = $data['id_product'];
			$product_code = $data['product_code'];
			$product_volume = $data['product_volume'];
			$id_coulour = $data['id_coulour'];
			$version = $data['version'];
			$id_user_version = $data['id_user_version'];
			$date = date('Y-m-d H:i:s');
						
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$stmt = $this->conn->prepare("INSERT INTO  product_code(id_product,  product_code, product_volume, id_coulour,product_code_active,version,id_user_version,version_date) values('$id_product','$product_code','$product_volume','$id_coulour',1,'$version','$id_user_version','$date')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
				
		
		
		public function editproductcode($data) {
				$response = array();
				// update query
				$id = $data['id'];
				$id_product = $data['id_product'];
				$product_code = $data['product_code'];
				$product_volume = $data['product_volume'];
				$id_coulour = $data['id_coulour'];
				$version = $data['version'];
				$id_user_version = $data['id_user_version'];
				
				$sqlset = $sqlset . "`id_product` = '$id_product',";
				$sqlset = $sqlset . "`product_code` = '$product_code',";
				$sqlset = $sqlset . "`product_volume` = '$product_volume',";
				$sqlset = $sqlset . "`id_coulour` = '$id_coulour',";
				$sqlset = $sqlset . "`version` = '$version',";
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE product_code SET ".$sqlset." WHERE id = '$id'");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}	

		
		public function deleteproductcode($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE product_code SET flag_product =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}    
		
		
		public function getallproductcode() {
			$stmt = $this->conn->query("SELECT * FROM product_code WHERE flag_product = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}



		public function useraccess($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_user = $data['id_user'];
			$pharmacy_code = $data['pharmacy_code'];
			$user_gps = $data['user_gps'];
			$id_role = $data['id_role'];
			$user_access_date = $data['user_access_date'];
			$version = $data['version'];
			$id_user_version = $data['id_user_version'];
			$version_date = $data['version_date'];
			$date = date('Y-m-d H:i:s');			
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$stmt = $this->conn->prepare("INSERT INTO  user_access(id_user,  pharmacy_code, user_gps, id_role,user_access_date,version,id_user_version,version_date) values('$id_user','$pharmacy_code','$user_gps','$id_role','$user_access_date','$version','$id_user_version','$date')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}

		public function edituseraccess($data) {
				$response = array();
				// update query
				$id = $data['id'];
				$id_user = $data['id_user'];
				$pharmacy_code = $data['pharmacy_code'];
				$user_gps = $data['user_gps'];
				$id_role = $data['id_role'];
				$user_access_date = $data['user_access_date'];
				$version = $data['version'];
				$id_user_version = $data['id_user_version'];
				$sqlset = $sqlset . "`id_user` = '$id_user',";
				$sqlset = $sqlset . "`pharmacy_code` = '$pharmacy_code',";
				$sqlset = $sqlset . "`user_gps` = '$user_gps',";
				$sqlset = $sqlset . "`id_role` = '$id_role',";
				$sqlset = $sqlset . "`user_access_date` = '$user_access_date',";
				$sqlset = $sqlset . "`version` = '$version',";
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE user_access SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}		

		
		
		public function deleteuseraccess($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE user_access SET flag_product =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}    
		
		
		public function getalluseraccess() {
			$stmt = $this->conn->query("SELECT * FROM user_access JOIN user ON user_access.id_user = user.id WHERE flag_product = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}

		
		
		public function role($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_role = $data['id_role'];
			$role_name = $data['role_name'];
			$version = $data['version'];
			$id_user_version = $data['id_user_version'];
			$date = date('Y-m-d H:i:s');			
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$stmt = $this->conn->prepare("INSERT INTO  role (id_role,  role_name,role_active,version,id_user_version,version_date) values('$id_role','$role_name',1,'$version','$id_user_version','$date')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
			
			
		public function editrole($data) {
				$response = array();
				// update query
				$id = $data['id'];
				$id_role = $data['id_role'];
				$role_name = $data['role_name'];
				$version = $data['version'];
				$id_user_version = $data['id_user_version'];
				
				
				$sqlset = $sqlset . "`id_role` = '$id_role',";
				$sqlset = $sqlset . "`role_name` = '$role_name',";
				$sqlset = $sqlset . "`version` = '$version',";
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE role SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}



		public function deleterole($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE role SET flag_product =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}    		
		
		public function getallrole() {
			$stmt = $this->conn->query("SELECT * FROM role WHERE flag_product = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		
		public function addrange($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_range = $data['id_range'];
			$id_laboratory = $data['id_laboratory'];
			$range_name = $data['range_name'];
			$id_typerange = $data['id_typerange'];
			$id_picture = $data['id_picture'];
			$version = $data['version'];
			$id_user_version = $data['id_user_version'];
			$date = date('Y-m-d H:i:s');					
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `range` (id_range,  id_laboratory,range_name,id_typerange,id_picture,range_active,version,id_user_version,version_date) values('$id_range','$id_laboratory','$range_name','$id_typerange','$id_picture',1,'$version','$id_user_version','$date')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}		
		
		public function editrange($data) {
				$response = array();
				// update query
				$id = $data['id'];
				$id_range = $data['id_range'];
				$id_laboratory = $data['id_laboratory'];
				$range_name = $data['range_name'];
				$id_typerange = $data['id_typerange'];
				$id_picture = $data['id_picture'];
				$version = $data['version'];
				$id_user_version = $data['id_user_version'];
				
				$sqlset = $sqlset . "`id_range` = '$id_range',";
				$sqlset = $sqlset . "`id_laboratory` = '$id_laboratory',";
				$sqlset = $sqlset . "`range_name` = '$range_name',";				
				$sqlset = $sqlset . "`id_typerange` = '$id_typerange',";
				$sqlset = $sqlset . "`id_picture` = '$id_picture',";
				$sqlset = $sqlset . "`version` = '$version',";
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE `range` SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}



		public function deleterange($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE `range` SET flag_product =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}    
		

		public function getallrange() {
			$stmt = $this->conn->query("SELECT * FROM `range` WHERE flag_product = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function addmember($data) {
			$response = array();
			// First check if user already existed in db
			$id_member 	 	 = md5($this->generateRandomString($length = 4));
			$id_user 	 = $data['id_user'];
			$member_name  = $data['member_name'];
			$mem_dob  = date('Y-m-d',strtotime($data['mem_dob']));
			$id_picture = $data['id_picture'];
			$date 			 = date('Y-m-d H:i:s');	
			$id_user_version = $_SESSION['user']['id'];	
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `member` (id_member, id_user, member_name, mem_dob, id_picture, flg_member_active, id_user_version, version_date) values('$id_member','$id_user','$member_name', '$mem_dob','$id_picture',1,'$id_user_version','$date')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function editmember($data) {
				// update query
				$id_member = $data['id_member'];
				$member_name  = $data['member_name'];
				$picture_id  = $data['picture_id'];
				$date1 = str_replace("/","-",$data['mem_dob']); 
				$mem_dob  =  date('Y-m-d',strtotime($date1));
				$id_picture = $data['id_picture'];
				$this->updateversion('member','id',$id);
				$id_user_version = $_SESSION['user']['id'];	
				
				if($this->checkmember($id_member) == true){
					print_r($this->checkmember($id_member));
					
					$previousmember_name = $this->getcolumnvalue('member','member_name','id_member',$id_member); 
					$previousemem_dob = $this->getcolumnvalue('member','mem_dob','id_member',$id_member);
					$previouseid_picture = $this->getcolumnvalue('member','id_picture','id_member',$id_member);
					
					if(isset($member_name) && ($previousmember_name != $member_name)){
						$sqlset = $sqlset . "`member_name` = '$member_name',";
					}
					if(isset($mem_dob) && ($previousemem_dob != $mem_dob)){
						$sqlset = $sqlset . "`mem_dob` = '$mem_dob',";
					}
					if(isset($id_picture) && ($previouseid_picture != $id_picture)){
						$sqlset = $sqlset . "`id_picture` = '$id_picture',";
					}
					$sqlset = $sqlset . "`id_user_version` = '$id_user_version',";
					$sqlset = rtrim($sqlset, ',');
					if ($sqlset!='' ){
						$stmt = $this->conn->prepare("UPDATE member SET ".$sqlset." WHERE id_member = '$id_member'");
							
						if ($stmt === FALSE){
							die($this->conn->error);
						} else  {
							$result = $stmt->execute();
							$stmt->close();
						}
						// Check for successful insertion
						if ($result) {
							// User successfully inserted
							return USER_UPDATED_SUCCESSFULLY;
						} else {
							// Failed to create user
							return USER_UPDATED_FAILED;
						}
					}
				} else {
					return YOU_CANNOT_EDIT;
				}
		}
		
		public function checkmember($idmember){
			 $iduser = $_SESSION['user']['id'];
			 $sql = "SELECT id_user FROM member WHERE id_member= '$idmember'";
			 $stmt = $this->conn->query($sql);
			
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				 $detail = $stmt->fetch_array(MYSQLI_ASSOC);
				 $result = $detail['id_user'];
				 if($iduser == $result ){
					 return true;
				 }else{
				 	return false;
				 }
			}
		}
		
		public function alreadydeleted($id_member){
			$sql = "SELECT flg_mem_visible FROM member WHERE id_member = '$id_member'";
			$stmt = $this->conn->query($sql);
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$detail = $stmt->fetch_array(MYSQLI_ASSOC);
				$result = $detail['flg_mem_visible'];
			}
			if($result == 0){
				$response["error"] = true;
                $response["message"] = "Oops! Already Deleted";
				echoRespnse(201, $response);
				exit();
			}
		} 
		
		public function deletemember($data){
			$id_member  = $data['id_member'];
			if($this->checkmember($id_member) == true){
				$this->alreadydeleted($id_member);
				$sql = "UPDATE `member` SET flg_mem_visible = 0 WHERE id_member = '$id_member'";
				$stmt = $this->conn->prepare($sql);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_DELETED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_DELETED_FAILED;
				}
			} else {
				return CANNOT_DELETE;
			}
		} 
		
		public function getallmember() {
			$iduser = $_SESSION['user']['id'];
			$stmt = $this->conn->query("SELECT member.*,picture.picture_name FROM `member`
										LEFT JOIN picture ON member.id_picture = picture.id
										WHERE member.flg_member_active = 1 AND member.flg_mem_visible = 1 AND member.id_user = '$iduser'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$details = $stmt; 
				return $details;
			}
		}
		
		public function addfamilytag($data) {
			$response = array();
			// First check if user already existed in db
			$id_family_tag 		= $data['id_family_tag'];
			$id_family 			= $data['id_family'];
			$id_tag 			= $data['id_tag'];
			$id_family_next	    = $data['id_family_next'];
			$family_tag_active	= $data['family_tag_active'];
			$version 			= $data['version'];
			$id_user_version	= $data['id_user_version'];
			$date = date('Y-m-d H:i:s');
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$stmt = $this->conn->prepare("INSERT INTO  family_tag (id_family_tag ,  id_family , id_tag , id_family_next , family_tag_active , version , id_user_version , version_date) values('$id_family_tag','$id_family','$id_tag','$id_family_next','family_tag_active','$version','$id_user_version','$date')");
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function editfamilytag($data) {
				$response = array();
				// update query
				$id					= $data['id'];
				$id_family_tag 		= $data['id_family_tag'];
				$id_family 			= $data['id_family'];
				$id_tag 			= $data['id_tag'];
				$id_family_next	    = $data['id_family_next'];
				$version 			= $data['version'];
				$id_user_version	= $data['id_user_version'];
			
				
				$sqlset = $sqlset . "`id_family_tag` = '$id_family_tag',";
				$sqlset = $sqlset . "`id_family` = '$id_family',";
				$sqlset = $sqlset . "`id_tag` = '$id_tag',";
				$sqlset = $sqlset . "`id_family_next` = '$id_family_next',";
				$sqlset = $sqlset . "`family_tag_active` = 1,";
				$sqlset = $sqlset . "`version` = '$version',";
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				
				$stmt = $this->conn->prepare("UPDATE family_tag SET ".$sqlset." WHERE id = '$id'");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletefamilytag($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE family_tag SET flag_family_tag =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getallfamilytag() {
			$stmt = $this->conn->query("SELECT * FROM family_tag WHERE flag_family_tag = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function addcontact($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$contact_email 	  =  $data['contact_email'];
			$contact_subject  =  $data['contact_subject'];
			$contact_form 	  =  $data['contact_form'];
			date_default_timezone_set('Asia/Calcutta');
			$date			  =  date('Y-m-d H:i:s');		
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `contact` (contact_email, contact_subject, contact_form, contact_date) values('$contact_email','$contact_subject','$contact_form','$date')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function editcontact($data) {
				$response = array();
				// update query
				$contact_id = $data['contact_id'];
				$contact_email = $data['contact_email'];
				$contact_subject = $data['contact_subject'];
				$contact_form = $data['contact_form'];
				
				$sqlset = $sqlset . "`contact_email` = '$contact_email',";
				$sqlset = $sqlset . "`contact_subject` = '$contact_subject',";
				$sqlset = $sqlset . "`contact_form` = '$contact_form'";	
				
				$stmt = $this->conn->prepare("UPDATE `contact` SET ".$sqlset." WHERE contact_id = $contact_id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletecontact($data){
			$contact_id  = $data['contact_id'];
			$stmt = $this->conn->prepare("UPDATE `contact` SET flag_contact =1 WHERE contact_id = '$contact_id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getallcontact() {
			$stmt = $this->conn->query("SELECT * FROM `contact` WHERE flag_contact = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}


		public function testques($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_ques 	  =  $data['id_ques'];
			$id_surv  =  $data['id_surv'];
			$ques_name 	  =  $data['ques_name'];
			$id_typeques 	  =  $data['id_typeques'];
			$id_ques_next  =  $data['id_ques_next'];
			$ques_value 	  =  $data['ques_value'];
			$ques_desc 	  =  $data['ques_desc'];
			$id_usre_ds  =  $data['id_usre_ds'];
			$usre_ds_mem 	  =  $data['usre_ds_mem'];
			$version_nbr 	  =  $data['version_nbr'];
			$version_date  =  date('Y-m-d H:i:s');
			$id_usre_version 	  =  $data['id_usre_version'];
					
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `test_ques` (id_ques, id_surv, ques_name, id_typeques,id_ques_next,ques_value,ques_desc,id_usre_ds,usre_ds_mem,flg_active,version_nbr,version_date,id_usre_version) values('$id_ques','$id_surv','$ques_name','$id_typeques','$id_ques_next','$ques_value','$ques_desc','$id_usre_ds','$usre_ds_mem',1,'$version_nbr','$version_date','$id_usre_version')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function edittestques($data) {
				$response = array();
				// update query
				$id_ques 	  =  $data['id_ques'];
				$id_surv  =  $data['id_surv'];
				$ques_name 	  =  $data['ques_name'];
				$id_typeques 	  =  $data['id_typeques'];
				$id_ques_next  =  $data['id_ques_next'];
				$ques_value 	  =  $data['ques_value'];
				$ques_desc 	  =  $data['ques_desc'];
				$id_usre_ds  =  $data['id_usre_ds'];
				$usre_ds_mem 	  =  $data['usre_ds_mem']; 
				$version_nbr 	  =  $data['version_nbr'];
				$id_usre_version 	  =  $data['id_usre_version'];
				
				$sqlset = $sqlset . "`id_surv` = '$id_surv',";
				$sqlset = $sqlset . "`ques_name` = '$ques_name',";	
				$sqlset = $sqlset . "`id_typeques` = '$id_typeques',";
				$sqlset = $sqlset . "`id_ques_next` = '$id_ques_next',";
				$sqlset = $sqlset . "`ques_value` = '$ques_value',";	
				$sqlset = $sqlset . "`ques_desc` = '$ques_desc',";
				$sqlset = $sqlset . "`id_usre_ds` = '$id_usre_ds',";
				$sqlset = $sqlset . "`usre_ds_mem` = '$usre_ds_mem',";	
				$sqlset = $sqlset . "`version_nbr` = '$version_nbr',";
				$sqlset = $sqlset . "`id_usre_version` = '$id_usre_version'";	
				
				$stmt = $this->conn->prepare("UPDATE `test_ques` SET ".$sqlset." WHERE id_ques = $id_ques");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletetestques($data){
			$id_ques  = $data['id_ques'];
			$stmt = $this->conn->prepare("UPDATE `test_ques` SET flg_visible =1 WHERE id_ques = '$id_ques'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getalltestques() {
			$stmt = $this->conn->query("SELECT * FROM `test_ques` WHERE flg_visible = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function testquestag($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_ques_tag 	  =  $data['id_ques_tag'];
			$id_ques  =  $data['id_ques'];
			$id_tag 	  =  $data['id_tag'];
			$flg_ques_tag_alt 	  =  $data['flg_ques_tag_alt'];
			$id_usre_ds  =  $data['id_usre_ds'];
			$usre_ds_mem 	  =  $data['usre_ds_mem'];
			$id_usre_ds  =  $data['id_usre_ds'];
			$usre_ds_mem 	  =  $data['usre_ds_mem'];
			$version_nbr 	  =  $data['version_nbr'];
			$version_date  =  date('Y-m-d H:i:s');
			$id_usre_version 	  =  $data['id_usre_version'];
					
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `test_ques_tag` (id_ques_tag, id_ques, id_tag, flg_ques_tag_alt,id_usre_ds,usre_ds_mem,flg_active,version_nbr,version_date,id_user_version) values('$id_ques_tag','$id_ques','$id_tag','$flg_ques_tag_alt','$id_usre_ds','$usre_ds_mem',1,'$version_nbr','$version_date','$id_usre_version')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function edittestquestag($data) {
				$response = array();
				// update query
				$id 		=  $data['id'];
				$id_ques_tag 	  =  $data['id_ques_tag'];
				$id_ques  =  $data['id_ques'];
				$id_tag 	  =  $data['id_tag'];
				$flg_ques_tag_alt 	  =  $data['flg_ques_tag_alt'];
				$id_usre_ds  =  $data['id_usre_ds'];
				$usre_ds_mem 	  =  $data['usre_ds_mem'];
				$version_nbr 	  =  $data['version_nbr'];
				$version_date  =  date('Y-m-d H:i:s');
				$id_usre_version 	  =  $data['id_usre_version'];
				
				$sqlset = $sqlset . "`id_ques_tag` = '$id_ques_tag',";
				$sqlset = $sqlset . "`id_ques` = '$id_ques',";
				$sqlset = $sqlset . "`id_tag` = '$id_tag',";	
				$sqlset = $sqlset . "`flg_ques_tag_alt` = '$flg_ques_tag_alt',";
				$sqlset = $sqlset . "`id_usre_ds` = '$id_usre_ds',";
				$sqlset = $sqlset . "`usre_ds_mem` = '$usre_ds_mem',";	
				$sqlset = $sqlset . "`version_nbr` = '$version_nbr',";
				$sqlset = $sqlset . "`id_user_version` = '$id_usre_version'";
				
				$stmt = $this->conn->prepare("UPDATE `test_ques_tag` SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletetestquestag($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE `test_ques_tag` SET flg_visible =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getalltest_ques_tag() {
			$stmt = $this->conn->query("SELECT * FROM `test_ques_tag` WHERE flg_visible = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function testquestion($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_question 	  =  $data['id_question'];
			$id_test  =  $data['id_test'];
			$question_value 	  =  $data['question_value'];
			$question_description 	  =  $data['question_description'];
			$question_order  =  $data['question_order'];
			$version 	  =  $data['version'];
			$id_user_version  =  $data['id_user_version'];
			$version_date  =  date('Y-m-d H:i:s');
					
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `test_question` (id_question, id_test, question_value, question_description, question_order, question_active, version, id_user_version, version_date) values('$id_question','$id_test','$question_value','$question_description','$question_order',1,'$version','$id_user_version','$version_date')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function edittestquestion($data) {
				$response = array();
				// update query
				$id 		=  $data['id'];
				$id_question 	  =  $data['id_question'];
				$id_test  =  $data['id_test'];
				$question_value 	  =  $data['question_value'];
				$question_description 	  =  $data['question_description'];
				$question_order  =  $data['question_order'];
				$version 	  =  $data['version'];
				$id_user_version  =  $data['id_user_version'];
				$version_date  =  date('Y-m-d H:i:s');
				
				$sqlset = $sqlset . "`id_question` = '$id_question',";
				$sqlset = $sqlset . "`id_test` = '$id_test',";
				$sqlset = $sqlset . "`question_value` = '$question_value',";	
				$sqlset = $sqlset . "`question_description` = '$question_description',";
				$sqlset = $sqlset . "`question_order` = '$question_order',";
				$sqlset = $sqlset . "`version` = '$version',";	
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version',";
				$sqlset = $sqlset . "`version_date` = '$version_date'";
				
				$stmt = $this->conn->prepare("UPDATE `test_question` SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletetestquestion($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE `test_question` SET flg_visible =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getalltest_question() {
			$stmt = $this->conn->query("SELECT * FROM `test_question` WHERE flg_visible = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function testquestiontag($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_question 	  =  $data['id_question'];
			$id_tag  =  $data['id_tag'];
			$version 	  =  $data['version'];
			$id_user_version  =  $data['id_user_version'];
			$version_date  =  date('Y-m-d H:i:s');
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `test_question_tag` (id_question, id_tag, version, id_user_version, version_date) values('$id_question','$id_tag','$version','$id_user_version','$version_date')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close(); 
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function edittestquestiontag($data) {
				$response = array();
				// update query
				$id 		=  $data['id'];
				$id_question 	  =  $data['id_question'];
				$id_tag  =  $data['id_tag'];
				$version 	  =  $data['version'];
				$id_user_version  =  $data['id_user_version'];
				
				$sqlset = $sqlset . "`id_question` = '$id_question',";
				$sqlset = $sqlset . "`id_tag` = '$id_tag',";
				$sqlset = $sqlset . "`version` = '$version',";	
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE `test_question_tag` SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletetestquestiontag($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE `test_question_tag` SET flg_visible =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getalltest_question_tag() {
			$stmt = $this->conn->query("SELECT * FROM `test_question_tag` WHERE flg_visible = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function testsurv($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_surv 	  =  $data['id_surv'];
			$cod_surv  =  $data['cod_surv'];
			$surv_name  =  $data['surv_name'];
			$surv_desc 	  =  $data['surv_desc'];
			$id_ques_start 	  =  $data['id_ques_start'];
			$id_user_ds  =  $data['id_user_ds'];
			$user_ds_mem 	  =  $data['user_ds_mem'];
			$version_nbr	  =  $data['version_nbr'];
			$id_user_version  =  $data['id_user_version'];
			$version_date  =  date('Y-m-d H:i:s');
					
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `test_surv` (id_surv, cod_surv, surv_name, surv_desc, id_ques_start, id_user_ds, user_ds_mem, flg_active,version_nbr, id_user_version, version_date) values('$id_surv','$cod_surv', '$surv_name','$surv_desc','$id_ques_start','$id_user_ds','$user_ds_mem', 1,'$version_nbr','$id_user_version','$version_date')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function edittestsurv($data) {
				$response = array();
				// update query
				$id 		=  $data['id'];
				$id_surv 	  =  $data['id_surv'];
				$cod_surv  =  $data['cod_surv'];
				$surv_name  =  $data['surv_name'];
				$surv_desc 	  =  $data['surv_desc'];
				$id_ques_start 	  =  $data['id_ques_start'];
				$id_user_ds  =  $data['id_user_ds'];
				$user_ds_mem 	  =  $data['user_ds_mem'];
				$version_nbr	  =  $data['version_nbr'];
				$id_user_version  =  $data['id_user_version'];
				
				$sqlset = $sqlset . "`id_surv` = '$id_surv',";
				$sqlset = $sqlset . "`cod_surv` = '$cod_surv',";
				$sqlset = $sqlset . "`surv_name` = '$surv_name',";
				$sqlset = $sqlset . "`surv_desc` = '$surv_desc',";
				$sqlset = $sqlset . "`id_ques_start` = '$id_ques_start',";
				$sqlset = $sqlset . "`id_user_ds` = '$id_user_ds',";
				$sqlset = $sqlset . "`user_ds_mem` = '$user_ds_mem',";
				$sqlset = $sqlset . "`version_nbr` = '$version_nbr',";	
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE `test_surv` SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}

		public function deletetestsurv($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE `test_surv` SET flg_visible =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getalltest_surv() {
			$stmt = $this->conn->query("SELECT * FROM `test_surv` WHERE flg_visible = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function test_surv_tag($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_surv_tag 	  =  $data['id_surv_tag'];
			$id_surv  =  $data['id_surv'];
			$id_tag  =  $data['id_tag'];
			$flg_surv_tag_alt 	  =  $data['flg_surv_tag_alt'];
			$id_user_ds 	  =  $data['id_user_ds'];
			$user_ds_mem  =  $data['user_ds_mem'];
			$version_nbr	  =  $data['version_nbr'];
			$id_user_version  =  $data['id_user_version'];
			$version_date  =  date('Y-m-d H:i:s');
					
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `test_surv_tag` (id_surv_tag, id_surv, id_tag, flg_surv_tag_alt, id_user_ds, user_ds_mem, flg_active,version_nbr, id_user_version, version_date) values('$id_surv_tag','$id_surv', '$id_tag','$flg_surv_tag_alt','$id_user_ds','$user_ds_mem', 1,'$version_nbr','$id_user_version','$version_date')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function edittest_surv_tag($data) {
				$response = array();
				// update query
				$id 		=  $data['id'];
				$id_surv_tag 	  =  $data['id_surv_tag'];
				$id_surv  =  $data['id_surv'];
				$id_tag  =  $data['id_tag'];
				$flg_surv_tag_alt 	  =  $data['flg_surv_tag_alt'];
				$id_user_ds 	  =  $data['id_user_ds'];
				$user_ds_mem  =  $data['user_ds_mem'];
				$version_nbr	  =  $data['version_nbr'];
				$id_user_version  =  $data['id_user_version'];
				
				$sqlset = $sqlset . "`id_surv_tag` = '$id_surv_tag',";
				$sqlset = $sqlset . "`id_surv` = '$id_surv',";
				$sqlset = $sqlset . "`id_tag` = '$id_tag',";
				$sqlset = $sqlset . "`flg_surv_tag_alt` = '$flg_surv_tag_alt',";
				$sqlset = $sqlset . "`id_user_ds` = '$id_user_ds',";
				$sqlset = $sqlset . "`user_ds_mem` = '$user_ds_mem',";
				$sqlset = $sqlset . "`version_nbr` = '$version_nbr',";	
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE `test_surv_tag` SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletetest_surv_tag($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE `test_surv_tag` SET flg_visible =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getalltest_surv_tag() {
			$stmt = $this->conn->query("SELECT * FROM `test_surv_tag` WHERE flg_visible = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function test_tag($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_tag 	  =  $data['id_tag'];
			$cod_tag  =  $data['cod_tag'];
			$tag_name  =  $data['tag_name'];
			$tag_desc 	  =  $data['tag_desc'];
			$flg_tag_form 	  =  $data['flg_tag_form'];
			$id_user_ds  =  $data['id_user_ds'];
			$user_ds_mem  =  $data['user_ds_mem'];
			$version_nbr	  =  $data['version_nbr'];
			$id_user_version  =  $data['id_user_version'];
			$version_date  =  date('Y-m-d H:i:s');
					
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `test_tag` (id_tag, cod_tag, tag_name, tag_desc, flg_tag_form, id_user_ds, user_ds_mem, flg_active,version_nbr, id_user_version, version_date) values('$id_tag','$cod_tag', '$tag_name','$tag_desc','$flg_tag_form', '$id_user_ds','$user_ds_mem', 1,'$version_nbr','$id_user_version','$version_date')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function edittest_tag($data) {
				$response = array();
				// update query
				$id 		=  $data['id'];
				$id_tag 	  =  $data['id_tag'];
				$cod_tag  =  $data['cod_tag'];
				$tag_name  =  $data['tag_name'];
				$tag_desc 	  =  $data['tag_desc'];
				$flg_tag_form 	  =  $data['flg_tag_form'];
				$id_user_ds  =  $data['id_user_ds'];
				$user_ds_mem  =  $data['user_ds_mem'];
				$version_nbr	  =  $data['version_nbr'];
				$id_user_version  =  $data['id_user_version'];
				
				$sqlset = $sqlset . "`id_tag` = '$id_tag',";
				$sqlset = $sqlset . "`cod_tag` = '$cod_tag',";
				$sqlset = $sqlset . "`tag_name` = '$tag_name',";
				$sqlset = $sqlset . "`tag_desc` = '$tag_desc',";
				$sqlset = $sqlset . "`flg_tag_form` = '$flg_tag_form',";
				$sqlset = $sqlset . "`id_user_ds` = '$id_user_ds',";
				$sqlset = $sqlset . "`user_ds_mem` = '$user_ds_mem',";
				$sqlset = $sqlset . "`version_nbr` = '$version_nbr',";	
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE `test_tag` SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletetest_tag($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE `test_tag` SET flg_visible =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getalltest_tag() {
			$stmt = $this->conn->query("SELECT * FROM `test_tag` WHERE flg_visible = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function test_typeques($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_typeques 	  =  $data['id_typeques'];
			$code_typeques  =  $data['code_typeques'];
			$typeques_name  =  $data['typeques_name'];
			$typeques_desc 	  =  $data['typeques_desc'];
			$id_user_ds  =  $data['id_user_ds'];
			$user_ds_mem  =  $data['user_ds_mem'];
			$version_nbr	  =  $data['version_nbr'];
			$id_user_version  =  $data['id_user_version'];
			$version_date  =  date('Y-m-d H:i:s');
					
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `test_typeques` (id_typeques, code_typeques, typeques_name, typeques_desc, id_user_ds, user_ds_mem, flg_active,version_nbr, id_user_version, version_date) values('$id_typeques','$code_typeques', '$typeques_name','$typeques_desc', '$id_user_ds','$user_ds_mem', 1,'$version_nbr','$id_user_version','$version_date')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function edittest_typeques($data) {
				$response = array();
				// update query
				$id_typeques 	  =  $data['id_typeques'];
				$code_typeques  =  $data['code_typeques'];
				$typeques_name  =  $data['typeques_name'];
				$typeques_desc 	  =  $data['typeques_desc'];
				$id_user_ds  =  $data['id_user_ds'];
				$user_ds_mem  =  $data['user_ds_mem'];
				$version_nbr	  =  $data['version_nbr'];
				$id_user_version  =  $data['id_user_version'];
				
				$sqlset = $sqlset . "`code_typeques` = '$code_typeques',";
				$sqlset = $sqlset . "`typeques_name` = '$typeques_name',";
				$sqlset = $sqlset . "`typeques_desc` = '$typeques_desc',";
				$sqlset = $sqlset . "`id_user_ds` = '$id_user_ds',";
				$sqlset = $sqlset . "`user_ds_mem` = '$user_ds_mem',";
				$sqlset = $sqlset . "`version_nbr` = '$version_nbr',";	
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE `test_typeques` SET ".$sqlset." WHERE id_typeques = '$id_typeques'");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletetest_typeques($data){
			$id_typeques  = $data['id_typeques'];
			$stmt = $this->conn->prepare("UPDATE `test_typeques` SET flg_visible =1 WHERE id_typeques = '$id_typeques'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close(); 
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getalltest_typeques() {
			$stmt = $this->conn->query("SELECT * FROM `test_typeques` WHERE flg_visible = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function test_user($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_user 	  =  $data['id_user'];
			$user_firstname  =  $data['user_firstname'];
			$user_lastname  =  $data['user_lastname'];
			$user_login 	  =  $data['user_login'];
			$user_password 	  =  $data['user_password'];
			$user_create_date 	  =  $data['user_create_date'];
			$id_user_ds  =  $data['id_user_ds'];
			$user_ds_mem  =  $data['user_ds_mem'];
			$version_nbr	  =  $data['version_nbr'];
			$id_user_version  =  $data['id_user_version'];
			$version_date  =  date('Y-m-d H:i:s');
					
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `test_user` (id_user, user_firstname, user_lastname, user_login, user_password, user_create_date, id_user_ds, user_ds_mem, flg_active,version_nbr, id_user_version, version_date) values('$id_user','$user_firstname', '$user_lastname','$user_login', '$user_password', '$user_create_date','$id_user_ds','$user_ds_mem', 1,'$version_nbr','$id_user_version','$version_date')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function edittest_user($data) {
				$response = array();
				// update query
				$id 		=  $data['id'];
				$id_user 	  =  $data['id_user'];
				$user_firstname  =  $data['user_firstname'];
				$user_lastname  =  $data['user_lastname'];
				$user_login 	  =  $data['user_login'];
				$user_password 	  =  $data['user_password'];
				$user_create_date 	  =  $data['user_create_date'];
				$id_user_ds  =  $data['id_user_ds'];
				$user_ds_mem  =  $data['user_ds_mem'];
				$version_nbr	  =  $data['version_nbr'];
				$id_user_version  =  $data['id_user_version'];
				
				$sqlset = $sqlset . "`id_user` = '$id_user',";
				$sqlset = $sqlset . "`user_firstname` = '$user_firstname',";
				$sqlset = $sqlset . "`user_lastname` = '$user_lastname',";
				$sqlset = $sqlset . "`user_login` = '$user_login',";
				$sqlset = $sqlset . "`user_password` = '$user_password',";
				$sqlset = $sqlset . "`user_create_date` = '$user_create_date',";
				$sqlset = $sqlset . "`id_user_ds` = '$id_user_ds',";
				$sqlset = $sqlset . "`user_ds_mem` = '$user_ds_mem',";
				$sqlset = $sqlset . "`version_nbr` = '$version_nbr',";	
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE `test_user` SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletetest_user($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE `test_user` SET flg_visible =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getalltest_user() {
			$stmt = $this->conn->query("SELECT * FROM `test_user` WHERE flg_visible = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function test_user_ans($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_user_ans 	  =  $data['id_user_ans'];
			$id_user_ques  =  $data['id_user_ques'];
			$user_ans_order  =  $data['user_ans_order'];
			$id_ans 	  =  $data['id_ans'];
			$id_user_ds  =  $data['id_user_ds'];
			$user_ds_mem  =  $data['user_ds_mem'];
			$version_nbr	  =  $data['version_nbr'];
			$id_user_version  =  $data['id_user_version'];
			$version_date  =  date('Y-m-d H:i:s');
					
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `test_user_ans` (id_user_ans, id_user_ques, user_ans_order, id_ans, id_user_ds, user_ds_mem, flg_active,version_nbr, id_user_version, version_date) values('$id_user_ans','$id_user_ques', '$user_ans_order','$id_ans','$id_user_ds','$user_ds_mem', 1,'$version_nbr','$id_user_version','$version_date')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function edittest_user_ans($data) {
				$response = array();
				// update query
				$id 		=  $data['id'];
				$id_user_ans 	  =  $data['id_user_ans'];
				$id_user_ques  =  $data['id_user_ques'];
				$user_ans_order  =  $data['user_ans_order'];
				$id_ans 	  =  $data['id_ans'];
				$id_user_ds  =  $data['id_user_ds'];
				$user_ds_mem  =  $data['user_ds_mem'];
				$version_nbr	  =  $data['version_nbr'];
				$id_user_version  =  $data['id_user_version'];
				
				$sqlset = $sqlset . "`id_user_ans` = '$id_user_ans',";
				$sqlset = $sqlset . "`id_user_ques` = '$id_user_ques',";
				$sqlset = $sqlset . "`user_ans_order` = '$user_ans_order',";
				$sqlset = $sqlset . "`id_ans` = '$id_ans',";
				$sqlset = $sqlset . "`id_user_ds` = '$id_user_ds',";
				$sqlset = $sqlset . "`user_ds_mem` = '$user_ds_mem',";
				$sqlset = $sqlset . "`version_nbr` = '$version_nbr',";	
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE `test_user_ans` SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletetest_user_ans($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE `test_user_ans` SET flg_visible =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getalltest_user_ans() {
			$stmt = $this->conn->query("SELECT * FROM `test_user_ans` WHERE flg_visible = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function test_user_surv($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_user_surv 	  =  $data['id_user_surv'];
			$id_user  =  $data['id_user'];
			$id_surv  =  $data['id_surv'];
			$user_surv_date 	  =  $data['user_surv_date'];
			$id_user_ds  =  $data['id_user_ds'];
			$user_ds_mem  =  $data['user_ds_mem'];
			$version_nbr	  =  $data['version_nbr'];
			$id_user_version  =  $data['id_user_version'];
			$version_date  =  date('Y-m-d H:i:s');
					
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `test_user_surv` (id_user_surv, id_user, id_surv, user_surv_date, id_user_ds, user_ds_mem, flg_active, version_nbr, id_user_version, version_date) values('$id_user_surv','$id_user', '$id_surv','$user_surv_date','$id_user_ds','$user_ds_mem', 1,'$version_nbr','$id_user_version','$version_date')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		public function edittest_user_surv($data) {
				$response = array();
				// update query
				$id 		=  $data['id'];
				$id_user_surv 	  =  $data['id_user_surv'];
				$id_user  =  $data['id_user'];
				$id_surv  =  $data['id_surv'];
				$user_surv_date 	  =  $data['user_surv_date'];
				$id_user_ds  =  $data['id_user_ds'];
				$user_ds_mem  =  $data['user_ds_mem'];
				$version_nbr	  =  $data['version_nbr'];
				$id_user_version  =  $data['id_user_version'];
				$version_date  =  date('Y-m-d H:i:s');
				
				$sqlset = $sqlset . "`id_user_surv` = '$id_user_surv',";
				$sqlset = $sqlset . "`id_user` = '$id_user',";
				$sqlset = $sqlset . "`id_surv` = '$id_surv',";
				$sqlset = $sqlset . "`user_surv_date` = '$user_surv_date',";
				$sqlset = $sqlset . "`id_user_ds` = '$id_user_ds',";
				$sqlset = $sqlset . "`user_ds_mem` = '$user_ds_mem',";
				$sqlset = $sqlset . "`version_nbr` = '$version_nbr',";	
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE `test_user_surv` SET ".$sqlset." WHERE id = $id");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
			return $response;
		}
		
		public function deletetest_user_surv($data){
			$id  = $data['id'];
			$stmt = $this->conn->prepare("UPDATE `test_user_surv` SET flg_visible =1 WHERE id = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return PHARMA_UPDATED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return PHARMA_UPDATED_FAILED;
			}
		}
		
		public function getalltest_user_surv() {
			$stmt = $this->conn->query("SELECT * FROM `test_user_surv` WHERE flg_visible = 0 ");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$pharmacy = $stmt; 
				return $pharmacy;
			}
		}
		
		public function test_proud($data) {
			require_once 'PassHash.php';
			$response = array();
			// First check if user already existed in db
			$id_prod 	  =  $data['id_prod'];
			$cod_prod  =  $data['cod_prod'];
			$id_labo  =  $data['id_labo'];
			$id_range 	  =  $data['id_range'];
			$prod_name  =  $data['prod_name'];
			$id_form  =  $data['id_form'];
			$id_unit 	  =  $data['id_unit'];
			$id_prodstatus  =  $data['id_prodstatus'];
			$prod_mem  =  $data['prod_mem'];
			$id_user_ds  =  $data['id_user_ds'];
			$user_ds_mem  =  $data['user_ds_mem'];
			$version_nbr	  =  $data['version_nbr'];
			$id_user_version  =  $data['id_user_version'];
			$version_date  =  date('Y-m-d H:i:s');
					
			
			if (!$this->isPharmaExists($email)) { 
				// insert query
				$sql = "INSERT INTO  `test_prod` (id_prod, cod_prod, id_labo, id_range, prod_name, id_form, id_unit, id_prodstatus, prod_mem, id_user_ds, user_ds_mem, flg_active, version_nbr, id_user_version, version_date) values('$id_prod','$cod_prod', '$id_labo','$id_range','$prod_name','$id_form', '$id_unit','id_prodstatus', '$prod_mem',  '$id_user_ds', '$user_ds_mem',1,'$version_nbr','$id_user_version','$version_date')";
				$stmt = $this->conn->prepare($sql);
				//$stmt->bind_param($name,$email,$password,$api_key, 0);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) {
					// User successfully inserted
					return USER_CREATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_CREATE_FAILED;
				}
			} else {
				// User with same email already existed in the db 
				return USER_ALREADY_EXISTED;
			}
			return $response;
		}
		
		
		public function testquestionadmin($data) {
			$response = array();
			// First check if user already existed in db
			$question_name 	 =  $data['question_name'];
			$question 	 	  =  $data['question'];
			$question_tag 	  =  $data['tag'];
			$question_description =  $data['question_description'];
			$survayid  	  	  =  $data['surveyid'];
			$questiontypeid  	=  $data['questiontypeid'];
			$next_question 	 =  $data['nextquestionid'];
			$version_date  	  =  date('Y-m-d H:i:s');
			$answer            =  $data['answer'];
			
			// insert query
			$sql = "INSERT INTO  test_ques (id_surv, ques_name,id_typeques, id_ques_next, ques_value, ques_desc,version_date) 
					values('$survayid','$question_name','$questiontypeid','$next_question','$question','$question_description','$version_date') ";
			$stmt = $this->conn->prepare($sql);
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$stmt->execute();
				$lastquestionid = $this->conn->insert_id;
				$stmt->close();
				$singlequestiontag = explode(',',$question_tag);
				foreach($singlequestiontag as $tag){
					$tagid = $this->checktag($tag);
					$sql3 = "INSERT INTO test_ques_tag (id_ques, id_tag,version_date)
							 values('$lastquestionid','$tagid','$version_date')";
					$stmt3 = $this->conn->prepare($sql3);
					if ($stmt3 === FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt3->execute();
						$stmt3->close();
					}
				}
				
			   foreach($answer as $ans){
					$answerorder 	   =  $ans['order'];
					$answervalue 	   =  $ans['value'];
					$anstag 	  	    =  $ans['tag'];
					$answerdescription =  $ans['description'];
					$correctanswers    =  $ans['correct'];
					$nextquestion      =  $ans['nextquestion'];  
					
					$sql2 = "INSERT INTO test_ans (id_ques,ans_order, ans_value, ans_desc, id_ques_ans_next, id_prod_ans,version_date) values('$lastquestionid','$answerorder', '$answervalue', '$answerdescription', '$nextquestion', '$correctanswers','$version_date')";
					$stmt2 = $this->conn->prepare($sql2);
					if ($stmt2 === FALSE){
						die($this->conn->error);
					} else  {
						$stmt2->execute();
						$lastansid = $this->conn->insert_id;
						$stmt2->close();
						$singleanstag = explode(',',$anstag);
						foreach($singleanstag as $tag){
							$tagid1 = $this->checktag($tag);
							$sql3 = "INSERT INTO test_ans_tag (id_ans,id_tag,version_date) 
									values('$lastansid','$tagid1','$version_date')";
							$stmt3 = $this->conn->prepare($sql3);
							if ($stmt3 === FALSE){
								die($this->conn->error);
							} else  {
								$result = $stmt3->execute();
								$stmt3->close();
							}
					   }
					}
			   }
			   
			   return QUESTION_SUCCESSFULLY_CREATED;
			}
		}
				
		public function edittestquestionadmin($data) {
			$response = array();
			// First check if user already existed in db
			$id 	 		    =  $data['id'];
			$question_name 	 =  $data['question_name'];
			$question 	 	  =  $data['question'];
			$question_tag 	  =  $data['tag'];
			$question_description =  $data['question_description'];
			$survayid  	  	  =  $data['surveyid'];
			$questiontypeid  	=  $data['questiontypeid'];
			$next_question 	 =  $data['nextquestionid'];
			$version_date  	  =  date('Y-m-d H:i:s');
			$answer            =  $data['answer']; 
			
			// insert query
			$sql = "UPDATE  test_ques SET id_surv='$survayid', ques_name='$question_name', id_typeques='$questiontypeid', id_ques_next='$next_question', ques_value='$question', ques_desc='$question_description',version_date='$version_date' WHERE id_ques= '$id'";
			$stmt = $this->conn->prepare($sql);
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$stmt->execute();
				$lastquestionid = $id;
				$stmt->close();
				$singlequestiontag = explode(',',$question_tag);
				
				$stmtquestg = $this->conn->prepare("DELETE FROM test_ques_tag WHERE id_ques = '$lastquestionid'");
				$stmtquestg->execute();
				$stmtquestg->close();
				foreach($singlequestiontag as $tag){
					$tagid = $this->checktag($tag);
					$sql3 = "INSERT INTO test_ques_tag (id_ques, id_tag,version_date)
							 values('$lastquestionid','$tagid','$version_date')";
					$stmt3 = $this->conn->prepare($sql3);
					if ($stmt3 === FALSE){
						die($this->conn->error); 
					} else  {
						$result = $stmt3->execute();
						$stmt3->close();
					}
				}
				
			   foreach($answer as $ans){
				    $ansid 	  		 =  $ans['id'];
					$answerorder 	   =  $ans['order'];
					$answervalue 	   =  $ans['value'];
					$anstag 	  	   =  $ans['tag'];
					$answerdescription =  $ans['description'];
					$correctanswers    =  $ans['correct'];
					$nextquestion      =  $ans['nextquestion'];  
					
					$sql2 = "UPDATE test_ans SET id_ques='$lastquestionid', ans_order='$answerorder', ans_value='$answervalue', ans_desc='$answerdescription', id_ques_ans_next='$nextquestion', id_prod_ans='$correctanswers', version_date='$version_date' WHERE id_ans='$ansid'";
					$stmt2 = $this->conn->prepare($sql2);
					if ($stmt2 === FALSE){
						die($this->conn->error);
					} else  {
						$stmt2->execute();
						$lastansid = $ansid;
						$stmt2->close();
						$singleanstag = explode(',',$anstag);
						$stmtansstg = $this->conn->prepare("DELETE FROM test_ans_tag WHERE id_ans = '$lastansid'");
						$stmtansstg->execute();
						$stmtansstg->close();
						foreach($singleanstag as $tag){
							$tagid1 = $this->checktag($tag);
							$sql3 = "INSERT INTO test_ans_tag (id_ans,id_tag,version_date) 
									values('$lastansid','$tagid1','$version_date')";
							$stmt3 = $this->conn->prepare($sql3);
							if ($stmt3 === FALSE){
								die($this->conn->error);
							} else  {
								$result = $stmt3->execute();
								$stmt3->close();
							}
					   }
					}
			   }
			   
			   return QUESTION_SUCCESSFULLY_EDITED;
			}
		}	
				
				
/*				
				// Check for successful insertion
				$sql5 = "SELECT test_ques.*, test_ques_tag.*, test_ans.*,test_ans_tag.*  FROM `test_ques` 
						LEFT JOIN test_ques_tag ON test_ques.id_ques = test_ques_tag.id_ques_tag 
						LEFT JOIN test_ans ON test_ans.id_ans =  test_ques_tag.id_ques_tag 
						LEFT JOIN test_ans_tag ON test_ans_tag.id_ans_tag = test_ques_tag.id_ques_tag";
				$stmt4 = $this->conn->query($sql5);
				if ($stmt4 === FALSE){
					die($this->conn->error);
				} else  {
					$details = $stmt4; 
					return $details;
				}
*/		
        
		
		function getquestionlist(){
				$sql = "SELECT test_ques.* FROM test_ques WHERE flg_ques = 0";
				$stmt = $this->conn->query($sql);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
				   $response["question"] = array();
					$i = 0;
					while ($question = $stmt->fetch_array(MYSQLI_ASSOC)) {
						$questionid = $question['id_ques'];
						$que = array();
						$que["ques_name"]   	= $question["ques_name"];
						$que["ques_value"]  	= $question["ques_value"]; 
						$que["ques_desc"]  		= $question["ques_desc"];
						$que["id_ques"]     	= $question["id_ques"];
						$que["id_surv"]     	= $question["id_surv"];
						$que["id_typeques"]     = $question["id_typeques"];
						$que["id_ques_next"]    = $question["id_ques_next"];							
						
						array_push($response["question"], $que);
						$sqlqtag = "SELECT test_tag.tag_name,test_ques_tag.id_tag FROM test_ques_tag 
									JOIN test_tag ON test_ques_tag.id_tag = test_tag.id_tag 
									WHERE test_ques_tag.id_ques = '$questionid'";
						$stmtqtag = $this->conn->query($sqlqtag);
						$response["question"][$i]["tag"] = array();
						while($qtag = $stmtqtag->fetch_array(MYSQLI_ASSOC)) {
							//print_r($qtag);
							$questag = array();
							$questag['tagname'] = $qtag['tag_name'];
							$questag['tagid']   = $qtag['id_tag'];
							array_push($response["question"][$i]["tag"], $questag);
						}
						
						$sqla = "SELECT test_ans.* FROM test_ans  WHERE test_ans.id_ques = '$questionid'";
						$stmta = $this->conn->query($sqla);
						$k = 0;
						$response["question"][$i]["answer"] = array();
						while($answer = $stmta->fetch_array(MYSQLI_ASSOC)) {
							$answerid = $answer['id_ans'];
							$ans = array();
							$ans["id_ans"]   = $answer["id_ans"]; 
							$ans["id_ques"]   = $answer["id_ques"]; 
							$ans["ans_order"]   = $answer["ans_order"]; 
							$ans["id_ques_ans_next"]   = $answer["id_ques_ans_next"];
							$ans["ans_value"]   = $answer["ans_value"]; 
							$ans["ans_desc"]  = $answer["ans_desc"];
							$ans["id_prod_ans"]  = $answer["id_prod_ans"];
							array_push($response["question"][$i]["answer"], $ans);
							$sqlatag = "SELECT test_tag.tag_name,test_ans_tag.id_tag 
							            FROM test_ans_tag 
										JOIN test_tag ON test_ans_tag.id_tag = test_tag.id_tag 
										WHERE test_ans_tag.id_ans = '$answerid'";
							$stmtatag = $this->conn->query($sqlatag);
							$response["question"][$i]["answer"][$k]['tag'] = array();
							while($atag = $stmtatag->fetch_array(MYSQLI_ASSOC)) {
								//print_r($atag);
								$anstag = array();
								$anstag['tagname'] = $atag['tag_name'];
								$anstag['tagid']   = $atag['id_tag'];
								array_push($response["question"][$i]["answer"][$k]['tag'], $anstag);
							}
							$k++;
						}
						
					  $i++;
					}
					
					return $response;
				}		
		 }
		 
		 
		public function deletequestion($data){
			$id  = $data['id_ques'];
			
			$stmt = $this->conn->query("SELECT * from `test_ques` WHERE `id_ques` = $id");
			   if ($stmt == FALSE){
				die($this->conn->error);
			   } else{
				$num_rows = $stmt->num_rows;
				if($num_rows > 0){
				 $result = $stmt->fetch_array(MYSQLI_ASSOC);
				 if($result['flg_ques'] == 1){
				  return QUES_ALREADY_DELETED;
				  exit;  
				 }
				}else{
				 return QUES_DOESNOT_EXIST;
				 exit;  
				}
			   }			
			
			$stmt = $this->conn->prepare("UPDATE `test_ques` SET flg_ques = 1 WHERE id_ques = '$id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return QUES_DELETED_SUCCESSFULLY;
			} else {
				// Failed to create user
				return QUES_DELETED_FAILED;
			}
		}
		 
			
		
		
			
			
		/** 
		 * Checking for duplicate pharma by email address
		 * @param String $email email to check in db
		 * @return boolean
		 */
		public function isPharmaExists($email) {
			$stmt = $this->conn->prepare("SELECT id from pharmacy WHERE `pharmacy_email` = ?");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$stmt->bind_param("s", $email);
				$stmt->execute();
				$stmt->store_result();
				$num_rows = $stmt->num_rows;
				$stmt->close();
				return $num_rows > 0;
			}
		} 
		
		function survey($surv_name){
			$result = $this->conn->prepare("SELECT id from test_surv WHERE `surv_name` = '$surv_name'");
			while ($rows = $result->fetch_array(MYSQLI_ASSOC)) {
				$surveytag["id"] = $rows["id"];
			}
			return $surveytag;
		}
		
		
		public function checktag($tag){
			$stmt = $this->conn->query("SELECT id_tag from test_tag WHERE `tag_name` = '$tag'");
			if ($stmt == FALSE){
				die($this->conn->error);
			} else{
				$num_rows = $stmt->num_rows;
				if($num_rows > 0){
					$result = $stmt->fetch_array(MYSQLI_ASSOC);
					return $result['id_tag'];
				}else{
					$stmt = $this->conn->prepare("INSERT INTO test_tag (tag_name) values('$st')");
					$fire = $stmt->execute();
					$stmt->close();
					$id = $this->conn->insert_id;
					return $id;
				}
			}
		}
		
		public function getsearch($type,$page,$search){
			switch($type){
				case 'product':
					if(!empty($page)){
						$u= 10;
						$a= $page * $u;
						$b= $a - $u;
						$c= $b.','.$a;
					}
					$sql = "SELECT product.*,product_range_price.* 
							FROM product 
							JOIN product_range_price ON product.id_product = product_range_price.range_price_id ";
					
					if($search != ''){
						$sql .= " WHERE ( (product.product_name LIKE '%$search%') || ( product.product_indication LIKE '%$search%') || (product.product_posology LIKE '%$search%') ) ";
					}
					$sql  .= " LIMIT $c";
					
					$stmt = $this->conn->query($sql);
					$num_rows = $stmt->num_rows;
					if($num_rows > 0){
						if ($stmt === FALSE){
							die($this->conn->error);
						} else  {
 							$response["error"] = false;
							$response["result"] = array();
							$i = 1;
							$id_user_search = $this->searchinfo($type,$search);
							// looping through result and preparing tasks array
							while ($result = $stmt->fetch_array(MYSQLI_ASSOC)) {
								$tmp = array();
								$tmp["id"]      	   = $result["id"]; 
								$tmp["product_name"]   = $result["product_name"];
								$tmp["product_indication"] = $result["product_indication"];
								$tmp["product_posology"] = $result["product_posology"];
								$tmp["range_price_text"] = $result["range_price_text"];
								$tmp["id_laboratory"] = $result["id_laboratory"];
							  
								array_push($response["result"], $tmp);
								$rowtext = json_encode($tmp);
								$order = $i;
								$id_asset = md5($this->generateRandomString($length = 5)); 
								$i++; 
								$sql1 ="INSERT INTO user_search_assets (asset_order, asset_text, id_user_search,id_asset)
										values('$order','$rowtext','$id_user_search','$id_asset')";
								$stmt1 = $this->conn->prepare($sql1);
								if ($stmt1 === FALSE){
									die($this->conn->error);
								} else  {
									$stmt1->execute();
									$stmt1->close();
								}
							}
							echoRespnse(200, $response);
						}
					}else {
						$response["error"] = true;
						$response["message"] = "Oops! row doesn't exist";
						// echo json response 
						echoRespnse(201, $response);
					}
			break;
			}
		}
		
		public function searchinfo($type,$search){ 
			
			$id_search = md5($this->generateRandomString($length = 8)); 
			$search_date = date('Y-m-d H:i:s');
			$id_user = $_SESSION['user']['id'];
			
			$sql = "INSERT INTO search (search_mem, search_type, search_date, id_search) values('$search','$type','$search_date','$id_search')";
			$stmt = $this->conn->prepare($sql);
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$stmt->execute();
				$stmt->close();
			}
			$sql1 = "INSERT INTO user_search (id_search,id_user,user_search_date,id_user_search) values('$id_search','$id_user','$search_date','$search')";
			$stmt1= $this->conn->prepare($sql1);
			if ($stmt1 === FALSE){
				die($this->conn->error);
			} else  {
				$stmt1->execute();
				$stmt1->close();
				return $id_search;
			} 
			
		}


		public function list_survey() {
			$stmt = $this->conn->query("SELECT  * FROM test_surv
										WHERE flg_visible = 1");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$test = $stmt; 
				return $test;
			}
		}
		
		
		public function getSurveyById($id){
			
			$stmt = $this->conn->query("SELECT  * FROM test_surv
										WHERE id_surv = '$id' AND flg_visible = 1");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$test = $stmt; 
				return $test;
			}
		}

		
		public function list_testsurvey($data) {
			$surv_id = $data['survey_id'];
			$stmt = $this->conn->query("SELECT  a.ques_name, a.id_typeques, a.id_ques_next ,a.ques_value, a.ques_desc,  b.ques_name AS 'nx_ques_name', b.id_typeques AS 'nx_id_typeques', b.id_ques_next AS 'nx_id_ques_next' ,b.ques_value AS 'nx_ques_value', b.ques_desc AS 'nx_ques_desc'
										FROM test_ques  a 
										JOIN test_ques  b ON a.id_ques_next = b.id_ques
										WHERE a.id_surv = '$surv_id'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$test = $stmt; 
				return $test;
			}
		}
		
		public function listtest_ans($data) {
			$id_ques = $data['id_ques'];
			$stmt = $this->conn->query("SELECT   b.ans_order, b.ans_value, b.ans_desc ,b.id_prod_ans, a.ques_name, a.id_typeques, a.id_ques_next ,a.ques_value, a.ques_desc
										FROM test_ans  b 
										JOIN test_ques  a ON  b.id_ques_ans_next = a.id_ques
										WHERE b.id_ques = '$id_ques'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$test = $stmt; 
				return $test;
			}
		}
		
		public function addtestsurvey($data) {
				// update query
				$id_surv  = md5($this->generateRandomString($length = 8));
				$cod_surv  = $data['cod_surv'];
				$surv_name = $data['surv_name']; 
				$surv_desc = $data['surv_desc'];
				$id_ques_start = $data['id_ques_start'];
				$id_user_ds = $data['id_user_ds'];
				$user_ds_mem = $data['user_ds_mem'];
				$id_user_version =$_SESSION['user']['id'];
				$date = date('Y-m-d H:i:s');
								
				$stmt = $this->conn->prepare("INSERT INTO test_surv (id_surv, cod_surv, surv_name, surv_desc, id_ques_start, id_user_ds, user_ds_mem, id_user_version,version_date) values('$id_surv','$cod_surv','$surv_name','$surv_desc','$id_ques_start','$id_user_ds','$user_ds_mem','$id_user_version','$date')");
		      	
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				
				// Check for successful insertion
				if ($result) { 
					// User successfully inserted
					return TESTSERVEY_ADDED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return TESTSERVEY_ADDED_FAILED;
				}
		}
		
		public function edittestsurvey($data) {
				// update query
				$id_surv  = $data['id_surv'];
				$cod_surv  = $data['cod_surv'];
				$surv_name = $data['surv_name']; 
				$surv_desc = $data['surv_desc'];
				$id_ques_start = $data['id_ques_start'];
				$id_user_ds = $data['id_user_ds'];
				$user_ds_mem = $data['user_ds_mem'];
				$version = $this->updateversion('test_surv','id_surv',$id_surv); 
				$id_user_version =$_SESSION['user']['id'];
				
				$sqlset = $sqlset . "`cod_surv` = '$cod_surv',";
				$sqlset = $sqlset . "`surv_name` = '$surv_name',";
				$sqlset = $sqlset . "`surv_desc` = '$surv_desc',";
				$sqlset = $sqlset . "`id_ques_start` = '$id_ques_start',";
				$sqlset = $sqlset . "`id_user_ds` = '$id_user_ds',";
				$sqlset = $sqlset . "`user_ds_mem` = '$user_ds_mem',";
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version'";
				
				$stmt = $this->conn->prepare("UPDATE test_surv SET ".$sqlset." WHERE id_surv = '$id_surv'");
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) { 
					// User successfully inserted
					return USER_UPDATED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return USER_UPDATED_FAILED;
				}
		}
		
		public function deletetestsurvey($data){
			$id_surv  = $data['id_surv'];
			$this->redeletedcheck('test_surv','flg_visible','id_surv',$id_surv);
			$stmt = $this->conn->prepare("UPDATE test_surv SET flg_visible =0 WHERE id_surv = '$id_surv'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return TESTSURVEY_DELETED_SUCCESSFULLY; 
			} else {
				// Failed to create user
				return TESTSURVEY_DELETED_FAILED;
			}
		}
		
		
		
		
		public function addhistory($data) {
				// update query
				$id_surv  = $data['id_surv'];
				$history_date  = $data['history_date'];
				$id_user = $data['id_user']; 
				$survey_key =  md5($this->generateRandomString($length = 6));
				$id_ques_start = $data['id_ques_start'];
				$id_history = md5($this->generateRandomString($length = 8));
				$user_ds_mem = $data['user_ds_mem'];
				$id_user_version =$_SESSION['user']['id'];
				$date = date('Y-m-d H:i:s');
				
				$sql = "INSERT INTO history (id_surv, history_date, id_user, survey_key,  id_history, id_user_version,version_date) 		values('$id_surv','$history_date','$id_user','$survey_key','$id_history','$id_user_version','$date')";
				print_r($sql);
				$stmt = $this->conn->prepare($sql);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt;
					$stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) { 
					// User successfully inserted
					return HISTORY_ADDED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return HISTORY_ADDED_FAILED;
				}
		} 
		
		public function edithistory($data) {
				// update query
				$id_surv  = $data['id_surv'];
				$history_date  = $data['history_date'];
				$id_user = $data['id_user']; 
				$id_user_version =$_SESSION['user']['id'];
				$this->updateversion('history','id_surv',$id_surv); 
				
				$previoushistory_date = $this->getcolumnvalue('history','history_date','id_surv',$id_surv); 
				$previousid_user = $this->getcolumnvalue('history','id_user','id_surv',$id_surv);
				
				if(isset($history_date) && ($previoushistory_date != $history_date)){
					$sqlset = $sqlset . "`history_date` = '$history_date',";
				}
				if(isset($id_user) && ($previousid_user != $id_user)){
					$sqlset = $sqlset . "`id_user` = '$id_user',";
				}
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version',";
				$sqlset = rtrim($sqlset, ',');
				if ($sqlset!='' ){
					$stmt = $this->conn->prepare("UPDATE history SET ".$sqlset." WHERE id_surv = '$id_surv'");
						
					if ($stmt === FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt->execute();
						$stmt->close();
					}
					// Check for successful insertion
					if ($result) { 
						// User successfully inserted
						return USER_UPDATED_SUCCESSFULLY;
					} else {
						// Failed to create user
						return USER_UPDATED_FAILED;
					}
				}
		}
		
		public function addhistoryproduct($data) {
				// update query
				$id_product  = $data['id_product'];
				$product_order  = $data['product_order'];
				$id_history =  md5($this->generateRandomString($length = 8));
				$id_user_version =$_SESSION['user']['id'];
				$date = date('Y-m-d H:i:s');
				
				$sql = "INSERT INTO history_product (id_product, product_order, id_history, id_user_version,version_date) 		values('$id_product','$product_order','$id_history','$id_user_version','$date')";
				$stmt = $this->conn->prepare($sql);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt;
					$stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) { 
					// User successfully inserted
					return HISTORYPRODUCT_ADDED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return HISTORYPRODUCT_ADDED_FAILED;
				}
		}
		
		public function edithistoryproduct($data) {
				// update query
				$id_history  = $data['id_history'];
				$product_order  = $data['product_order'];
				$id_user_version =$_SESSION['user']['id'];
				$this->updateversion('history_product','id_history',$id_history); 
				
				$preproduct_order= $this->getcolumnvalue('history_product','product_order','id_history',$id_history); 
				
				if(isset($product_order) && ($preproduct_order != $product_order)){
					$sqlset = $sqlset . "`product_order` = '$product_order',";
				}
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version',";
				$sqlset = rtrim($sqlset, ',');
				if ($sqlset!='' ){
					$stmt = $this->conn->prepare("UPDATE history_product SET ".$sqlset." WHERE id_history = '$id_history'");
						
					if ($stmt === FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt->execute();
						$stmt->close();
					}
					// Check for successful insertion
					if ($result) { 
						// User successfully inserted
						return HISTORYPRODUCT_UPDATED_SUCCESSFULLY;
					} else {
						// Failed to create user
						return HISTORYPRODUCT_UPDATED_FAILED;
					}
				}
		}
		
		/*public function deletehistoryproduct($id_history){
			$id_history  = $data['id_history'];
			$this->redeletedcheck('test_surv','flg_visible','id_history',$id_history);
			$stmt = $this->conn->prepare("UPDATE test_surv SET flg_visible =0 WHERE id_surv = '$id_surv'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$result = $stmt->execute();
				$stmt->close();
			}
			// Check for successful insertion
			if ($result) {
				// User successfully inserted
				return TESTSURVEY_DELETED_SUCCESSFULLY; 
			} else {
				// Failed to create user
				return TESTSURVEY_DELETED_FAILED;
			}
		}*/
		
		public function addhistoryproductaddl($data) {
				// update query
				$id_product  = $data['id_product'];
				$id_function  = md5($this->generateRandomString($length = 8));
				$product_order  = $data['product_order'];
				$id_history =  md5($this->generateRandomString($length = 8));
				$id_user_version =$_SESSION['user']['id'];
				$date = date('Y-m-d H:i:s');
				
				$sql = "INSERT INTO history_product_addl (id_history, product_order, id_product, id_function, id_user_version,version_date) 		values('$id_history','$product_order','$id_product', '$id_function','$id_user_version','$date')";
				$stmt = $this->conn->prepare($sql);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt;
					$stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) { 
					// User successfully inserted
					return HISTORYPRODUCT_ADDED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return HISTORYPRODUCT_ADDED_FAILED;
				}
		}
		
		public function edithistoryproductaddl($data) {
				// update query
				$id_history  = $data['id_history'];
				$id_product  = $data['id_product'];
				$product_order  = $data['product_order'];
				$id_user_version =$_SESSION['user']['id'];
				$this->updateversion('history_product_addl','id_history',$id_history); 
				
				$preid_product= $this->getcolumnvalue('history_product_addl','id_product','id_history',$id_history); 
				$preproduct_order= $this->getcolumnvalue('history_product_addl','product_order','id_history',$id_history); 
				
				if(isset($id_product) && ($preid_product != $id_product)){
					$sqlset = $sqlset . "`id_product` = '$id_product',";
				}
				if(isset($product_order) && ($preproduct_order != $product_order)){
					$sqlset = $sqlset . "`product_order` = '$product_order',";
				}
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version',";
				$sqlset = rtrim($sqlset, ',');
				if ($sqlset!='' ){
					$stmt = $this->conn->prepare("UPDATE history_product_addl SET ".$sqlset." WHERE id_history = '$id_history'");
						
					if ($stmt === FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt->execute();
						$stmt->close();
					}
					// Check for successful insertion
					if ($result) { 
						// User successfully inserted
						return HISTORYPRODUCT_UPDATED_SUCCESSFULLY;
					} else {
						// Failed to create user
						return HISTORYPRODUCT_UPDATED_FAILED;
					}
				}
		}
		
		public function addhistoryansaddl($data) {
				// update query
				$id_ans  = $data['id_ans'];
				$id_function  = md5($this->generateRandomString($length = 8));
				$product_order  = $data['product_order'];
				$id_history =  md5($this->generateRandomString($length = 8));
				$id_user_version =$_SESSION['user']['id'];
				$date = date('Y-m-d H:i:s');
				
				$sql = "INSERT INTO history_ans_addl (id_history, product_order, id_ans, id_function, id_user_version,version_date) 		values('$id_history','$product_order','$id_ans', '$id_function','$id_user_version','$date')";
				$stmt = $this->conn->prepare($sql);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$result = $stmt;
					$stmt->execute();
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) { 
					// User successfully inserted
					return HISTORYPRODUCT_ADDED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return HISTORYPRODUCT_ADDED_FAILED;
				}
		}
		
		public function edithistoryansaddl($data) {
				// update query
				$id_history  = $data['id_history'];
				$id_ans  = $data['id_ans'];
				$product_order  = $data['product_order'];
				$id_user_version =$_SESSION['user']['id'];
				$this->updateversion('history_ans_addl','id_history',$id_history); 
				
				$preid_product= $this->getcolumnvalue('history_ans_addl','id_ans','id_history',$id_history);
				$preid_ans= $this->getcolumnvalue('history_ans_addl','id_ans','id_history',$id_history); 
				$preproduct_order= $this->getcolumnvalue('history_ans_addl','product_order','id_history',$id_history); 
				
				if(isset($id_product) && ($preid_product != $id_product)){
					$sqlset = $sqlset . "`id_product` = '$id_product',";
				}
				if(isset($id_ans) && ($preid_ans != $id_ans)){
					$sqlset = $sqlset . "`id_ans` = '$id_ans',";
				}
				if(isset($product_order) && ($preproduct_order != $product_order)){
					$sqlset = $sqlset . "`product_order` = '$product_order',";
				}
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version',";
				$sqlset = rtrim($sqlset, ',');
				if ($sqlset!='' ){
					$stmt = $this->conn->prepare("UPDATE history_ans_addl SET ".$sqlset." WHERE id_history = '$id_history'");
						
					if ($stmt === FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt->execute();
						$stmt->close();
					}
					// Check for successful insertion
					if ($result) { 
						// User successfully inserted
						return HISTORYPRODUCT_UPDATED_SUCCESSFULLY;
					} else {
						// Failed to create user
						return HISTORYPRODUCT_UPDATED_FAILED;
					}
				}
		}
		
		public function addhistoryans($id_ans) {
				// update query
				print_r($id_ans);
				$ans_key =  md5($this->generateRandomString($length = 6));
				$id_history = md5($this->generateRandomString($length = 8));
				$user_ds_mem = $data['user_ds_mem'];
				$id_user_version = $_SESSION['user']['id'];
				$date = date('Y-m-d H:i:s');
				
				$sql = "INSERT INTO history_ans (id_ans, history_date, id_user, ans_key,  id_history, id_user_version,version_date) 		values('$id_ans','$date','$id_user_version','$ans_key','$id_history','$id_user_version','$date')";
				$stmt = $this->conn->prepare($sql);
				if ($stmt === FALSE){
					die($this->conn->error);
				} else  {
					$stmt->execute();
					$result = $stmt;
					$stmt->close();
				}
				// Check for successful insertion
				if ($result) { 
					// User successfully inserted
					return HISTORY_ADDED_SUCCESSFULLY;
				} else {
					// Failed to create user
					return HISTORY_ADDED_FAILED;
				}
		}
		
		/*public function edithistoryans($data) {
				// update query
				$id_surv  = $data['id_surv'];
				$history_date  = $data['history_date'];
				$id_user = $data['id_user']; 
				$id_user_version =$_SESSION['user']['id'];
				$this->updateversion('history','id_surv',$id_surv); 
				
				$previoushistory_date = $this->getcolumnvalue('history','history_date','id_surv',$id_surv); 
				$previousid_user = $this->getcolumnvalue('history','id_user','id_surv',$id_surv);
				
				if(isset($history_date) && ($previoushistory_date != $history_date)){
					$sqlset = $sqlset . "`history_date` = '$history_date',";
				}
				if(isset($id_user) && ($previousid_user != $id_user)){
					$sqlset = $sqlset . "`id_user` = '$id_user',";
				}
				$sqlset = $sqlset . "`id_user_version` = '$id_user_version',";
				$sqlset = rtrim($sqlset, ',');
				if ($sqlset!='' ){
					$stmt = $this->conn->prepare("UPDATE history SET ".$sqlset." WHERE id_surv = '$id_surv'");
						
					if ($stmt === FALSE){
						die($this->conn->error);
					} else  {
						$result = $stmt->execute();
						$stmt->close();
					}
					// Check for successful insertion
					if ($result) { 
						// User successfully inserted
						return USER_UPDATED_SUCCESSFULLY;
					} else {
						// Failed to create user
						return USER_UPDATED_FAILED;
					}
				}
		}*/
		
		
		public function listsurveytag($id_surv){
			$sql = "SELECT * FROM test_surv_tag
			                            JOIN test_tag ON test_surv_tag.id_tag = test_tag.id_tag  
										WHERE test_surv_tag.id_surv = '$id_surv'";
			$stmt = $this->conn->query($sql);
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$test = $stmt; 
				return $test;
			}
		}
		
		public function listtestquestag($id_ques) {
			$stmt = $this->conn->query("SELECT  * FROM test_ques_tag
			                            JOIN test_tag ON test_ques_tag.id_tag = test_tag.id_tag
										WHERE test_ques_tag.id_ques = '$id_ques'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$test = $stmt; 
				return $test;
			}
		}
		
		
		public function listtestanstag($id_ans) {
			$stmt = $this->conn->query("SELECT  * FROM test_ans_tag
			                            JOIN test_tag ON test_ans_tag.id_tag = test_tag.id_tag
										WHERE test_ans_tag.id_ans = '$id_ans'");
			if ($stmt === FALSE){
				die($this->conn->error);
			} else  {
				$test = $stmt; 
				return $test;
			}
		}
		
		public function uploadFile(){
			if(isset($_FILES['uploads'])){
				if (!empty($_FILES['uploads']['name'])) {
					$files = $_FILES['uploads'];
					$name = uniqid('img-'.date('Ymd').'-').$files['name'];
					$dir = dirname(dirname(__FILE__)).'/v1/uploads';
					if (move_uploaded_file($files['tmp_name'], $dir.'/' . $name) === true) {
						$url  = $dir.'/' . $name; 
						$name = $name;
						$idpicture = md5($this->generateRandomString($length = 4));
						$id_user_version = $_SESSION['user']['id'];
						$date = date('Y-m-d H:i:s');
						$sql = "INSERT INTO `picture` (id_picture,picture_path,picture_name,picture_active,version,id_user_version, version_date) values('$idpicture','$url','$name',1,0,'$id_user_version','$date')";
						$stmt = $this->conn->prepare($sql);
						if ($stmt === FALSE){
							die($this->conn->error);
						} else  {
							$result = $stmt->execute();
							$id = $this->conn->insert_id;
							$stmt->close();
							return $id;
						}
					}
				} 
			}
		}
		
	}
	
?>
